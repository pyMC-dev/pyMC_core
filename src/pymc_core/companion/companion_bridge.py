"""
CompanionBridge - Repeater-integrated companion mode.

Provides the same API as CompanionRadio but uses a shared dispatcher via
packet_injector. No radio ownership; host (repeater) injects packets via
process_received_packet and TX goes through packet_injector.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Optional

from ..node.handlers import create_core_handlers
from ..node.handlers.login_server import LoginServerHandler
from ..protocol import LocalIdentity, Packet
from ..protocol.constants import (
    MAX_PATH_SIZE,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from .companion_base import CompanionBase
from .constants import (
    ADV_TYPE_CHAT,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
)
from .models import Contact

logger = logging.getLogger("CompanionBridge")


# ---------------------------------------------------------------------------
# Bridge ACK handler: fires send_confirmed when ACK CRC matches a pending send
# ---------------------------------------------------------------------------

MAX_PENDING_ACK_CRCS = 64


class _BridgeAckHandler:
    """Handles ACK packets (discrete and PATH-carried).
    Fires send_confirmed when ACK CRC matches."""

    def __init__(self, bridge: "CompanionBridge") -> None:
        self._bridge = bridge

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ACK

    async def __call__(self, packet: Packet) -> None:
        if not packet.payload or len(packet.payload) != 4:
            return
        crc = int.from_bytes(packet.payload, "little")
        await self._apply_ack(crc)

    async def _apply_ack(self, crc: int) -> None:
        """If CRC is pending, clear it and fire send_confirmed."""
        if crc not in self._bridge._pending_ack_crcs:
            return
        self._bridge._pending_ack_crcs.discard(crc)
        await self._bridge._fire_callbacks("send_confirmed", crc)

    async def process_path_ack_variants(self, packet: Packet) -> Optional[int]:
        """Decrypt PATH payload; update contact out_path (firmware pattern), return ACK CRC.
        Tries every contact matching src_hash (same as TXT_MSG) so we use the correct key.
        """
        from ..protocol import CryptoUtils, Identity

        payload = packet.payload
        if not payload or len(payload) < 2 + 6:
            return None
        dest_hash = payload[0]
        src_hash = payload[1]
        our_hash = self._bridge._identity.get_public_key()[0]
        if dest_hash != our_hash:
            return None
        encrypted = bytes(payload[2:])
        # Try each contact with matching src_hash until decryption succeeds
        contacts_tried = 0
        for contact in self._bridge.contacts.contacts:
            try:
                pk = contact.public_key
                pub = bytes.fromhex(pk) if isinstance(pk, str) else bytes(pk)
                if len(pub) != 32 or pub[0] != src_hash:
                    continue
                contacts_tried += 1
                peer_id = Identity(pub)
                shared_secret = peer_id.calc_shared_secret(self._bridge._identity.get_private_key())
                aes_key = shared_secret[:16]
                decrypted = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted)
            except Exception as e:
                logger.debug(
                    "process_path_ack_variants: decrypt failed for src=0x%02x " "contact=%s: %s",
                    src_hash,
                    getattr(contact, "name", "?"),
                    e,
                )
                continue
            if len(decrypted) < 2:
                logger.debug(
                    "process_path_ack_variants: decrypted too short (%d) for src=0x%02x",
                    len(decrypted),
                    src_hash,
                )
                continue
            path_len = min(decrypted[0], MAX_PATH_SIZE)
            if 1 + path_len > len(decrypted):
                logger.debug(
                    "process_path_ack_variants: path_len=%d exceeds decrypted len=%d "
                    "for src=0x%02x",
                    path_len,
                    len(decrypted),
                    src_hash,
                )
                continue
            path_bytes = bytes(decrypted[1 : 1 + path_len])
            # Firmware pattern: onContactPathRecv stores out_path so replies can use sendDirect()
            # Update the underlying Contact (store expects Contact with bytes public_key, not proxy)
            contact_obj = self._bridge.contacts.get_by_key(pub)
            if contact_obj:
                contact_obj.out_path_len = path_len
                contact_obj.out_path = path_bytes
                self._bridge.contacts.update(contact_obj)
                logger.debug(
                    "process_path_ack_variants: updated out_path for src=0x%02x "
                    "contact=%s path_len=%d",
                    src_hash,
                    getattr(contact, "name", "?"),
                    path_len,
                )
            else:
                logger.debug(
                    "process_path_ack_variants: get_by_key returned None for src=0x%02x",
                    src_hash,
                )
            await self._bridge._fire_callbacks("contact_path_updated", pub, path_len, path_bytes)
            # If this PATH carries an ACK, return it so send_confirmed can fire
            extra_start = 1 + path_len
            if len(decrypted) >= extra_start + 1 + 4 and decrypted[extra_start] == PAYLOAD_TYPE_ACK:
                return int.from_bytes(decrypted[extra_start + 1 : extra_start + 5], "little")
            return None
        if contacts_tried > 0:
            logger.debug(
                "process_path_ack_variants: no contact decrypted successfully for src=0x%02x "
                "(tried %d)",
                src_hash,
                contacts_tried,
            )
        return None

    async def _notify_ack_received(self, crc: int) -> None:
        """Called by path handler when PATH packet contained an ACK."""
        await self._apply_ack(crc)


# ---------------------------------------------------------------------------
# Main CompanionBridge class
# ---------------------------------------------------------------------------


class CompanionBridge(CompanionBase):
    """Repeater-integrated companion: shared dispatcher, packet_injector for TX.

    No MeshNode, no radio. Host calls process_received_packet when packets
    destined for this companion arrive. All TX goes through packet_injector.
    """

    def __init__(
        self,
        identity: LocalIdentity,
        packet_injector: Callable[..., Any],
        node_name: str = "pyMC",
        adv_type: int = ADV_TYPE_CHAT,
        max_contacts: int = DEFAULT_MAX_CONTACTS,
        max_channels: int = DEFAULT_MAX_CHANNELS,
        offline_queue_size: int = DEFAULT_OFFLINE_QUEUE_SIZE,
        radio_config: Optional[dict] = None,
        authenticate_callback: Optional[Callable[..., tuple[bool, int]]] = None,
    ) -> None:
        """Initialise the companion bridge."""
        self._init_companion_stores(
            identity=identity,
            node_name=node_name,
            adv_type=adv_type,
            max_contacts=max_contacts,
            max_channels=max_channels,
            offline_queue_size=offline_queue_size,
            radio_config=radio_config,
        )
        self._packet_injector = packet_injector

        async def _handler_send_packet(pkt: Packet, wait_for_ack: bool = False) -> bool:
            return await self._packet_injector(pkt, wait_for_ack=wait_for_ack)

        def _login_send_callback(pkt: Packet, delay_ms: int) -> None:
            async def _delayed_send() -> None:
                await asyncio.sleep(delay_ms / 1000.0)
                await self._packet_injector(pkt, wait_for_ack=False)

            asyncio.create_task(_delayed_send())

        def _log(msg: str) -> None:
            logger.debug(f"[CompanionBridge] {msg}")

        self._pending_ack_crcs: set[int] = set()
        ack_handler = _BridgeAckHandler(self)

        # Use shared factory for the core protocol handlers
        core = create_core_handlers(
            identity=identity,
            contacts=self.contacts,
            channels=self.channels,
            event_service=self._event_service,
            send_packet_fn=_handler_send_packet,
            log_fn=_log,
            node_name=node_name,
            radio_config=self._radio_config,
            ack_handler=ack_handler,
        )

        # Bridge-specific: LoginServerHandler for incoming login requests
        auth_cb = authenticate_callback
        if auth_cb is None:

            def _reject_all(*args, **kwargs) -> tuple[bool, int]:
                return (False, 0)

            auth_cb = _reject_all

        login_server_handler = LoginServerHandler(
            identity, _log, authenticate_callback=auth_cb, is_room_server=False
        )
        login_server_handler.set_send_packet_callback(_login_send_callback)

        self._handlers: dict[int, Any] = {
            PAYLOAD_TYPE_ACK: ack_handler,
            PAYLOAD_TYPE_TXT_MSG: core.text_handler,
            PAYLOAD_TYPE_ADVERT: core.advert_handler,
            PAYLOAD_TYPE_PATH: core.path_handler,
            PAYLOAD_TYPE_ANON_REQ: login_server_handler,
            PAYLOAD_TYPE_GRP_TXT: core.group_text_handler,
            PAYLOAD_TYPE_RESPONSE: core.login_response_handler,
        }

        self._protocol_response_handler = core.protocol_response_handler
        self._login_response_handler = core.login_response_handler
        self._text_handler_ref = core.text_handler
        core.protocol_response_handler.set_binary_response_callback(self._on_binary_response)
        core.protocol_response_handler.set_packet_injector(self._packet_injector)

    # -------------------------------------------------------------------------
    # Handler accessors (used by CompanionBase concrete send methods)
    # -------------------------------------------------------------------------

    def _get_protocol_response_handler(self) -> Any:
        return self._protocol_response_handler

    def _get_login_response_handler(self) -> Any:
        return self._login_response_handler

    def _get_text_handler(self) -> Any:
        return self._text_handler_ref

    def _track_pending_ack(self, ack_crc: int) -> None:
        if len(self._pending_ack_crcs) < MAX_PENDING_ACK_CRCS:
            self._pending_ack_crcs.add(ack_crc)

    # -------------------------------------------------------------------------
    # RX Entry Point
    # -------------------------------------------------------------------------

    async def process_received_packet(self, packet: Packet) -> None:
        """Process a packet destined for this companion."""
        ptype = packet.header >> 2 & 0x0F
        route_type = packet.header & 0x03
        is_flood = route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD)
        self.stats.record_rx(is_flood=is_flood)

        handler = self._handlers.get(ptype)
        if handler:
            try:
                result = await handler(packet)
                if ptype == PAYLOAD_TYPE_ADVERT and result:
                    contact = await self._update_stores_from_advert(packet, result)
                    if contact:
                        await self._fire_callbacks("advert_received", contact)
            except Exception as e:
                logger.error(f"Handler error for type {ptype:02X}: {e}")

        # NOTE: PATH packets are already delivered to protocol_response_handler
        # via PathHandler.__call__ (path.py), which runs as the handler above.
        # No duplicate call here — it would cause double decryption and could
        # deliver the result to response waiters twice.

    async def _update_stores_from_advert(self, packet: Packet, advert_data: dict):
        """Update ContactStore and PathCache from advert result.

        Builds Contact and inbound path from packet, then delegates to
        _apply_advert_to_stores. Returns the Contact if added or updated, None otherwise.
        """
        try:
            contact = Contact.from_dict(advert_data, now=int(time.time()))
            if len(contact.public_key) < 7 or not contact.name:
                return None
            path_len = getattr(packet, "path_len", 0) or 0
            path = getattr(packet, "path", bytearray()) or bytearray()
            effective_len = path_len if path_len > 0 else len(path)
            inbound_path = bytes(path[:effective_len]) if effective_len > 0 else b""
            return await self._apply_advert_to_stores(contact, inbound_path)
        except Exception as e:
            logger.error("Error updating stores from advert: %s", e)
            return None

    # -------------------------------------------------------------------------
    # Abstract method implementations
    # -------------------------------------------------------------------------

    async def _send_packet(self, pkt: Packet, wait_for_ack: bool = False) -> bool:
        """Send a packet via the packet_injector."""
        return await self._packet_injector(pkt, wait_for_ack=wait_for_ack)

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        logger.info(
            f"CompanionBridge started: name={self.prefs.node_name}, "
            f"key={self._identity.get_public_key().hex()[:16]}..."
        )

    async def stop(self) -> None:
        self._running = False
        logger.info("CompanionBridge stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # -------------------------------------------------------------------------
    # Key Management
    # -------------------------------------------------------------------------

    def import_private_key(self, key: bytes) -> bool:
        try:
            self._identity = LocalIdentity(seed=key)
            logger.info(f"Imported new identity: {self._identity.get_public_key().hex()[:16]}...")
            return True
        except Exception as e:
            logger.error(f"Error importing private key: {e}")
            return False

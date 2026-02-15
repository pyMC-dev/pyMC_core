"""
CompanionBridge - Repeater-integrated companion mode.

Provides the same API as CompanionRadio but uses a shared dispatcher via
packet_injector. No radio ownership; host (repeater) injects packets via
process_received_packet and TX goes through packet_injector.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Callable, Optional

from ..node.events import EventService, EventSubscriber, MeshEvents
from ..node.handlers import (
    AdvertHandler,
    GroupTextHandler,
    LoginResponseHandler,
    PathHandler,
    ProtocolResponseHandler,
    TextMessageHandler,
)
from ..node.handlers.login_server import LoginServerHandler
from ..protocol import LocalIdentity, PacketBuilder
from ..protocol import Packet
from ..protocol.constants import (
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_CONTROL,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from ..protocol.constants import REQ_TYPE_GET_STATUS, REQ_TYPE_GET_TELEMETRY_DATA, TELEM_PERM_BASE
from .companion_base import CompanionBase, ResponseWaiter, adv_type_to_flags
from .constants import (
    ADV_TYPE_CHAT,
    ADVERT_LOC_SHARE,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
    TXT_TYPE_PLAIN,
)
from .models import Contact, QueuedMessage, SentResult

logger = logging.getLogger("CompanionBridge")


# ---------------------------------------------------------------------------
# Bridge ACK handler: fires send_confirmed when ACK CRC matches a pending send
# ---------------------------------------------------------------------------

MAX_PENDING_ACK_CRCS = 64


class _BridgeAckHandler:
    """Handles discrete ACK packets and PathHandler stub. Fires send_confirmed when ACK CRC matches a pending send."""

    def __init__(self, bridge: "CompanionBridge") -> None:
        self._bridge = bridge

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ACK

    async def __call__(self, packet: Packet) -> None:
        if not packet.payload or len(packet.payload) != 4:
            return
        crc = int.from_bytes(packet.payload, "little")
        if crc in self._bridge._pending_ack_crcs:
            self._bridge._pending_ack_crcs.discard(crc)
            await self._bridge._fire_callbacks("send_confirmed", crc)

    async def process_path_ack_variants(self, packet: Packet) -> Optional[int]:
        return None

    async def _notify_ack_received(self, crc: int) -> None:
        pass


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
    ):
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

        async def _send_packet(pkt: Packet, wait_for_ack: bool = False) -> bool:
            return await self._packet_injector(pkt, wait_for_ack=wait_for_ack)

        def _login_send_callback(pkt: Packet, delay_ms: int) -> None:
            async def _delayed_send() -> None:
                await asyncio.sleep(delay_ms / 1000.0)
                await self._packet_injector(pkt, wait_for_ack=False)
            asyncio.create_task(_delayed_send())

        _log = lambda msg: logger.debug(f"[CompanionBridge] {msg}")

        self._pending_ack_crcs: set[int] = set()
        self._pending_discovery_tags: set[int] = set()
        ack_handler = _BridgeAckHandler(self)
        protocol_response_handler = ProtocolResponseHandler(
            _log, identity, self.contacts
        )
        login_response_handler = LoginResponseHandler(
            identity, self.contacts, _log
        )
        login_response_handler.set_protocol_response_handler(
            protocol_response_handler
        )
        path_handler = PathHandler(
            _log, ack_handler, protocol_response_handler, login_response_handler
        )

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
            PAYLOAD_TYPE_TXT_MSG: TextMessageHandler(
                identity,
                self.contacts,
                _log,
                _send_packet,
                self._event_service,
                self._radio_config,
            ),
            PAYLOAD_TYPE_ADVERT: AdvertHandler(
                _log, event_service=self._event_service
            ),
            PAYLOAD_TYPE_PATH: path_handler,
            PAYLOAD_TYPE_ANON_REQ: login_server_handler,
            PAYLOAD_TYPE_GRP_TXT: GroupTextHandler(
                identity,
                self.contacts,
                _log,
                _send_packet,
                self.channels,
                self._event_service,
                node_name,
            ),
            PAYLOAD_TYPE_RESPONSE: login_response_handler,
        }

        self._protocol_response_handler = protocol_response_handler
        self._login_response_handler = login_response_handler
        self._text_handler = self._handlers[PAYLOAD_TYPE_TXT_MSG]
        protocol_response_handler.set_binary_response_callback(self._on_binary_response)

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
                    contact = self._update_stores_from_advert(packet, result)
                    if contact:
                        await self._fire_callbacks("advert_received", contact)
            except Exception as e:
                logger.error(f"Handler error for type {ptype:02X}: {e}")

    def _update_stores_from_advert(self, packet: Packet, advert_data: dict):
        """Update ContactStore and PathCache from advert result. Returns the Contact or None."""
        try:
            from .models import AdvertPath

            pub_key = bytes.fromhex(advert_data.get("public_key", ""))
            if len(pub_key) < 7:
                return None
            name = advert_data.get("name", "")
            if not name:
                return None
            # Inbound path: route the advert took to reach us (for discovery list / advert path display).
            # Stored in path_cache only; contact.out_path is separate and set elsewhere (e.g. path discovery).
            path_len = getattr(packet, "path_len", 0) or 0
            path = getattr(packet, "path", bytearray()) or bytearray()
            effective_len = path_len if path_len > 0 else len(path)
            inbound_path = bytes(path[:effective_len]) if effective_len > 0 else b""
            now = int(time.time())
            last_advert_ts = advert_data.get("advert_timestamp", 0)
            if last_advert_ts > now:
                last_advert_ts = now
            # Contact: out_path is for sending to this contact; leave unknown (-1) until set by path update.
            contact = Contact(
                public_key=pub_key,
                name=name,
                adv_type=advert_data.get("contact_type_id", 0),
                gps_lat=advert_data.get("latitude", 0.0),
                gps_lon=advert_data.get("longitude", 0.0),
                lastmod=now,
                last_advert_timestamp=last_advert_ts,
                out_path_len=-1,
                out_path=b"",
            )
            self.contacts.add(contact)

            # Path cache: store inbound path (path advert took to get here) for discovery list display.
            self.path_cache.update(
                AdvertPath(
                    public_key_prefix=pub_key[:7],
                    name=name,
                    path_len=len(inbound_path),
                    path=inbound_path,
                    recv_timestamp=int(time.time()),
                )
            )
            return contact
        except Exception as e:
            logger.error(f"Error updating stores from advert: {e}")
            return None

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
    # Advertisement
    # -------------------------------------------------------------------------

    async def advertise(self, flood: bool = True) -> bool:
        flags = adv_type_to_flags(self.prefs.adv_type)
        flags |= ADVERT_FLAG_HAS_NAME
        lat, lon = 0.0, 0.0
        if self.prefs.advert_loc_policy == ADVERT_LOC_SHARE:
            lat, lon = self.prefs.latitude, self.prefs.longitude
            if lat != 0.0 or lon != 0.0:
                flags |= ADVERT_FLAG_HAS_LOCATION
        route = "flood" if flood else "direct"
        pkt = PacketBuilder.create_advert(
            local_identity=self._identity,
            name=self.prefs.node_name,
            lat=lat,
            lon=lon,
            flags=flags,
            route_type=route,
        )
        success = await self._packet_injector(pkt, wait_for_ack=False)
        if success:
            self.stats.record_tx(is_flood=flood)
        else:
            self.stats.record_tx_error()
        return success

    # -------------------------------------------------------------------------
    # Messaging
    # -------------------------------------------------------------------------

    async def send_text_message(
        self,
        pub_key: bytes,
        text: str,
        txt_type: int = TXT_TYPE_PLAIN,
        attempt: int = 1,
    ) -> SentResult:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            logger.warning(f"Contact not found for key {pub_key.hex()[:12]}...")
            return SentResult(success=False)
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return SentResult(success=False)
        try:
            is_flood = proxy.out_path_len < 0
            msg_type = "flood" if is_flood else "direct"
            pkt, ack_crc = PacketBuilder.create_text_message(
                contact=proxy,
                local_identity=self._identity,
                message=text,
                attempt=attempt,
                message_type=msg_type,
            )
            if len(self._pending_ack_crcs) < MAX_PENDING_ACK_CRCS:
                self._pending_ack_crcs.add(ack_crc)
            success = await self._packet_injector(pkt, wait_for_ack=True)
            if success:
                self.stats.record_tx(is_flood=is_flood)
            else:
                self.stats.record_tx_error()
            return SentResult(
                success=success,
                is_flood=is_flood,
                expected_ack=ack_crc,
                timeout_ms=None,
            )
        except Exception as e:
            logger.error(f"Error sending text message: {e}")
            self.stats.record_tx_error()
            return SentResult(success=False)

    async def send_channel_message(self, channel_idx: int, text: str) -> bool:
        channel = self.channels.get(channel_idx)
        if not channel:
            logger.warning(f"Channel {channel_idx} not found")
            return False
        try:
            pkt = PacketBuilder.create_group_datagram(
                group_name=channel.name,
                local_identity=self._identity,
                message=text,
                sender_name=self.prefs.node_name,
                channels_config=self.channels.get_channels(),
            )
            success = await self._packet_injector(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=True)
            else:
                self.stats.record_tx_error()
            return success
        except Exception as e:
            logger.error(f"Error sending channel message: {e}")
            self.stats.record_tx_error()
            return False

    def sync_next_message(self) -> Optional[QueuedMessage]:
        return self.message_queue.pop()

    async def send_raw_data(
        self,
        dest_key: bytes,
        data: bytes,
        path: Optional[bytes] = None,
    ) -> SentResult:
        contact = self.contacts.get_by_key(dest_key)
        if not contact:
            return SentResult(success=False)
        try:
            proxy = self.contacts.get_by_name(contact.name)
            if not proxy:
                return SentResult(success=False)
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=0x00,
                data=data,
            )
            success = await self._packet_injector(pkt, wait_for_ack=False)
            return SentResult(success=success)
        except Exception as e:
            logger.error(f"Error sending raw data: {e}")
            return SentResult(success=False)

    # -------------------------------------------------------------------------
    # Contact Management (share_contact override)
    # -------------------------------------------------------------------------

    async def share_contact(self, pub_key: bytes) -> bool:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        try:
            pkt = PacketBuilder.create_advert(
                local_identity=self._identity,
                name=contact.name,
                flags=adv_type_to_flags(contact.adv_type) | ADVERT_FLAG_HAS_NAME,
                route_type="direct",
            )
            return await self._packet_injector(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sharing contact: {e}")
            return False

    # -------------------------------------------------------------------------
    # Path & Routing
    # -------------------------------------------------------------------------

    async def send_trace_path(
        self,
        pub_key: bytes,
        tag: int,
        auth_code: int,
        flags: int = 0,
    ) -> bool:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        path = list(contact.out_path) if contact.out_path else []
        if not path:
            path = [contact.public_key[0]]
        try:
            pkt = PacketBuilder.create_trace(tag, auth_code, flags, path=path)
            return await self._packet_injector(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending trace: {e}")
            return False

    async def send_trace_path_raw(
        self,
        tag: int,
        auth_code: int,
        flags: int,
        path_bytes: bytes,
    ) -> bool:
        """Send a trace packet with an explicit path (e.g. from CMD_SEND_TRACE_PATH). Matches firmware behavior."""
        try:
            path_list = list(path_bytes)
            pkt = PacketBuilder.create_trace(tag, auth_code, flags, path=path_list)
            return await self._packet_injector(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending trace (raw path): {e}")
            return False

    async def _try_handle_path_discovery(
        self, tag_bytes: bytes, path_info: tuple
    ) -> bool:
        """If tag is pending path discovery, fire path_discovery_response and return True."""
        out_path, in_path, contact_pubkey = path_info
        tag_int = int.from_bytes(tag_bytes, "little")
        if tag_int not in self._pending_discovery_tags:
            return False
        self._pending_discovery_tags.discard(tag_int)
        await self._fire_callbacks(
            "path_discovery_response",
            tag_bytes,
            contact_pubkey,
            out_path,
            in_path,
        )
        return True

    async def send_path_discovery(self, pub_key: bytes) -> bool:
        """Legacy: send path discovery without returning tag. Prefer send_path_discovery_req."""
        result = await self.send_path_discovery_req(pub_key)
        return result.success

    async def send_path_discovery_req(self, pub_key: bytes) -> SentResult:
        """Send path discovery (flood telemetry request with tag). Returns SentResult for RESP_CODE_SENT.
        When path return arrives with matching tag, path_discovery_response is fired (PUSH 0x8D)."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return SentResult(success=False)
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return SentResult(success=False)
        tag_int = random.randint(0, 0xFFFFFFFF)
        tag_bytes = tag_int.to_bytes(4, "little")
        # Firmware: REQ_TYPE_GET_TELEMETRY_DATA, ~TELEM_PERM_BASE, reserved(3), random(4) -> 9 bytes; tag is from sendRequest.
        # We send tag(4) + type(1) + perm(1) + reserved(3) = 9 bytes so response echoes our tag.
        inv_perm = 0xFF & ~TELEM_PERM_BASE
        req_payload = tag_bytes + bytes(
            [REQ_TYPE_GET_TELEMETRY_DATA, inv_perm, 0, 0, 0]
        )
        old_path_len = contact.out_path_len
        old_path = contact.out_path
        contact.out_path_len = -1
        contact.out_path = b""
        self.contacts.update(contact)
        try:
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=REQ_TYPE_GET_TELEMETRY_DATA,
                data=req_payload,
            )
            success = await self._packet_injector(pkt, wait_for_ack=False)
            if success:
                self._pending_discovery_tags.add(tag_int)
            return SentResult(
                success=success,
                is_flood=True,
                expected_ack=tag_int,
                timeout_ms=10000,
            )
        except Exception as e:
            logger.error(f"Error in path discovery: {e}")
            return SentResult(success=False)
        finally:
            current = self.contacts.get_by_key(pub_key)
            if current and current.out_path_len == -1:
                current.out_path_len = old_path_len
                current.out_path = old_path
                self.contacts.update(current)

    async def send_control_data(self, data: bytes) -> bool:
        """Send a CONTROL packet (e.g. discovery request). data = first byte flags/type (0x80 set for DISCOVER_REQ) + payload.
        Firmware: (cmd_frame[1] & 0x80) != 0, createControlData(&cmd_frame[1], len-1), sendZeroHop(resp). Returns True if sent."""
        if not data or len(data) > 254:
            return False
        if (data[0] & 0x80) == 0:
            return False  # firmware requires first byte to have 0x80 set (e.g. DISCOVER_REQ)
        try:
            pkt = Packet()
            pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_CONTROL, route_type="direct")
            pkt.path_len = 0
            pkt.path = bytearray()
            pkt.payload = bytearray(data)
            pkt.payload_len = len(data)
            return await self._packet_injector(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending control data: {e}")
            return False

    # -------------------------------------------------------------------------
    # Key Management
    # -------------------------------------------------------------------------

    def import_private_key(self, key: bytes) -> bool:
        try:
            self._identity = LocalIdentity(seed=key)
            logger.info(
                f"Imported new identity: {self._identity.get_public_key().hex()[:16]}..."
            )
            return True
        except Exception as e:
            logger.error(f"Error importing private key: {e}")
            return False

    # -------------------------------------------------------------------------
    # Requests
    # -------------------------------------------------------------------------

    async def send_login(self, pub_key: bytes, password: str) -> dict:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        dest_hash = bytes.fromhex(proxy.public_key)[0]
        self._login_response_handler.store_login_password(dest_hash, password)
        login_result = {"success": False, "data": {}}
        login_event = asyncio.Event()

        def _login_cb(success: bool, data: dict) -> None:
            login_result["success"] = success
            login_result["data"] = data
            login_event.set()

        self._login_response_handler.set_login_callback(_login_cb)
        try:
            pkt = PacketBuilder.create_login_packet(
                contact=proxy, local_identity=self._identity, password=password
            )
            await self._packet_injector(pkt, wait_for_ack=False)
            try:
                await asyncio.wait_for(login_event.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                return {"success": False, "reason": "Login response timeout"}
            data = login_result["data"]
            return {
                "success": login_result["success"],
                "repeater": contact.name,
                "is_admin": data.get("is_admin", False),
                "keep_alive_interval": data.get("keep_alive_interval", 0),
                "tag": data.get("timestamp", 0),
                "acl_permissions": data.get("reserved", data.get("permissions", 0)),
                "reason": "Login successful" if login_result["success"] else "Login failed",
            }
        except Exception as e:
            logger.error(f"Login error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            self._login_response_handler.set_login_callback(None)
            self._login_response_handler.clear_login_password(dest_hash)

    async def send_status_request(self, pub_key: bytes, timeout: float = 15.0) -> dict:
        """Send a protocol request for repeater stats (REQ_TYPE_GET_STATUS).

        The firmware handles CMD_SEND_STATUS_REQ by calling
        ``sendRequest(*recipient, REQ_TYPE_GET_STATUS, tag, est_timeout)``
        which creates a PAYLOAD_TYPE_REQ packet.  The remote repeater replies
        with a PAYLOAD_TYPE_RESPONSE containing ``reflected_timestamp(4) +
        RepeaterStats(48)``.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        contact_hash = bytes.fromhex(proxy.public_key)[0]
        waiter = ResponseWaiter()
        self._protocol_response_handler.set_response_callback(
            contact_hash, waiter.callback
        )
        try:
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=REQ_TYPE_GET_STATUS,
                data=b"",
            )
            await self._packet_injector(pkt, wait_for_ack=False)
            result = await waiter.wait(timeout)
            return {
                "success": result.get("success", False),
                "repeater": contact.name,
                "stats": result.get("parsed", {}),
                "response_text": result.get("text"),
                "reason": "Stats received" if result.get("success") else "Stats request failed",
            }
        except Exception as e:
            logger.error(f"Status request error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            self._protocol_response_handler.clear_response_callback(contact_hash)

    async def send_telemetry_request(
        self,
        pub_key: bytes,
        want_base: bool = True,
        want_location: bool = True,
        want_environment: bool = True,
        timeout: float = 10.0,
    ) -> dict:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        contact_hash = bytes.fromhex(proxy.public_key)[0]
        waiter = ResponseWaiter()
        self._protocol_response_handler.set_response_callback(
            contact_hash, waiter.callback
        )
        try:
            inv = PacketBuilder._compute_inverse_perm_mask(
                want_base, want_location, want_environment
            )
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=REQ_TYPE_GET_TELEMETRY_DATA,
                data=bytes([inv]),
            )
            await self._packet_injector(pkt, wait_for_ack=False)
            result = await waiter.wait(timeout)
            return {
                "success": result.get("success", False),
                "contact": contact.name,
                "telemetry_data": result.get("parsed", {}),
                "response_text": result.get("text"),
                "reason": "Telemetry received" if result.get("success") else "Telemetry failed",
            }
        except Exception as e:
            logger.error(f"Telemetry error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            self._protocol_response_handler.clear_response_callback(contact_hash)

    async def send_binary_req(
        self, pub_key: bytes, data: bytes, timeout_seconds: float = 15.0
    ) -> SentResult:
        """Send binary request (CMD_SEND_BINARY_REQ). data = request_type(1) + optional payload.
        Returns SentResult with expected_ack (4-byte tag as int) and timeout_ms for RESP_CODE_SENT.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return SentResult(success=False)
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return SentResult(success=False)
        tag_int = random.randint(0, 0xFFFFFFFF)
        tag_bytes = tag_int.to_bytes(4, "little")
        tag_hex = tag_bytes.hex()
        request_type = data[0] if len(data) >= 1 else 0
        req_payload = tag_bytes + data
        self.cleanup_expired_binary_requests()
        self.register_binary_request(
            tag_hex,
            request_type=request_type,
            timeout_seconds=timeout_seconds,
            pubkey_prefix=pub_key[:6].hex(),
        )
        try:
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=0x02,
                data=req_payload,
            )
            success = await self._packet_injector(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Binary request send error: {e}")
            self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        if not success:
            self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        return SentResult(
            success=True,
            is_flood=contact.out_path_len <= 0,
            expected_ack=tag_int,
            timeout_ms=10000,
        )

    async def send_binary_request(self, pub_key: bytes, data: bytes) -> dict:
        """Legacy: send binary request and wait for response via waiter. Prefer send_binary_req + on_binary_response."""
        return await self._send_protocol_request(pub_key, 0x02, data)

    async def send_anon_request(self, pub_key: bytes, data: bytes) -> dict:
        return await self._send_protocol_request(pub_key, 0x07, data)

    async def _send_protocol_request(
        self, pub_key: bytes, protocol_code: int, data: bytes
    ) -> dict:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        contact_hash = bytes.fromhex(proxy.public_key)[0]
        waiter = ResponseWaiter()
        self._protocol_response_handler.set_response_callback(
            contact_hash, waiter.callback
        )
        try:
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=protocol_code,
                data=data,
            )
            await self._packet_injector(pkt, wait_for_ack=False)
            result = await waiter.wait(10.0)
            return {
                "success": result.get("success", False),
                "response": result.get("text"),
                "parsed_data": result.get("parsed", {}),
                "reason": "Success" if result.get("success") else "Failed",
            }
        except Exception as e:
            logger.error(f"Protocol request error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            self._protocol_response_handler.clear_response_callback(contact_hash)

    async def send_repeater_command(
        self, pub_key: bytes, command: str, parameters: Optional[str] = None
    ) -> dict:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        full_command = command
        if parameters:
            full_command += f" {parameters}"
        response_data = {"text": None, "success": False}
        response_event = asyncio.Event()

        def _response_cb(message_text: str, sender_contact: Any) -> None:
            response_data["text"] = message_text
            response_data["success"] = True
            response_event.set()

        self._text_handler.set_command_response_callback(_response_cb)
        try:
            msg_type = "flood" if proxy.out_path_len < 0 else "direct"
            pkt, ack_crc = PacketBuilder.create_text_message(
                contact=proxy,
                local_identity=self._identity,
                message=full_command,
                attempt=1,
                message_type=msg_type,
            )
            await self._packet_injector(pkt, wait_for_ack=True)
            try:
                await asyncio.wait_for(response_event.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                pass
            return {
                "success": response_data["success"],
                "repeater": contact.name,
                "command": command,
                "response": response_data["text"],
                "reason": "Command successful" if response_data["success"] else "No response",
            }
        except Exception as e:
            logger.error(f"Repeater command error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            self._text_handler.set_command_response_callback(None)


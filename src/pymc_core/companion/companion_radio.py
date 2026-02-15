"""
MeshCore Companion Radio - Python-native implementation.

Provides the same feature set as the MeshCore companion radio firmware
(meshcore-dev/MeshCore/examples/companion_radio), implemented as a
high-level wrapper around MeshNode with in-memory contact, channel,
message queue, path cache, and statistics management.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Callable, Optional

from ..node.node import MeshNode
from ..protocol import LocalIdentity, Packet, PacketBuilder
from ..protocol.constants import (
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    PAYLOAD_TYPE_CONTROL,
    REQ_TYPE_GET_TELEMETRY_DATA,
    TELEM_PERM_BASE,
)
from .companion_base import CompanionBase, adv_type_to_flags
from .constants import (
    ADV_TYPE_CHAT,
    ADVERT_LOC_SHARE,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
    STATS_TYPE_PACKETS,
    TXT_TYPE_PLAIN,
)
from .models import QueuedMessage, SentResult

logger = logging.getLogger("CompanionRadio")


class CompanionRadio(CompanionBase):
    """Python-native MeshCore companion radio.

    Wraps MeshNode and augments it with application-layer state and services
    that the C++ companion radio firmware provides: contact management,
    messaging with offline queue, advertisement broadcasting, channel
    management, path tracking, signing, telemetry, statistics, and device
    configuration.

    Example:
        ```python
        from pymc_core import CompanionRadio, LocalIdentity
        from pymc_core.hardware import KissModemWrapper

        radio = KissModemWrapper("/dev/ttyUSB0")
        radio.connect()
        identity = LocalIdentity()
        companion = CompanionRadio(radio, identity, node_name="myNode")

        async def main():
            await companion.start()
            print(f"Key: {companion.get_public_key().hex()}")
            await companion.advertise()
            await companion.stop()

        asyncio.run(main())
        ```
    """

    def __init__(
        self,
        radio: Any,
        identity: LocalIdentity,
        node_name: str = "pyMC",
        adv_type: int = ADV_TYPE_CHAT,
        max_contacts: int = DEFAULT_MAX_CONTACTS,
        max_channels: int = DEFAULT_MAX_CHANNELS,
        offline_queue_size: int = DEFAULT_OFFLINE_QUEUE_SIZE,
        radio_config: Optional[dict] = None,
    ):
        """Initialise the companion radio."""
        self._init_companion_stores(
            identity=identity,
            node_name=node_name,
            adv_type=adv_type,
            max_contacts=max_contacts,
            max_channels=max_channels,
            offline_queue_size=offline_queue_size,
            radio_config=radio_config,
        )
        self._radio = radio
        self._dispatcher_task: Optional[asyncio.Task] = None
        self._pending_discovery_tags: set[int] = set()

        self.node = MeshNode(
            radio=radio,
            local_identity=identity,
            config={
                "node": {"name": node_name},
                "radio": self._radio_config,
            },
            contacts=self.contacts,
            channel_db=self.channels,
            event_service=self._event_service,
        )
        self._setup_packet_callbacks()

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            logger.warning("CompanionRadio already running")
            return
        self._running = True
        self._dispatcher_task = asyncio.create_task(self.node.start())
        logger.info(
            f"CompanionRadio started: name={self.prefs.node_name}, "
            f"key={self._identity.get_public_key().hex()[:16]}..."
        )

    async def stop(self) -> None:
        self._running = False
        if self._dispatcher_task:
            self._dispatcher_task.cancel()
            try:
                await self._dispatcher_task
            except asyncio.CancelledError:
                pass
            self._dispatcher_task = None
        self.node.stop()
        logger.info("CompanionRadio stopped")

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
            lat = self.prefs.latitude
            lon = self.prefs.longitude
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
        success = await self.node.dispatcher.send_packet(pkt, wait_for_ack=False)
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
        try:
            result = await self.node.send_text(
                contact_name=contact.name,
                message=text,
                attempt=attempt,
            )
            success = result.get("success", False)
            is_flood = contact.out_path_len <= 0
            if success:
                self.stats.record_tx(is_flood=is_flood)
            else:
                self.stats.record_tx_error()
            return SentResult(
                success=success,
                is_flood=is_flood,
                expected_ack=result.get("crc"),
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
            result = await self.node.send_group_text(
                group_name=channel.name,
                message=text,
            )
            success = result.get("success", False)
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
            logger.warning(f"Contact not found for raw data send: {dest_key.hex()[:12]}")
            return SentResult(success=False)
        try:
            result = await self.node.send_protocol_request(
                repeater_name=contact.name,
                protocol_code=0x00,
                data=data,
            )
            return SentResult(success=result.get("success", False))
        except Exception as e:
            logger.error(f"Error sending raw data: {e}")
            return SentResult(success=False)

    # -------------------------------------------------------------------------
    # Contact Management (share_contact overrides base - uses node)
    # -------------------------------------------------------------------------

    async def share_contact(self, pub_key: bytes) -> bool:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            logger.warning(f"Contact not found for sharing: {pub_key.hex()[:12]}")
            return False
        try:
            pkt = PacketBuilder.create_advert(
                local_identity=self._identity,
                name=contact.name,
                flags=adv_type_to_flags(contact.adv_type) | ADVERT_FLAG_HAS_NAME,
                route_type="direct",
            )
            return await self.node.dispatcher.send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sharing contact: {e}")
        return False

    # -------------------------------------------------------------------------
    # Device Configuration (overrides for radio hardware)
    # -------------------------------------------------------------------------

    def set_advert_name(self, name: str) -> None:
        super().set_advert_name(name)
        self.node.node_name = self.prefs.node_name

    def set_radio_params(self, freq_hz: int, bw_hz: int, sf: int, cr: int) -> bool:
        super().set_radio_params(freq_hz, bw_hz, sf, cr)
        if hasattr(self._radio, "configure_radio"):
            try:
                self._radio.configure_radio(
                    frequency=freq_hz,
                    bandwidth=bw_hz,
                    spreading_factor=sf,
                    coding_rate=cr,
                )
                return True
            except Exception as e:
                logger.error(f"Error configuring radio: {e}")
                return False
        return True

    def set_tx_power(self, power_dbm: int) -> bool:
        super().set_tx_power(power_dbm)
        if hasattr(self._radio, "set_tx_power"):
            try:
                self._radio.set_tx_power(power_dbm)
                return True
            except Exception as e:
                logger.error(f"Error setting TX power: {e}")
                return False
        return True

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
            logger.warning(f"Contact not found for trace: {pub_key.hex()[:12]}")
            return False
        try:
            result = await self.node.send_trace_packet(
                contact_name=contact.name,
                tag=tag,
                auth_code=auth_code,
                flags=flags,
            )
            return result.get("success", False)
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
            return await self.node.dispatcher.send_packet(pkt, wait_for_ack=False)
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
            success = await self.node.dispatcher.send_packet(pkt, wait_for_ack=False)
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

    # -------------------------------------------------------------------------
    # Key Management
    # -------------------------------------------------------------------------

    def import_private_key(self, key: bytes) -> bool:
        try:
            self._identity = LocalIdentity(seed=key)
            self.node = MeshNode(
                radio=self._radio,
                local_identity=self._identity,
                config={
                    "node": {"name": self.prefs.node_name},
                    "radio": self._radio_config,
                },
                contacts=self.contacts,
                channel_db=self.channels,
                event_service=self._event_service,
            )
            self._setup_packet_callbacks()
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
        try:
            return await self.node.send_login(
                repeater_name=contact.name,
                password=password,
            )
        except Exception as e:
            logger.error(f"Login error: {e}")
            return {"success": False, "reason": str(e)}

    async def send_status_request(self, pub_key: bytes) -> dict:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        try:
            return await self.node.send_status_request(repeater_name=contact.name)
        except Exception as e:
            logger.error(f"Status request error: {e}")
            return {"success": False, "reason": str(e)}

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
        try:
            return await self.node.send_telemetry_request(
                contact_name=contact.name,
                want_base=want_base,
                want_location=want_location,
                want_environment=want_environment,
                timeout=timeout,
            )
        except Exception as e:
            logger.error(f"Telemetry request error: {e}")
            return {"success": False, "reason": str(e)}

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
            success = await self.node.dispatcher.send_packet(pkt, wait_for_ack=False)
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
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        try:
            return await self.node.send_protocol_request(
                repeater_name=contact.name,
                protocol_code=0x02,
                data=data,
            )
        except Exception as e:
            logger.error(f"Binary request error: {e}")
            return {"success": False, "reason": str(e)}

    async def send_anon_request(self, pub_key: bytes, data: bytes) -> dict:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        try:
            return await self.node.send_protocol_request(
                repeater_name=contact.name,
                protocol_code=0x07,
                data=data,
            )
        except Exception as e:
            logger.error(f"Anon request error: {e}")
            return {"success": False, "reason": str(e)}

    async def send_repeater_command(
        self, pub_key: bytes, command: str, parameters: Optional[str] = None
    ) -> dict:
        """Send a text-based command to a repeater and await response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        try:
            result = await self.node.send_repeater_command(
                repeater_name=contact.name,
                command=command,
                parameters=parameters,
            )
            return {
                "success": result.get("success", False),
                "repeater": contact.name,
                "command": command,
                "response": result.get("response"),
                "reason": (
                    "Command successful" if result.get("success") else "No response"
                ),
            }
        except Exception as e:
            logger.error(f"Repeater command error: {e}")
            return {"success": False, "reason": str(e)}

    # -------------------------------------------------------------------------
    # Control Data
    # -------------------------------------------------------------------------

    async def send_control_data(self, data: Optional[bytes] = None) -> bool:
        """Send a CONTROL packet. If data is provided and valid (len 1-254, first byte has 0x80),
        send it as raw control payload; otherwise send a default discovery request (backward compat)."""
        if data and len(data) <= 254 and (data[0] & 0x80) != 0:
            try:
                pkt = Packet()
                pkt.header = PacketBuilder._create_header(
                    PAYLOAD_TYPE_CONTROL, route_type="direct"
                )
                pkt.path_len = 0
                pkt.path = bytearray()
                pkt.payload = bytearray(data)
                pkt.payload_len = len(data)
                return await self.node.dispatcher.send_packet(pkt, wait_for_ack=False)
            except Exception as e:
                logger.error(f"Error sending control data: {e}")
                return False
        try:
            tag = random.randint(0, 0xFFFFFFFF)
            pkt = PacketBuilder.create_discovery_request(tag, filter_mask=0x04)
            return await self.node.dispatcher.send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending control data: {e}")
            return False

    # -------------------------------------------------------------------------
    # Statistics (override for radio hardware)
    # -------------------------------------------------------------------------

    def _get_radio_stats(self) -> dict:
        radio_stats = super()._get_radio_stats()
        if hasattr(self._radio, "get_last_rssi"):
            radio_stats["last_rssi"] = self._radio.get_last_rssi()
        if hasattr(self._radio, "get_last_snr"):
            radio_stats["last_snr"] = self._radio.get_last_snr()
        return radio_stats

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _setup_packet_callbacks(self) -> None:
        dispatcher = self.node.dispatcher
        dispatcher.set_packet_received_callback(self._on_packet_received)
        dispatcher.set_packet_sent_callback(self._on_packet_sent)
        if hasattr(dispatcher, "protocol_response_handler") and dispatcher.protocol_response_handler:
            dispatcher.protocol_response_handler.set_binary_response_callback(
                self._on_binary_response
            )

    async def _on_packet_received(self, pkt: Any) -> None:
        from ..protocol.constants import ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD
        route_type = pkt.get_route_type()
        is_flood = route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD)
        self.stats.record_rx(is_flood=is_flood)

    async def _on_packet_sent(self, pkt: Any) -> None:
        pass

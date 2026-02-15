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
from typing import Any, Optional

from ..node.node import MeshNode
from ..protocol import LocalIdentity, Packet, PacketBuilder
from ..protocol.constants import (
    PAYLOAD_TYPE_CONTROL,
)
from .companion_base import CompanionBase
from .constants import (
    ADV_TYPE_CHAT,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
    PROTOCOL_CODE_ANON_REQ,
    PROTOCOL_CODE_BINARY_REQ,
    PROTOCOL_CODE_RAW_DATA,
    TXT_TYPE_PLAIN,
)
from .models import SentResult

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
    ) -> None:
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
    # Abstract method implementations
    # -------------------------------------------------------------------------

    async def _send_packet(
        self, pkt: Packet, wait_for_ack: bool = False
    ) -> bool:
        """Send a packet via the MeshNode dispatcher."""
        return await self.node.dispatcher.send_packet(pkt, wait_for_ack=wait_for_ack)

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
                protocol_code=PROTOCOL_CODE_RAW_DATA,
                data=data,
            )
            return SentResult(success=result.get("success", False))
        except Exception as e:
            logger.error(f"Error sending raw data: {e}")
            return SentResult(success=False)

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

    async def send_binary_request(self, pub_key: bytes, data: bytes) -> dict:
        """Legacy: send binary request and wait for response via waiter. Prefer send_binary_req + on_binary_response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        try:
            return await self.node.send_protocol_request(
                repeater_name=contact.name,
                protocol_code=PROTOCOL_CODE_BINARY_REQ,
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
                protocol_code=PROTOCOL_CODE_ANON_REQ,
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

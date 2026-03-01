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
from typing import Any, Optional

from ..node.node import MeshNode
from ..protocol import LocalIdentity, Packet
from ..protocol.constants import ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD
from .companion_base import CompanionBase
from .constants import (
    ADV_TYPE_CHAT,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
)

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

    async def _send_packet(self, pkt: Packet, wait_for_ack: bool = False) -> bool:
        """Send a packet via the MeshNode dispatcher."""
        return await self.node.dispatcher.send_packet(pkt, wait_for_ack=wait_for_ack)

    # -------------------------------------------------------------------------
    # Handler accessors (used by CompanionBase concrete send methods)
    # -------------------------------------------------------------------------

    def _get_protocol_response_handler(self) -> Any:
        return getattr(self.node.dispatcher, "protocol_response_handler", None)

    def _get_login_response_handler(self) -> Any:
        return getattr(self.node.dispatcher, "login_response_handler", None)

    def _get_text_handler(self) -> Any:
        return getattr(self.node.dispatcher, "text_message_handler", None)

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
    # Flood Scope (sync to dispatcher)
    # -------------------------------------------------------------------------

    def set_flood_scope(self, transport_key: Optional[bytes] = None) -> None:
        """Set or clear flood scope and propagate to the dispatcher."""
        super().set_flood_scope(transport_key)
        self.node.dispatcher.flood_transport_key = self._flood_transport_key

    def set_flood_region(self, region_name: Optional[str] = None) -> None:
        """Set flood region and propagate to the dispatcher."""
        super().set_flood_region(region_name)
        self.node.dispatcher.flood_transport_key = self._flood_transport_key

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
    # Key Management
    # -------------------------------------------------------------------------

    def import_private_key(self, key: bytes) -> bool:
        try:
            self._identity = LocalIdentity(seed=key)
            self._pending_ack_crcs.clear()
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
            logger.info(f"Imported new identity: {self._identity.get_public_key().hex()[:16]}...")
            return True
        except Exception as e:
            logger.error(f"Error importing private key: {e}")
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
        dispatcher.set_ack_received_listener(self._on_ack_received)
        if (
            hasattr(dispatcher, "protocol_response_handler")
            and dispatcher.protocol_response_handler
        ):
            dispatcher.protocol_response_handler.set_binary_response_callback(
                self._on_binary_response
            )
            dispatcher.protocol_response_handler.set_contact_path_updated_callback(
                self._on_contact_path_updated
            )

    async def _on_packet_received(self, pkt: Any) -> None:
        route_type = pkt.get_route_type()
        is_flood = route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD)
        self.stats.record_rx(is_flood=is_flood)

    async def _on_ack_received(self, crc: int) -> None:
        """Called by dispatcher when an ACK CRC is received; fire send_confirmed if pending."""
        await self._try_confirm_send(crc)

    async def _on_packet_sent(self, pkt: Any) -> None:
        pass

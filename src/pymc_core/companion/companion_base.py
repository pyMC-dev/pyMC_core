"""
CompanionBase - Shared logic for CompanionRadio and CompanionBridge.

Provides stores, event handling, contact management, device configuration,
and push callbacks. Subclasses implement TX via MeshNode or packet_injector.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import struct
import time
from collections import OrderedDict
from typing import Any, Callable, Optional

from ..node.events import EventService, EventSubscriber, MeshEvents
from ..protocol import LocalIdentity, PacketBuilder
from ..protocol.constants import (
    ADVERT_FLAG_HAS_NAME,
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
)
from .channel_store import ChannelStore
from .constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_REPEATER,
    ADV_TYPE_ROOM,
    ADV_TYPE_SENSOR,
    ADVERT_LOC_SHARE,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
    MAX_SIGN_DATA_SIZE,
    STATS_TYPE_CORE,
    STATS_TYPE_PACKETS,
    STATS_TYPE_RADIO,
)
from .contact_store import ContactStore
from .message_queue import MessageQueue
from .models import AdvertPath, Channel, Contact, NodePrefs, QueuedMessage
from .path_cache import PathCache
from .stats_collector import StatsCollector

logger = logging.getLogger("CompanionBase")

PUSH_CALLBACK_KEYS = [
    "message_received",
    "channel_message_received",
    "advert_received",
    "contact_path_updated",
    "send_confirmed",
    "trace_received",
    "node_discovered",
    "login_result",
    "telemetry_response",
    "status_response",
    "raw_data_received",
    "binary_response",
    "path_discovery_response",
]


class ResponseWaiter:
    """Helper for awaiting async protocol/login responses."""

    def __init__(self) -> None:
        self.event = asyncio.Event()
        self.data: dict = {"success": False, "text": None, "parsed": {}}

    def callback(
        self,
        success: bool,
        text: str,
        parsed_data: Optional[dict] = None,
    ) -> None:
        self.data["success"] = success
        self.data["text"] = text
        self.data["parsed"] = parsed_data or {}
        self.event.set()

    async def wait(self, timeout: float = 10.0) -> dict:
        try:
            await asyncio.wait_for(self.event.wait(), timeout=timeout)
            return self.data
        except asyncio.TimeoutError:
            return {**self.data, "timeout": True}


class _CompanionEventSubscriber(EventSubscriber):
    """Bridges event service to companion push callbacks."""

    def __init__(self, companion: CompanionBase) -> None:
        self._companion = companion

    async def handle_event(self, event_type: str, data: dict) -> None:
        await self._companion._handle_mesh_event(event_type, data)


def adv_type_to_flags(adv_type: int) -> int:
    """Convert ADV_TYPE_* constant to advertisement flags byte."""
    if adv_type == ADV_TYPE_CHAT:
        return ADVERT_FLAG_IS_CHAT_NODE
    elif adv_type == ADV_TYPE_REPEATER:
        return ADVERT_FLAG_IS_REPEATER
    elif adv_type == ADV_TYPE_ROOM:
        return ADVERT_FLAG_IS_ROOM_SERVER
    elif adv_type == ADV_TYPE_SENSOR:
        return 0x04
    return ADVERT_FLAG_IS_CHAT_NODE


class CompanionBase:
    """Base class for companion implementations.

    Provides shared stores, event handling, contact management, device config,
    and push callbacks. Subclasses implement TX (via node or packet_injector).
    """

    def _init_companion_stores(
        self,
        identity: LocalIdentity,
        node_name: str = "pyMC",
        adv_type: int = ADV_TYPE_CHAT,
        max_contacts: int = DEFAULT_MAX_CONTACTS,
        max_channels: int = DEFAULT_MAX_CHANNELS,
        offline_queue_size: int = DEFAULT_OFFLINE_QUEUE_SIZE,
        radio_config: Optional[dict] = None,
    ) -> None:
        """Initialize shared stores, prefs, event service, and push callbacks."""
        self._identity = identity
        self._radio_config = radio_config or {}
        self._running = False

        self.contacts = ContactStore(max_contacts)
        self.channels = ChannelStore(max_channels)
        self.message_queue = MessageQueue(offline_queue_size)
        self.path_cache = PathCache()
        self.stats = StatsCollector()

        self.prefs = NodePrefs(
            node_name=node_name,
            adv_type=adv_type,
            tx_power_dbm=self._radio_config.get("power", self._radio_config.get("tx_power", 20)),
            frequency_hz=self._radio_config.get("frequency", 915000000),
            bandwidth_hz=self._radio_config.get("bandwidth", 250000),
            spreading_factor=self._radio_config.get("spreading_factor", 10),
            coding_rate=self._radio_config.get("coding_rate", 5),
        )

        self._custom_vars: dict[str, str] = {}
        self._sign_buffer: Optional[bytearray] = None
        self._flood_transport_key: Optional[bytes] = None

        self._event_service = EventService()
        self._event_subscriber = _CompanionEventSubscriber(self)
        self._event_service.subscribe_all(self._event_subscriber)

        self._push_callbacks: dict[str, list[Callable]] = {
            k: [] for k in PUSH_CALLBACK_KEYS
        }

        # Pending binary requests by tag (hex) for matching responses
        self._pending_binary_requests: dict[str, dict] = {}

        # GRP_TXT dedup by packet hash: match Mesh.cpp behavior (only process when !_tables->hasSeen(pkt)),
        # so companion queues one frame per logical message like the firmware.
        self._seen_grp_txt: OrderedDict[str, float] = OrderedDict()
        self._seen_grp_txt_ttl = 300
        self._seen_grp_txt_max = 1000
        # TXT_MSG (direct) dedup by packet hash so reconnects don't queue the same packet multiple times.
        self._seen_txt: OrderedDict[str, float] = OrderedDict()
        self._seen_txt_ttl = 300
        self._seen_txt_max = 1000

    # -------------------------------------------------------------------------
    # Contact Management
    # -------------------------------------------------------------------------

    def get_contacts(self, since: int = 0) -> list[Contact]:
        return self.contacts.get_all(since=since)

    def get_contact_by_key(self, pub_key: bytes) -> Optional[Contact]:
        return self.contacts.get_by_key(pub_key)

    def get_contact_by_name(self, name: str) -> Optional[Contact]:
        proxy = self.contacts.get_by_name(name)
        if proxy:
            return self.contacts.get_by_key(bytes.fromhex(proxy.public_key))
        return None

    def add_update_contact(self, contact: Contact) -> bool:
        if contact.lastmod == 0:
            contact.lastmod = int(time.time())
        return self.contacts.add(contact)

    def remove_contact(self, pub_key: bytes) -> bool:
        return self.contacts.remove(pub_key)

    def export_contact(self, pub_key: Optional[bytes] = None) -> Optional[bytes]:
        if pub_key is None:
            key = self._identity.get_public_key()
            name = self.prefs.node_name.encode("utf-8")[:32]
            name = name + b"\x00" * (32 - len(name))
            lat = int(self.prefs.latitude * 1e6)
            lon = int(self.prefs.longitude * 1e6)
            return struct.pack(
                "<32sB32sii",
                key,
                self.prefs.adv_type,
                name,
                lat,
                lon,
            )
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return None
        name = contact.name.encode("utf-8")[:32]
        name = name + b"\x00" * (32 - len(name))
        lat = int(contact.gps_lat * 1e6)
        lon = int(contact.gps_lon * 1e6)
        return struct.pack(
            "<32sB32sii",
            contact.public_key,
            contact.adv_type,
            name,
            lat,
            lon,
        )

    def import_contact(self, packet_data: bytes) -> bool:
        if len(packet_data) < 73:
            logger.warning(f"Import data too short: {len(packet_data)} bytes")
            return False
        try:
            pub_key = packet_data[:32]
            adv_type = packet_data[32]
            name_raw = packet_data[33:65]
            lat, lon = struct.unpack_from("<ii", packet_data, 65)
            name = name_raw.split(b"\x00")[0].decode("utf-8", errors="replace")
            contact = Contact(
                public_key=pub_key,
                name=name,
                adv_type=adv_type,
                gps_lat=lat / 1e6,
                gps_lon=lon / 1e6,
                lastmod=int(time.time()),
            )
            return self.contacts.add(contact)
        except Exception as e:
            logger.error(f"Error importing contact: {e}")
            return False

    # -------------------------------------------------------------------------
    # Device Configuration
    # -------------------------------------------------------------------------

    def set_advert_name(self, name: str) -> None:
        """Set the node's advertised name (max 31 chars)."""
        self.prefs.node_name = name[:31]

    def set_advert_latlon(self, lat: float, lon: float) -> None:
        if not (-90.0 <= lat <= 90.0):
            raise ValueError(f"Latitude out of range: {lat}")
        if not (-180.0 <= lon <= 180.0):
            raise ValueError(f"Longitude out of range: {lon}")
        self.prefs.latitude = lat
        self.prefs.longitude = lon

    def set_radio_params(self, freq_hz: int, bw_hz: int, sf: int, cr: int) -> bool:
        if not (5 <= sf <= 12):
            raise ValueError(f"Spreading factor out of range: {sf}")
        if not (5 <= cr <= 8):
            raise ValueError(f"Coding rate out of range: {cr}")
        self.prefs.frequency_hz = freq_hz
        self.prefs.bandwidth_hz = bw_hz
        self.prefs.spreading_factor = sf
        self.prefs.coding_rate = cr
        return True

    def set_tx_power(self, power_dbm: int) -> bool:
        self.prefs.tx_power_dbm = power_dbm
        return True

    def set_tuning_params(self, rx_delay: float, airtime_factor: float) -> None:
        self.prefs.rx_delay_base = rx_delay
        self.prefs.airtime_factor = airtime_factor

    def get_tuning_params(self) -> tuple[float, float]:
        return (self.prefs.rx_delay_base, self.prefs.airtime_factor)

    def set_other_params(
        self,
        manual_add: int,
        telemetry_modes: int,
        advert_loc_policy: int,
        multi_acks: int,
    ) -> None:
        self.prefs.manual_add_contacts = manual_add
        self.prefs.telemetry_mode_base = telemetry_modes & 0x03
        self.prefs.telemetry_mode_location = (telemetry_modes >> 2) & 0x03
        self.prefs.telemetry_mode_environment = (telemetry_modes >> 4) & 0x03
        self.prefs.advert_loc_policy = advert_loc_policy
        self.prefs.multi_acks = multi_acks

    def get_self_info(self) -> NodePrefs:
        return copy.copy(self.prefs)

    def get_public_key(self) -> bytes:
        return self._identity.get_public_key()

    # -------------------------------------------------------------------------
    # Path & Routing
    # -------------------------------------------------------------------------

    def reset_path(self, pub_key: bytes) -> bool:
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        contact.out_path_len = -1
        contact.out_path = b""
        self.contacts.update(contact)
        return True

    def get_advert_path(self, pub_key_prefix: bytes) -> Optional[AdvertPath]:
        return self.path_cache.get_by_prefix(pub_key_prefix)

    # -------------------------------------------------------------------------
    # Channel Management
    # -------------------------------------------------------------------------

    def get_channel(self, idx: int) -> Optional[Channel]:
        return self.channels.get(idx)

    def set_channel(self, idx: int, name: str, secret: bytes) -> bool:
        # MeshCore DataStore uses 32-byte secret; GroupTextHandler uses up to 32 for HMAC
        if len(secret) < 32:
            secret = secret + b"\x00" * (32 - len(secret))
        elif len(secret) > 32:
            secret = secret[:32]
        return self.channels.set(idx, Channel(name=name[:32], secret=secret))

    # -------------------------------------------------------------------------
    # Signing Pipeline
    # -------------------------------------------------------------------------

    def sign_start(self) -> int:
        self._sign_buffer = bytearray()
        return MAX_SIGN_DATA_SIZE

    def sign_data(self, data: bytes) -> bool:
        if self._sign_buffer is None:
            logger.warning("sign_data called without sign_start")
            return False
        if len(self._sign_buffer) + len(data) > MAX_SIGN_DATA_SIZE:
            logger.warning("Sign data would overflow buffer")
            return False
        self._sign_buffer.extend(data)
        return True

    def sign_finish(self) -> Optional[bytes]:
        if self._sign_buffer is None:
            logger.warning("sign_finish called without sign_start")
            return None
        try:
            return self._identity.sign(bytes(self._sign_buffer))
        except Exception as e:
            logger.error(f"Signing error: {e}")
            return None
        finally:
            self._sign_buffer = None

    # -------------------------------------------------------------------------
    # Key Management
    # -------------------------------------------------------------------------

    def export_private_key(self) -> bytes:
        return self._identity.get_signing_key_bytes()

    # -------------------------------------------------------------------------
    # Flood Scope
    # -------------------------------------------------------------------------

    def set_flood_scope(self, transport_key: Optional[bytes] = None) -> None:
        if transport_key and len(transport_key) >= 16:
            self._flood_transport_key = transport_key[:16]
        else:
            self._flood_transport_key = None

    # -------------------------------------------------------------------------
    # Statistics (subclasses may override _get_radio_stats for STATS_TYPE_RADIO)
    # -------------------------------------------------------------------------

    def get_stats(self, stats_type: int = STATS_TYPE_PACKETS) -> dict:
        if stats_type == STATS_TYPE_CORE:
            return {
                "uptime_secs": self.stats.get_uptime_secs(),
                "queue_len": self.message_queue.count,
                "contacts_count": self.contacts.get_count(),
                "channels_count": self.channels.get_count(),
            }
        elif stats_type == STATS_TYPE_RADIO:
            return self._get_radio_stats()
        return self.stats.get_totals()

    def _get_radio_stats(self) -> dict:
        """Override in CompanionRadio for hardware RSSI/SNR. Default: prefs only."""
        return {
            "frequency_hz": self.prefs.frequency_hz,
            "bandwidth_hz": self.prefs.bandwidth_hz,
            "spreading_factor": self.prefs.spreading_factor,
            "coding_rate": self.prefs.coding_rate,
            "tx_power_dbm": self.prefs.tx_power_dbm,
        }

    # -------------------------------------------------------------------------
    # Custom Variables
    # -------------------------------------------------------------------------

    def get_custom_vars(self) -> dict[str, str]:
        return dict(self._custom_vars)

    def set_custom_var(self, name: str, value: str) -> bool:
        self._custom_vars[name] = value
        return True

    # -------------------------------------------------------------------------
    # Auto-Add Configuration
    # -------------------------------------------------------------------------

    def get_autoadd_config(self) -> int:
        return self.prefs.autoadd_config

    def set_autoadd_config(self, config: int) -> None:
        self.prefs.autoadd_config = config

    # -------------------------------------------------------------------------
    # Push Callbacks
    # -------------------------------------------------------------------------

    def on_message_received(self, callback: Callable) -> None:
        self._push_callbacks["message_received"].append(callback)

    def on_channel_message_received(self, callback: Callable) -> None:
        self._push_callbacks["channel_message_received"].append(callback)

    def on_advert_received(self, callback: Callable) -> None:
        self._push_callbacks["advert_received"].append(callback)

    def on_contact_path_updated(self, callback: Callable) -> None:
        self._push_callbacks["contact_path_updated"].append(callback)

    def on_send_confirmed(self, callback: Callable) -> None:
        self._push_callbacks["send_confirmed"].append(callback)

    def on_trace_received(self, callback: Callable) -> None:
        self._push_callbacks["trace_received"].append(callback)

    def on_node_discovered(self, callback: Callable) -> None:
        self._push_callbacks["node_discovered"].append(callback)

    def on_login_result(self, callback: Callable) -> None:
        self._push_callbacks["login_result"].append(callback)

    def on_telemetry_response(self, callback: Callable) -> None:
        self._push_callbacks["telemetry_response"].append(callback)

    def on_status_response(self, callback: Callable) -> None:
        self._push_callbacks["status_response"].append(callback)

    def on_raw_data_received(self, callback: Callable) -> None:
        self._push_callbacks["raw_data_received"].append(callback)

    def on_binary_response(self, callback: Callable) -> None:
        """Register callback for PUSH_CODE_BINARY_RESPONSE (0x8C). Callback(tag_bytes, response_data, ...)."""
        self._push_callbacks["binary_response"].append(callback)

    def on_path_discovery_response(self, callback: Callable) -> None:
        """Register callback for path discovery response (PUSH 0x8D). Callback(tag_bytes, contact_pubkey, out_path, in_path)."""
        self._push_callbacks["path_discovery_response"].append(callback)

    def register_binary_request(
        self,
        tag_hex: str,
        request_type: int,
        timeout_seconds: float,
        pubkey_prefix: str = "",
        context: Optional[dict] = None,
    ) -> None:
        """Register a pending binary request for matching responses. Call cleanup_expired_requests first."""
        self._pending_binary_requests[tag_hex] = {
            "request_type": request_type,
            "pubkey_prefix": pubkey_prefix,
            "expires_at": time.time() + timeout_seconds,
            "context": context or {},
        }

    def cleanup_expired_binary_requests(self) -> None:
        """Remove expired entries from _pending_binary_requests."""
        now = time.time()
        expired = [
            tag for tag, info in self._pending_binary_requests.items()
            if now > info["expires_at"]
        ]
        for tag in expired:
            del self._pending_binary_requests[tag]

    async def _on_binary_response(
        self,
        tag_bytes: bytes,
        response_data: bytes,
        path_info: Optional[tuple] = None,
    ) -> None:
        """Called by ProtocolResponseHandler when a binary response (tag + data, optional path) is received."""
        if path_info is not None:
            if await self._try_handle_path_discovery(tag_bytes, path_info):
                return
        self.cleanup_expired_binary_requests()
        tag_hex = tag_bytes.hex()
        info = self._pending_binary_requests.pop(tag_hex, None)
        if not info:
            # Skip log for small payloads (e.g. login response already handled by LoginResponseHandler)
            if len(response_data) >= 20:
                logger.debug(f"Binary response for unknown tag {tag_hex}")
            await self._fire_callbacks("binary_response", tag_bytes, response_data)
            return
        request_type = info["request_type"]
        pubkey_prefix = info.get("pubkey_prefix", "")
        context = info.get("context", {})
        parsed = None
        try:
            from . import binary_parsing
            parsed = binary_parsing.parse_binary_response(
                request_type, response_data, pubkey_prefix=pubkey_prefix, context=context
            )
        except Exception as e:
            logger.debug(f"Binary response parse for type {request_type}: {e}")
        await self._fire_callbacks(
            "binary_response", tag_bytes, response_data, parsed, request_type
        )

    async def _try_handle_path_discovery(
        self, tag_bytes: bytes, path_info: tuple
    ) -> bool:
        """If this tag is a pending path discovery, fire path_discovery_response and return True. Override in bridge."""
        return False

    # -------------------------------------------------------------------------
    # Event Handling (shared)
    # -------------------------------------------------------------------------

    async def _handle_mesh_event(self, event_type: str, data: dict) -> None:
        try:
            if event_type == MeshEvents.NEW_MESSAGE:
                await self._handle_new_message(data)
            elif event_type == MeshEvents.NEW_CHANNEL_MESSAGE:
                await self._handle_new_channel_message(data)
            elif event_type == MeshEvents.NEW_CONTACT:
                await self._fire_callbacks("node_discovered", data)
            elif event_type == MeshEvents.CONTACT_UPDATED:
                pass
            elif event_type == MeshEvents.NODE_DISCOVERED:
                await self._fire_callbacks("node_discovered", data)
            elif event_type == MeshEvents.TELEMETRY_UPDATED:
                await self._fire_callbacks("telemetry_response", data)
        except Exception as e:
            logger.error(f"Error handling mesh event {event_type}: {e}")

    async def _handle_new_message(self, data: dict) -> None:
        # Deduplicate by packet hash so reconnects don't queue the same packet multiple times.
        pkt_hash = data.get("packet_hash")
        if pkt_hash:
            now = time.time()
            if pkt_hash in self._seen_txt:
                return
            expired = [k for k, ts in self._seen_txt.items() if now - ts > self._seen_txt_ttl]
            for k in expired:
                del self._seen_txt[k]
            self._seen_txt[pkt_hash] = now
            if len(self._seen_txt) > self._seen_txt_max:
                self._seen_txt.popitem(last=False)

        sender_key_hex = data.get("contact_pubkey", "")
        sender_key = bytes.fromhex(sender_key_hex) if sender_key_hex else b""
        # Handler publishes "message_text"; accept "text" for compatibility
        message_text = (data.get("message_text") or data.get("text") or "").rstrip("\x00")
        msg = QueuedMessage(
            sender_key=sender_key,
            txt_type=data.get("txt_type", data.get("flags", 0)),
            timestamp=data.get("timestamp", int(time.time())),
            text=message_text,
            is_channel=False,
            path_len=0,
        )
        self.message_queue.push(msg)
        await self._fire_callbacks(
            "message_received",
            sender_key,
            message_text,
            msg.timestamp,
            msg.txt_type,
        )

    async def _handle_new_channel_message(self, data: dict) -> None:
        # Deduplicate by packet hash so we queue one frame per logical message, matching
        # firmware: Mesh.cpp only calls onChannelMessageRecv when !_tables->hasSeen(pkt).
        pkt_hash = data.get("packet_hash")
        if pkt_hash:
            now = time.time()
            if pkt_hash in self._seen_grp_txt:
                return
            expired = [k for k, ts in self._seen_grp_txt.items() if now - ts > self._seen_grp_txt_ttl]
            for k in expired:
                del self._seen_grp_txt[k]
            self._seen_grp_txt[pkt_hash] = now
            if len(self._seen_grp_txt) > self._seen_grp_txt_max:
                self._seen_grp_txt.popitem(last=False)

        path_len = data.get("path_len", 0)
        channel_name = data.get("channel_name", "")
        # Resolve channel index so sync_next_message returns correct channel_idx in the frame
        channel_idx = 0
        if getattr(self, "channels", None) and hasattr(self.channels, "find_by_name"):
            idx = self.channels.find_by_name(channel_name)
            if idx is not None:
                channel_idx = idx
        # MeshCore client expects "SenderName: Message" format in text field; it parses to show
        # sender and message separately. Use full_content (not message_text) so client can split.
        # Strip trailing nulls so frame matches firmware (exact string length, no padding).
        display_text = (data.get("full_content", data.get("message_text", "")) or "").rstrip("\x00")
        msg = QueuedMessage(
            sender_key=b"",
            txt_type=0,
            timestamp=data.get("timestamp", int(time.time())),
            text=display_text,
            is_channel=True,
            channel_idx=channel_idx,
            path_len=path_len,
        )
        self.message_queue.push(msg)
        await self._fire_callbacks(
            "channel_message_received",
            data.get("channel_name", ""),
            data.get("sender_name", ""),
            display_text,
            msg.timestamp,
            path_len,
            channel_idx,
        )

    async def _fire_callbacks(self, event_name: str, *args: Any) -> None:
        for callback in self._push_callbacks.get(event_name, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(*args)
                else:
                    callback(*args)
            except Exception as e:
                logger.error(f"Error in {event_name} callback: {e}")

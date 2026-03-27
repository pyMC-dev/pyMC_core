"""
CompanionBase - Shared logic for CompanionRadio and CompanionBridge.

Provides stores, event handling, contact management, device configuration,
and push callbacks. Subclasses implement TX via MeshNode or packet_injector.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import random
import struct
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Any, Callable, Iterable, Optional

from ..node.events import EventService, EventSubscriber, MeshEvents
from ..protocol import LocalIdentity, Packet, PacketBuilder
from ..protocol.constants import (
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
    ADVERT_FLAG_IS_SENSOR,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_CONTROL,
    PH_ROUTE_MASK,
    PUB_KEY_SIZE,
    REQ_TYPE_GET_STATUS,
    REQ_TYPE_GET_TELEMETRY_DATA,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
    TELEM_PERM_BASE,
)
from ..protocol.packet_utils import PathUtils
from ..protocol.transport_keys import calc_transport_code, get_auto_key_for
from .channel_store import ChannelStore
from .constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_REPEATER,
    ADV_TYPE_ROOM,
    ADV_TYPE_SENSOR,
    ADVERT_LOC_SHARE,
    AUTOADD_CHAT,
    AUTOADD_OVERWRITE_OLDEST,
    AUTOADD_REPEATER,
    AUTOADD_ROOM,
    AUTOADD_SENSOR,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
    DEFAULT_RESPONSE_TIMEOUT_MS,
    MAX_PENDING_ACK_CRCS,
    MAX_SIGN_DATA_SIZE,
    PROTOCOL_CODE_ANON_REQ,
    PROTOCOL_CODE_BINARY_REQ,
    PROTOCOL_CODE_RAW_DATA,
    PUSH_CODE_TELEMETRY_RESPONSE,
    STATS_TYPE_CORE,
    STATS_TYPE_PACKETS,
    STATS_TYPE_RADIO,
    TXT_TYPE_PLAIN,
)
from .contact_store import ContactStore
from .message_queue import MessageQueue
from .models import AdvertPath, Channel, Contact, NodePrefs, QueuedMessage, SentResult
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
    "rx_log_data",  # raw RX with SNR/RSSI (CompanionRadio only; matches PUSH 0x88)
    "binary_response",
    "path_discovery_response",
    "contact_deleted",
    "contacts_full",
    "channel_updated",
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
        return ADVERT_FLAG_IS_SENSOR
    return ADVERT_FLAG_IS_CHAT_NODE


class CompanionBase(ABC):
    """Abstract base class for companion implementations.

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
        initial_contacts: Optional[Iterable[Contact]] = None,
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
        self._time_offset: float = 0.0

        self._event_service = EventService()
        self._event_subscriber = _CompanionEventSubscriber(self)
        self._event_service.subscribe_all(self._event_subscriber)

        self._push_callbacks: dict[str, list[Callable]] = {k: [] for k in PUSH_CALLBACK_KEYS}

        # Pending binary requests by tag (hex) for matching responses
        self._pending_binary_requests: dict[str, dict] = {}
        # Pending path discovery tags for matching responses
        self._pending_discovery_tags: set[int] = set()
        # Pending ACK CRCs for send_confirmed (Bridge and Radio)
        self._pending_ack_crcs: set[int] = set()

        # GRP_TXT dedup by packet hash: match Mesh.cpp (!_tables->hasSeen(pkt));
        # companion queues one frame per logical message like the firmware.
        self._seen_grp_txt: OrderedDict[str, float] = OrderedDict()
        self._seen_grp_txt_ttl = 300
        self._seen_grp_txt_max = 1000
        # TXT_MSG (direct) dedup by packet hash so reconnects don't re-queue same packet.
        self._seen_txt: OrderedDict[str, float] = OrderedDict()
        self._seen_txt_ttl = 300
        self._seen_txt_max = 1000

        # Allow subclasses to restore persisted preferences on startup.
        self._load_prefs()

        # Optional bulk load of contacts (e.g. from persistence on boot).
        if initial_contacts is not None:
            self.contacts.load_from(initial_contacts)

    # -------------------------------------------------------------------------
    # Preference Persistence Hooks
    # -------------------------------------------------------------------------

    def _save_prefs(self) -> None:
        """Hook: persist the current :attr:`prefs` to stable storage.

        The default implementation is a no-op — preferences live only in
        memory.  Subclasses that need persistence (e.g. backed by SQLite or
        a JSON file) should override this method.

        Called automatically after any preference-mutating method
        (``set_radio_params``, ``set_tx_power``, ``set_tuning_params``,
        ``set_autoadd_config``, ``set_other_params``,
        ``set_advert_name``, ``set_advert_latlon``).
        """

    def _load_prefs(self) -> None:
        """Hook: restore :attr:`prefs` from stable storage on startup.

        The default implementation is a no-op.  Subclasses should override
        to populate :attr:`self.prefs` fields from their persistence layer.

        Called once at the end of :meth:`_init_companion_stores`.
        """

    # -------------------------------------------------------------------------
    # Contact Management
    # -------------------------------------------------------------------------

    def get_contacts(self, since: int = 0) -> list[Contact]:
        """Return all contacts, optionally filtered by modification time."""
        return self.contacts.get_all(since=since)

    def get_contact_by_key(self, pub_key: bytes) -> Optional[Contact]:
        """Look up a contact by its full 32-byte public key."""
        return self.contacts.get_by_key(pub_key)

    def get_contact_by_name(self, name: str) -> Optional[Contact]:
        """Look up a contact by name, returning the full Contact or None."""
        proxy = self.contacts.get_by_name(name)
        if proxy:
            return self.contacts.get_by_key(bytes.fromhex(proxy.public_key))
        return None

    def add_update_contact(self, contact: Contact) -> bool:
        """Add or update a contact, setting lastmod if unset."""
        if contact.lastmod == 0:
            contact.lastmod = int(time.time())
        return self.contacts.add(contact)

    def remove_contact(self, pub_key: bytes) -> bool:
        """Remove a contact by public key."""
        return self.contacts.remove(pub_key)

    def export_contact(self, pub_key: Optional[bytes] = None) -> Optional[bytes]:
        """Export a contact (or self) as a 73-byte binary packet."""
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
        """Import a contact from a 73-byte binary packet."""
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
        self._save_prefs()
        self._sync_our_node_name_to_handlers()

    def _get_group_text_handler(self) -> Optional[Any]:
        """Return the group text handler for name sync, or None. Override in Radio/Bridge."""
        return None

    def _sync_our_node_name_to_handlers(self) -> None:
        """Sync node name to group text handler for echo detection."""
        handler = self._get_group_text_handler()
        if handler is not None:
            handler.set_our_node_name(self.prefs.node_name)

    def set_advert_latlon(self, lat: float, lon: float) -> None:
        """Set the GPS coordinates included in advertisements."""
        if not (-90.0 <= lat <= 90.0):
            raise ValueError(f"Latitude out of range: {lat}")
        if not (-180.0 <= lon <= 180.0):
            raise ValueError(f"Longitude out of range: {lon}")
        self.prefs.latitude = lat
        self.prefs.longitude = lon
        self._save_prefs()

    def set_radio_params(self, freq_hz: int, bw_hz: int, sf: int, cr: int) -> bool:
        """Set radio parameters (frequency, bandwidth, SF, CR)."""
        if not (5 <= sf <= 12):
            raise ValueError(f"Spreading factor out of range: {sf}")
        if not (5 <= cr <= 8):
            raise ValueError(f"Coding rate out of range: {cr}")
        self.prefs.frequency_hz = freq_hz
        self.prefs.bandwidth_hz = bw_hz
        self.prefs.spreading_factor = sf
        self.prefs.coding_rate = cr
        self._save_prefs()
        return True

    def set_tx_power(self, power_dbm: int) -> bool:
        """Set the transmit power in dBm."""
        self.prefs.tx_power_dbm = power_dbm
        self._save_prefs()
        return True

    def set_tuning_params(self, rx_delay: float, airtime_factor: float) -> None:
        """Set RX delay and airtime factor tuning parameters."""
        self.prefs.rx_delay_base = rx_delay
        self.prefs.airtime_factor = airtime_factor
        self._save_prefs()

    def get_tuning_params(self) -> tuple[float, float]:
        """Return the current (rx_delay, airtime_factor) tuning parameters."""
        return (self.prefs.rx_delay_base, self.prefs.airtime_factor)

    def get_radio_params(self) -> dict:
        """Return current radio configuration (frequency, bandwidth, SF, CR, TX power, tuning).

        Use this to fetch the radio configuration details. Keys match the arguments
        to set_radio_params/set_tx_power/set_tuning_params: frequency_hz, bandwidth_hz,
        spreading_factor, coding_rate, tx_power_dbm, rx_delay_base, airtime_factor.
        """
        return {
            "frequency_hz": self.prefs.frequency_hz,
            "bandwidth_hz": self.prefs.bandwidth_hz,
            "spreading_factor": self.prefs.spreading_factor,
            "coding_rate": self.prefs.coding_rate,
            "tx_power_dbm": self.prefs.tx_power_dbm,
            "rx_delay_base": self.prefs.rx_delay_base,
            "airtime_factor": self.prefs.airtime_factor,
        }

    def get_time(self) -> int:
        """Return the current device time as a Unix timestamp."""
        return int(time.time() + self._time_offset)

    def set_time(self, secs: int) -> bool:
        """Set the device time.  Returns False if *secs* is in the past."""
        current = self.get_time()
        if secs < current:
            return False
        self._time_offset = secs - time.time()
        return True

    def set_other_params(
        self,
        manual_add: int,
        telemetry_modes: int,
        advert_loc_policy: int,
        multi_acks: int,
    ) -> None:
        """Set additional node parameters (manual add, telemetry, location, multi-acks)."""
        self.prefs.manual_add_contacts = manual_add
        self.prefs.telemetry_mode_base = telemetry_modes & 0x03
        self.prefs.telemetry_mode_location = (telemetry_modes >> 2) & 0x03
        self.prefs.telemetry_mode_environment = (telemetry_modes >> 4) & 0x03
        self.prefs.advert_loc_policy = advert_loc_policy
        self.prefs.multi_acks = multi_acks
        self._save_prefs()

    def set_path_hash_mode(self, mode: int) -> None:
        """Set path hash encoding mode (0=1-byte, 1=2-byte, 2=3-byte hashes)."""
        self.prefs.path_hash_mode = mode
        self._save_prefs()

    def get_self_info(self) -> NodePrefs:
        """Return a copy of the current node preferences."""
        return copy.copy(self.prefs)

    def get_public_key(self) -> bytes:
        """Return this node's 32-byte Ed25519 public key."""
        return self._identity.get_public_key()

    # -------------------------------------------------------------------------
    # Path & Routing
    # -------------------------------------------------------------------------

    def reset_path(self, pub_key: bytes) -> bool:
        """Reset the outbound routing path for a contact."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        contact.out_path_len = -1
        contact.out_path = b""
        self.contacts.update(contact)
        return True

    def get_advert_path(self, pub_key_prefix: bytes) -> Optional[AdvertPath]:
        """Look up a cached advert path by public key prefix."""
        return self.path_cache.get_by_prefix(pub_key_prefix)

    # -------------------------------------------------------------------------
    # Channel Management
    # -------------------------------------------------------------------------

    def get_channel(self, idx: int) -> Optional[Channel]:
        """Return the channel at the given index, or None."""
        return self.channels.get(idx)

    def set_channel(self, idx: int, name: str, secret: bytes) -> bool:
        """Set a channel at the given index with name and 32-byte secret."""
        # MeshCore DataStore uses 32-byte secret; GroupTextHandler uses up to 32 for HMAC
        if len(secret) < 32:
            secret = secret + b"\x00" * (32 - len(secret))
        elif len(secret) > 32:
            secret = secret[:32]
        ok = self.channels.set(idx, Channel(name=name[:32], secret=secret))
        if ok:
            ch = self.channels.get(idx)
            self._schedule_fire_callbacks("channel_updated", idx, ch)
        return ok

    def remove_channel(self, idx: int) -> bool:
        """Remove the channel at the given index. Fires on_channel_updated(idx, None)."""
        ok = self.channels.remove(idx)
        if ok:
            self._schedule_fire_callbacks("channel_updated", idx, None)
        return ok

    # -------------------------------------------------------------------------
    # Signing Pipeline
    # -------------------------------------------------------------------------

    def sign_start(self) -> int:
        """Begin a signing session; returns the maximum sign buffer size."""
        self._sign_buffer = bytearray()
        return MAX_SIGN_DATA_SIZE

    def sign_data(self, data: bytes) -> bool:
        """Append data to the signing buffer."""
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
        """Return the raw signing key bytes for backup/export."""
        return self._identity.get_signing_key_bytes()

    # -------------------------------------------------------------------------
    # Flood Scope
    # -------------------------------------------------------------------------

    def set_flood_scope(self, transport_key: Optional[bytes] = None) -> None:
        """Set or clear the flood transport key for scoped flooding."""
        if transport_key and len(transport_key) >= 16:
            self._flood_transport_key = transport_key[:16]
        else:
            self._flood_transport_key = None

    def set_flood_region(self, region_name: Optional[str] = None) -> None:
        """Set flood scope from a region name (e.g., ``'#usa'``) or clear it.

        Derives the 16-byte transport key automatically via SHA-256 of the
        region name.  A leading ``#`` is added if not already present.
        Pass ``None`` to clear the scope (flood to all).
        """
        if region_name:
            if not region_name.startswith("#"):
                region_name = f"#{region_name}"
            self._flood_transport_key = get_auto_key_for(region_name)
        else:
            self._flood_transport_key = None

    def _apply_flood_scope(self, pkt: Packet) -> None:
        """Apply flood scope transport codes to a packet in-place.

        If ``_flood_transport_key`` is set and the packet uses flood routing,
        calculates the transport code, attaches it to the packet, and changes
        the route type to ``ROUTE_TYPE_TRANSPORT_FLOOD``.

        Matches firmware ``sendFloodScoped()`` in ``BaseChatMesh.cpp``.
        """
        if self._flood_transport_key is None:
            return
        route_type = pkt.get_route_type()
        if route_type != ROUTE_TYPE_FLOOD:
            return  # only scope flood packets, not direct
        code = calc_transport_code(self._flood_transport_key, pkt)
        pkt.transport_codes[0] = code
        pkt.transport_codes[1] = 0  # reserved for home region (firmware TODO)
        # Switch route type from FLOOD -> TRANSPORT_FLOOD
        pkt.header = (pkt.header & ~0x03) | ROUTE_TYPE_TRANSPORT_FLOOD

    def _apply_path_hash_mode(self, pkt: Packet) -> None:
        """Encode the device's path_hash_mode in originated packets.

        When a packet has 0 hops (freshly originated), sets bits 6-7 of
        ``path_len`` to encode the hash size from ``prefs.path_hash_mode``.
        Packets with existing hops (stored contact paths) are untouched.
        Trace packets are excluded because the repeater's trace handler uses
        ``path``/``path_len`` to store SNR values, not routing hashes.
        Sets ``_path_hash_mode_applied`` so the dispatcher does not overwrite.
        """
        pkt.apply_path_hash_mode(self.prefs.path_hash_mode, mark_applied=True)

    # -------------------------------------------------------------------------
    # Statistics (subclasses may override _get_radio_stats for STATS_TYPE_RADIO)
    # -------------------------------------------------------------------------

    def get_stats(self, stats_type: int = STATS_TYPE_PACKETS) -> dict:
        """Return statistics of the requested type (core, radio, or packets)."""
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
        """Return a copy of all custom variables."""
        return dict(self._custom_vars)

    def set_custom_var(self, name: str, value: str) -> bool:
        """Set a custom variable by name."""
        self._custom_vars[name] = value
        return True

    # -------------------------------------------------------------------------
    # Auto-Add Configuration
    # -------------------------------------------------------------------------

    def get_autoadd_config(self) -> int:
        """Return the current auto-add configuration bitmask."""
        return self.prefs.autoadd_config

    def set_autoadd_config(self, config: int) -> None:
        """Set the auto-add configuration bitmask."""
        self.prefs.autoadd_config = config
        self._save_prefs()

    # Map ADV_TYPE_* → AUTOADD_* bitmask bits (mirrors C++ shouldAutoAddContactType)
    _AUTOADD_TYPE_MAP: dict[int, int] = {
        ADV_TYPE_CHAT: AUTOADD_CHAT,  # 1 → 0x02
        ADV_TYPE_REPEATER: AUTOADD_REPEATER,  # 2 → 0x04
        ADV_TYPE_ROOM: AUTOADD_ROOM,  # 3 → 0x08
        ADV_TYPE_SENSOR: AUTOADD_SENSOR,  # 4 → 0x10
    }

    def should_auto_add_contact_type(self, contact_type: int) -> bool:
        """Check if a contact type should be auto-added based on current preferences.

        Mirrors C++ MyMesh::shouldAutoAddContactType (MyMesh.cpp:281-304).
        """
        # manual_add_contacts bit 0 == 0  →  auto-add ALL types
        if (self.prefs.manual_add_contacts & 1) == 0:
            return True
        # Selective mode: check the type-specific bit in autoadd_config
        type_bit = self._AUTOADD_TYPE_MAP.get(contact_type, 0)
        return bool(self.prefs.autoadd_config & type_bit) if type_bit else False

    def should_overwrite_when_full(self) -> bool:
        """Check if overwrite-oldest is enabled. Mirrors C++ shouldOverwriteWhenFull."""
        return bool(self.prefs.autoadd_config & AUTOADD_OVERWRITE_OLDEST)

    async def _apply_advert_to_stores(
        self,
        contact: Contact,
        inbound_path: Optional[bytes] = None,
        *,
        path_len_encoded: Optional[int] = None,
    ) -> Optional[Contact]:
        """Apply advert to ContactStore and PathCache. Shared by Bridge and NODE_DISCOVERED.

        Mirrors C++ BaseChatMesh::onAdvertRecv (existing update, auto-add filter,
        overwrite when full). Returns the Contact if added or updated, None otherwise.
        Path cache is updated for all valid contacts (pub_key >= 7, name non-empty).

        Args:
            path_len_encoded: Encoded path_len byte from the packet. If None,
                falls back to len(inbound_path) (assumes 1-byte hashes).
        """
        try:
            if len(contact.public_key) < 7 or not contact.name:
                return None
            inbound_path = inbound_path or b""
            advert_path_len = (
                path_len_encoded if path_len_encoded is not None else len(inbound_path)
            )
            self.path_cache.update(
                AdvertPath(
                    public_key_prefix=contact.public_key[:7],
                    name=contact.name,
                    path_len=advert_path_len,
                    path=inbound_path,
                    recv_timestamp=int(time.time()),
                )
            )
            existing = self.contacts.get_by_key(contact.public_key)
            if existing is not None:
                contact.out_path_len = existing.out_path_len
                contact.out_path = existing.out_path
                contact.flags = existing.flags
                contact.sync_since = existing.sync_since
                if contact.last_advert_packet is None:
                    contact.last_advert_packet = existing.last_advert_packet
                self.contacts.update(contact)
                return contact
            if not self.should_auto_add_contact_type(contact.adv_type):
                logger.debug("Auto-add filtered: type %d not allowed", contact.adv_type)
                return None
            if self.should_overwrite_when_full() and self.contacts.is_full():
                ok, overwritten = self.contacts.add_or_overwrite(contact)
                if ok and overwritten:
                    await self._fire_callbacks("contact_deleted", overwritten)
                elif not ok:
                    await self._fire_callbacks("contacts_full")
                return contact if ok else None
            added = self.contacts.add(contact)
            if not added and self.contacts.is_full():
                await self._fire_callbacks("contacts_full")
            return contact if added else None
        except Exception as e:
            logger.error("Error applying advert to stores: %s", e)
            return None

    # -------------------------------------------------------------------------
    # Push Callbacks
    # -------------------------------------------------------------------------

    def clear_push_callbacks(self) -> None:
        """Remove all registered push callbacks.

        Called by FrameServer between client connections so that stale
        closures from a previous connection are not invoked on the next one.
        """
        for key in self._push_callbacks:
            self._push_callbacks[key].clear()

    def on_message_received(self, callback: Callable) -> None:
        self._push_callbacks["message_received"].append(callback)

    def on_channel_message_received(self, callback: Callable) -> None:
        self._push_callbacks["channel_message_received"].append(callback)

    def on_advert_received(self, callback: Callable) -> None:
        self._push_callbacks["advert_received"].append(callback)

    def on_contact_path_updated(self, callback: Callable) -> None:
        self._push_callbacks["contact_path_updated"].append(callback)

    async def _on_contact_path_updated(self, pub: bytes, path_len: int, path_bytes: bytes) -> None:
        """Called by ProtocolResponseHandler when contact's out_path is updated from a PATH packet.

        Matches companion firmware behaviour: PATH updates are only applied
        (and pushed to the client) for contacts that already exist in the
        store.  Unknown public keys are silently ignored.
        """
        contact = self.get_contact_by_key(pub)
        if contact is None:
            return  # Firmware does not send PATH for non-contacts
        contact.out_path_len = path_len
        contact.out_path = path_bytes
        self.contacts.update(contact)
        await self._fire_callbacks("contact_path_updated", contact)

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

    def on_rx_log_data(self, callback: Callable) -> None:
        """Register callback for raw RX with SNR/RSSI (CompanionRadio only).

        Callback(snr: float, rssi: int, raw_bytes: bytes). Same data as
        PUSH_CODE_LOG_RX_DATA (0x88). Only fired when using CompanionRadio;
        CompanionBridge does not own the radio.
        """
        self._push_callbacks["rx_log_data"].append(callback)

    def on_binary_response(self, callback: Callable) -> None:
        """Register callback for PUSH 0x8C. Callback(tag_bytes, response_data)."""
        self._push_callbacks["binary_response"].append(callback)

    def on_path_discovery_response(self, callback: Callable) -> None:
        """Register callback for path discovery 0x8D. (tag_bytes, pubkey, out_path, in_path)."""
        self._push_callbacks["path_discovery_response"].append(callback)

    def on_contact_deleted(self, callback: Callable) -> None:
        """Register callback for PUSH 0x8F (contact overwritten). Callback(pub_key_bytes)."""
        self._push_callbacks["contact_deleted"].append(callback)

    def on_contacts_full(self, callback: Callable) -> None:
        """Register callback for PUSH 0x90 (contacts store full). Callback()."""
        self._push_callbacks["contacts_full"].append(callback)

    def on_channel_updated(self, callback: Callable) -> None:
        """Register callback for channel set/remove. Callback(idx: int, channel_or_none)."""
        self._push_callbacks["channel_updated"].append(callback)

    def register_binary_request(
        self,
        tag_hex: str,
        request_type: int,
        timeout_seconds: float,
        pubkey_prefix: str = "",
        context: Optional[dict] = None,
    ) -> None:
        """Register a pending binary request. Call cleanup_expired_requests first."""
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
            tag for tag, info in self._pending_binary_requests.items() if now > info["expires_at"]
        ]
        for tag in expired:
            del self._pending_binary_requests[tag]

    async def _on_binary_response(
        self,
        tag_bytes: bytes,
        response_data: bytes,
        path_info: Optional[tuple] = None,
    ) -> None:
        """Called when binary response (tag + data, optional path) received."""
        if path_info is not None:
            if await self._try_handle_path_discovery(tag_bytes, path_info):
                return
        self.cleanup_expired_binary_requests()
        tag_hex = tag_bytes.hex()
        info = self._pending_binary_requests.pop(tag_hex, None)
        if not info:
            # Skip log for small payloads (e.g. login response handled elsewhere)
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

    async def _try_handle_path_discovery(self, tag_bytes: bytes, path_info: tuple) -> bool:
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

    # -------------------------------------------------------------------------
    # Abstract methods (subclasses must implement)
    # -------------------------------------------------------------------------

    @abstractmethod
    async def _send_packet(self, pkt: Packet, wait_for_ack: bool = False) -> bool:
        """Send a packet via the subclass transport (radio or packet_injector)."""

    @abstractmethod
    async def start(self) -> None:
        """Start the companion."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop the companion."""

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Return whether the companion is currently running."""

    @abstractmethod
    def import_private_key(self, key: bytes) -> bool:
        """Import a private key and rebuild the identity."""

    def _get_protocol_response_handler(self) -> Any:
        """Return the protocol response handler, or ``None``.

        Subclasses that support request/response methods (telemetry, status,
        binary request, etc.) must override this to return their handler.
        """
        return None

    def _get_login_response_handler(self) -> Any:
        """Return the login response handler, or ``None``."""
        return None

    def _get_text_handler(self) -> Any:
        """Return the text message handler, or ``None``."""
        return None

    # -------------------------------------------------------------------------
    # Unified TX methods (shared between Radio and Bridge)
    # -------------------------------------------------------------------------

    async def advertise(self, flood: bool = True) -> bool:
        """Broadcast an advertisement packet."""
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
        self._apply_flood_scope(pkt)
        self._apply_path_hash_mode(pkt)
        success = await self._send_packet(pkt, wait_for_ack=False)
        if success:
            self.stats.record_tx(is_flood=flood)
        else:
            self.stats.record_tx_error()
        return success

    async def share_contact(self, pub_key: bytes) -> bool:
        """Share a contact's advert on zero hops (direct route, empty path).

        Matches firmware ``BaseChatMesh::shareContactZeroHop``: replay the last stored
        raw ADVERT wire bytes for this contact (see ``Contact.last_advert_packet``),
        with ``Mesh::sendZeroHop``-style header/path normalization. Does not re-sign with
        the companion identity. If no blob is stored (never heard an advert for this
        contact), returns ``False``.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        blob = contact.last_advert_packet
        if not blob:
            return False
        try:
            pkt = Packet()
            if not pkt.read_from(bytes(blob)):
                return False
            if pkt.get_payload_type() != PAYLOAD_TYPE_ADVERT:
                return False
            if len(pkt.payload) >= PUB_KEY_SIZE:
                embedded = bytes(pkt.payload[:PUB_KEY_SIZE])
                if embedded != pub_key:
                    logger.warning(
                        "Cached advert pubkey does not match contact key; refusing share"
                    )
                    return False
            # Mesh::sendZeroHop (non-transport): direct route, path_len=0, empty path
            pkt.header = (pkt.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT
            pkt.transport_codes = [0, 0]
            pkt.path_len = 0
            pkt.path = bytearray()
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sharing contact: {e}")
            return False

    async def send_trace_path_raw(
        self,
        tag: int,
        auth_code: int,
        flags: int,
        path_bytes: bytes,
    ) -> bool:
        """Send a trace packet with an explicit path."""
        try:
            path_list = list(path_bytes)
            pkt = PacketBuilder.create_trace(tag, auth_code, flags, path=path_list)
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending trace (raw path): {e}")
            return False

    async def send_binary_req(
        self, pub_key: bytes, data: bytes, timeout_seconds: float = 15.0
    ) -> SentResult:
        """Send binary request (CMD_SEND_BINARY_REQ).

        data = request_type(1) + optional payload.
        Returns SentResult with expected_ack (4-byte tag as int) and timeout_ms.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return SentResult(success=False)
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return SentResult(success=False)
        request_type = data[0] if len(data) >= 1 else 0
        # C++ companion pattern (BaseChatMesh::sendRequest):
        #   tag = getRTCClock()->getCurrentTimeUnique()
        #   memcpy(temp, &tag, 4);  memcpy(&temp[4], req_data, data_len);
        # create_protocol_request packs: timestamp(4) + protocol_code(1) + extra_data.
        # The repeater echoes sender_timestamp (bytes 0-3) in the response.
        # So the timestamp IS the tag — we capture it from create_protocol_request.
        protocol_code = request_type
        req_payload = data[1:]  # request params only; timestamp provides uniqueness
        self.cleanup_expired_binary_requests()
        try:
            pkt, timestamp = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=protocol_code,
                data=req_payload,
            )
            # Use the timestamp as the tag — matches what the repeater echoes back
            tag_int = timestamp
            tag_bytes = tag_int.to_bytes(4, "little")
            tag_hex = tag_bytes.hex()
            self.register_binary_request(
                tag_hex,
                request_type=request_type,
                timeout_seconds=timeout_seconds,
                pubkey_prefix=pub_key[:6].hex(),
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Binary request send error: {e}")
            if "tag_hex" in locals():
                self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        if not success:
            self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        return SentResult(
            success=True,
            is_flood=contact.out_path_len <= 0,
            expected_ack=tag_int,
            timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
        )

    async def send_anon_req(
        self, pub_key: bytes, data: bytes, timeout_seconds: float = 15.0
    ) -> SentResult:
        """Send anonymous request (CMD_SEND_ANON_REQ), e.g. owner info.

        data = request payload (e.g. [0x07] for GET_OWNER_INFO). Response is
        delivered via on_binary_response (PUSH_CODE_BINARY_RESPONSE) like binary req.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return SentResult(success=False)
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return SentResult(success=False)
        request_type = PROTOCOL_CODE_ANON_REQ
        req_payload = data  # no random tag; timestamp provides uniqueness
        self.cleanup_expired_binary_requests()
        try:
            pkt, timestamp = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=PROTOCOL_CODE_ANON_REQ,
                data=req_payload,
            )
            # Use the timestamp as the tag — matches what the repeater echoes back
            tag_int = timestamp
            tag_bytes = tag_int.to_bytes(4, "little")
            tag_hex = tag_bytes.hex()
            self.register_binary_request(
                tag_hex,
                request_type=request_type,
                timeout_seconds=timeout_seconds,
                pubkey_prefix=pub_key[:6].hex(),
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Anon request send error: {e}")
            if "tag_hex" in locals():
                self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        if not success:
            self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        return SentResult(
            success=True,
            is_flood=contact.out_path_len <= 0,
            expected_ack=tag_int,
            timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
        )

    async def send_path_discovery(self, pub_key: bytes) -> bool:
        """Legacy: send path discovery without returning tag. Prefer send_path_discovery_req."""
        result = await self.send_path_discovery_req(pub_key)
        return result.success

    async def send_path_discovery_req(self, pub_key: bytes) -> SentResult:
        """Send path discovery (flood telemetry request with tag).

        Returns SentResult for RESP_CODE_SENT. When path return arrives with
        matching tag, path_discovery_response is fired (PUSH 0x8D).
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return SentResult(success=False)
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return SentResult(success=False)
        tag_int = random.randint(0, 0xFFFFFFFF)
        tag_bytes = tag_int.to_bytes(4, "little")
        inv_perm = 0xFF & ~TELEM_PERM_BASE
        req_payload = tag_bytes + bytes([REQ_TYPE_GET_TELEMETRY_DATA, inv_perm, 0, 0, 0])
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
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self._pending_discovery_tags.add(tag_int)
            return SentResult(
                success=success,
                is_flood=True,
                expected_ack=tag_int,
                timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
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

    async def send_text_message(
        self,
        pub_key: bytes,
        text: str,
        txt_type: int = TXT_TYPE_PLAIN,
        attempt: int = 1,
        wait_for_ack: bool = True,
    ) -> SentResult:
        """Send a direct text message to a contact.

        When wait_for_ack is True (default), blocks until ACK or timeout.
        When wait_for_ack is False, returns as soon as the packet is handed off;
        ACK (if any) is still tracked and will trigger send_confirmed later.
        """
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
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            self._track_pending_ack(ack_crc)
            if wait_for_ack:
                success = await self._send_packet(pkt, wait_for_ack=True)
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
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=is_flood)
            else:
                self.stats.record_tx_error()
            return SentResult(
                success=success,
                is_flood=is_flood,
                expected_ack=ack_crc,
                timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
            )
        except Exception as e:
            logger.error(f"Error sending text message: {e}")
            self.stats.record_tx_error()
            return SentResult(success=False)

    async def send_channel_message(self, channel_idx: int, text: str) -> bool:
        """Send a message to a channel."""
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
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
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
        """Send raw data to a contact via a protocol request."""
        contact = self.contacts.get_by_key(dest_key)
        if not contact:
            return SentResult(success=False)
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return SentResult(success=False)
        try:
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=PROTOCOL_CODE_RAW_DATA,
                data=data,
            )
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            return SentResult(success=success)
        except Exception as e:
            logger.error(f"Error sending raw data: {e}")
            return SentResult(success=False)

    async def send_raw_data_direct(
        self, path: bytes, payload: bytes, *, path_len_encoded: int = None
    ) -> SentResult:
        """Send a raw custom packet (PAYLOAD_TYPE_RAW_CUSTOM) on the given direct path.

        No encryption or contact lookup; path and payload are supplied by the caller.
        Matches firmware CMD_SEND_RAW_DATA behaviour.

        Args:
            path_len_encoded: Encoded path_len byte. If None, assumes 1-byte hashes.
        """
        if len(payload) < 4:
            return SentResult(success=False)
        if len(path) > MAX_PATH_SIZE:
            return SentResult(success=False)
        if len(payload) > MAX_PACKET_PAYLOAD:
            return SentResult(success=False)
        try:
            pkt = PacketBuilder.create_raw_data(payload)
            pkt.set_path(path, path_len_encoded)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=False)
            else:
                self.stats.record_tx_error()
            return SentResult(success=success)
        except Exception as e:
            logger.error(f"Error sending raw data direct: {e}")
            return SentResult(success=False)

    async def send_trace_path(
        self,
        pub_key: bytes,
        tag: int,
        auth_code: int,
        flags: int = 0,
    ) -> bool:
        """Send a trace path request to a contact."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        path = list(contact.out_path) if contact.out_path else []
        if not path:
            path = [contact.public_key[0]]
        try:
            pkt = PacketBuilder.create_trace(tag, auth_code, flags, path=path)
            self._apply_path_hash_mode(pkt)
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending trace: {e}")
            return False

    async def send_control_data(self, data: Any = None) -> bool:
        """Send a CONTROL packet (e.g. discovery request).

        If *data* is provided it must be 1-254 bytes with the first byte having
        the 0x80 bit set (e.g. ``DISCOVER_REQ``).  Returns ``False`` for
        invalid payloads.

        When called with no *data* (or ``None``), a default discovery request
        is sent for backward compatibility.
        """
        try:
            if data and len(data) <= 254 and (data[0] & 0x80) != 0:
                pkt = Packet()
                pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_CONTROL, route_type="direct")
                pkt.path_len = 0
                pkt.path = bytearray()
                pkt.payload = bytearray(data)
                pkt.payload_len = len(data)
                self._apply_path_hash_mode(pkt)
                return await self._send_packet(pkt, wait_for_ack=False)
            elif data is not None:
                # data was provided but invalid
                return False
            # No data: send default discovery request
            tag = random.randint(0, 0xFFFFFFFF)
            pkt = PacketBuilder.create_discovery_request(tag, filter_mask=0x04)
            self._apply_path_hash_mode(pkt)
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending control data: {e}")
            return False

    async def send_login(self, pub_key: bytes, password: str) -> dict:
        """Send a login request to a repeater and wait for the response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        login_handler = self._get_login_response_handler()
        if not login_handler:
            return {"success": False, "reason": "Login handler not available"}
        dest_hash = bytes.fromhex(proxy.public_key)[0]
        login_handler.store_login_password(dest_hash, password)
        login_result: dict = {"success": False, "data": {}}
        login_event = asyncio.Event()

        def _login_cb(success: bool, data: dict) -> None:
            login_result["success"] = success
            login_result["data"] = data
            login_event.set()

        login_handler.set_login_callback(_login_cb)
        try:
            pkt = PacketBuilder.create_login_packet(
                contact=proxy, local_identity=self._identity, password=password
            )
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=False)
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
                "firmware_ver_level": data.get("firmware_ver_level"),
                "reason": "Login successful" if login_result["success"] else "Login failed",
            }
        except Exception as e:
            logger.error(f"Login error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            login_handler.set_login_callback(None)
            login_handler.clear_login_password(dest_hash)

    async def send_logout(self, pub_key: bytes) -> bool:
        """Send a logout / disconnect to a repeater contact."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        try:
            pkt, _ = PacketBuilder.create_logout_packet(
                contact=contact, local_identity=self._identity
            )
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=False)
            return True
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False

    async def _wait_for_path_propagation(self, proxy: Any, request_type: str) -> None:
        """Wait for reciprocal PATH to propagate through the mesh for multi-hop contacts.

        After login, pyMC sends a reciprocal PATH so the remote repeater learns
        the return route.  Each mesh hop adds ~500ms (airtime + processing).
        Without this delay, the first REQ may arrive before the reciprocal PATH,
        causing the remote to fall back to sendFlood() — which gets dropped by
        intermediate repeaters due to transport-code region filtering.
        """
        out_path_len = getattr(proxy, "out_path_len", -1)
        if out_path_len > 0:
            hop_count = PathUtils.get_path_hash_count(out_path_len)
            propagation_delay = hop_count * 0.5  # e.g. 3 hops → 1.5s
            logger.debug(
                f"Multi-hop {request_type}: waiting {propagation_delay:.1f}s for "
                f"reciprocal PATH propagation ({hop_count} hops)"
            )
            await asyncio.sleep(propagation_delay)

    async def send_status_request(self, pub_key: bytes, timeout: float = 15.0) -> dict:
        """Send a protocol request for repeater status/stats."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        proto_handler = self._get_protocol_response_handler()
        if not proto_handler:
            return {"success": False, "reason": "Protocol handler not available"}
        contact_hash = bytes.fromhex(proxy.public_key)[0]
        waiter = ResponseWaiter()
        proto_handler.set_response_callback(contact_hash, waiter.callback)
        try:
            await self._wait_for_path_propagation(proxy, "stats request")
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=REQ_TYPE_GET_STATUS,
                data=b"",
            )
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=False)
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
            proto_handler.clear_response_callback(contact_hash)

    async def send_telemetry_request(
        self,
        pub_key: bytes,
        want_base: bool = True,
        want_location: bool = True,
        want_environment: bool = True,
        timeout: float = 10.0,
    ) -> dict:
        """Send a telemetry request to a contact and wait for the response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        proto_handler = self._get_protocol_response_handler()
        if not proto_handler:
            return {"success": False, "reason": "Protocol handler not available"}
        contact_hash = bytes.fromhex(proxy.public_key)[0]
        waiter = ResponseWaiter()
        proto_handler.set_response_callback(contact_hash, waiter.callback)
        try:
            await self._wait_for_path_propagation(proxy, "telemetry request")
            inv = PacketBuilder._compute_inverse_perm_mask(
                want_base, want_location, want_environment
            )
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=REQ_TYPE_GET_TELEMETRY_DATA,
                data=bytes([inv]),
            )
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=False)
            result = await waiter.wait(timeout)
            telemetry_data = dict(result.get("parsed", {}))
            raw_bytes = telemetry_data.get("raw_bytes", b"")
            if raw_bytes and len(pub_key) >= 6:
                # Companion-style frame: 0x8B + reserved + 6-byte pubkey prefix + LPP
                telemetry_data["frame_bytes"] = (
                    bytes([PUSH_CODE_TELEMETRY_RESPONSE, 0]) + pub_key[:6] + raw_bytes
                )
            return {
                "success": result.get("success", False),
                "contact": contact.name,
                "telemetry_data": telemetry_data,
                "response_text": result.get("text"),
                "reason": ("Telemetry received" if result.get("success") else "Telemetry failed"),
            }
        except Exception as e:
            logger.error(f"Telemetry error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            proto_handler.clear_response_callback(contact_hash)

    async def send_binary_request(self, pub_key: bytes, data: bytes) -> dict:
        """Legacy: send binary request and wait.

        Prefer ``send_binary_req`` + ``on_binary_response``.
        """
        return await self._send_protocol_request(pub_key, PROTOCOL_CODE_BINARY_REQ, data)

    async def send_anon_request(self, pub_key: bytes, data: bytes) -> dict:
        """Send an anonymous request to a contact and wait for the response."""
        return await self._send_protocol_request(pub_key, PROTOCOL_CODE_ANON_REQ, data)

    async def _send_protocol_request(self, pub_key: bytes, protocol_code: int, data: bytes) -> dict:
        """Build and send a protocol request, waiting for the response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        proto_handler = self._get_protocol_response_handler()
        if not proto_handler:
            return {"success": False, "reason": "Protocol handler not available"}
        contact_hash = bytes.fromhex(proxy.public_key)[0]
        waiter = ResponseWaiter()
        proto_handler.set_response_callback(contact_hash, waiter.callback)
        try:
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=protocol_code,
                data=data,
            )
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=False)
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
            proto_handler.clear_response_callback(contact_hash)

    async def send_repeater_command(
        self, pub_key: bytes, command: str, parameters: Optional[str] = None
    ) -> dict:
        """Send a text-based command to a repeater and wait for the response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        proxy = self.contacts.get_by_name(contact.name)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        text_handler = self._get_text_handler()
        if not text_handler:
            return {"success": False, "reason": "Text handler not available"}
        full_command = command
        if parameters:
            full_command += f" {parameters}"
        response_data: dict = {"text": None, "success": False}
        response_event = asyncio.Event()

        def _response_cb(message_text: str, sender_contact: Any) -> None:
            response_data["text"] = message_text
            response_data["success"] = True
            response_event.set()

        text_handler.set_command_response_callback(_response_cb)
        try:
            msg_type = "flood" if proxy.out_path_len < 0 else "direct"
            pkt, ack_crc = PacketBuilder.create_text_message(
                contact=proxy,
                local_identity=self._identity,
                message=full_command,
                attempt=1,
                message_type=msg_type,
            )
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=True)
            try:
                await asyncio.wait_for(response_event.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                pass
            return {
                "success": response_data["success"],
                "repeater": contact.name,
                "command": command,
                "response": response_data["text"],
                "reason": ("Command successful" if response_data["success"] else "No response"),
            }
        except Exception as e:
            logger.error(f"Repeater command error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            text_handler.set_command_response_callback(None)

    def _track_pending_ack(self, ack_crc: int) -> None:
        """Track pending ACK CRC for send_confirmed (capped)."""
        if len(self._pending_ack_crcs) < MAX_PENDING_ACK_CRCS:
            self._pending_ack_crcs.add(ack_crc)

    async def _try_confirm_send(self, crc: int) -> bool:
        """If CRC is pending, discard it and fire send_confirmed. Returns True if fired."""
        if crc not in self._pending_ack_crcs:
            return False
        self._pending_ack_crcs.discard(crc)
        await self._fire_callbacks("send_confirmed", crc)
        return True

    def sync_next_message(self) -> Optional[QueuedMessage]:
        """Pop and return the next queued message, or None."""
        return self.message_queue.pop()

    # -------------------------------------------------------------------------
    # Dedup Helper
    # -------------------------------------------------------------------------

    def _check_dedup(self, cache: OrderedDict, key: str, ttl: float, max_size: int) -> bool:
        """Return True if *key* is a duplicate. Evicts expired entries."""
        now = time.time()
        if key in cache:
            return True
        expired = [k for k, ts in cache.items() if now - ts > ttl]
        for k in expired:
            del cache[k]
        cache[key] = now
        if len(cache) > max_size:
            cache.popitem(last=False)
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
                # Advert pipeline (single path): all adverts applied here; one event
                # -> one store update and at most one advert_received (Bridge and Radio).
                now = int(time.time())
                contact = Contact.from_dict(data, now=now)
                raw_blob = data.get("raw_advert_packet")
                if isinstance(raw_blob, (bytes, bytearray)) and len(raw_blob) > 0:
                    contact.last_advert_packet = bytes(raw_blob)
                if len(contact.public_key) >= 7 and contact.name:
                    inbound_path = data.get("inbound_path")
                    path_len_encoded = data.get("path_len_encoded")
                    applied = await self._apply_advert_to_stores(
                        contact, inbound_path, path_len_encoded=path_len_encoded
                    )
                    if applied is not None:
                        await self._fire_callbacks("advert_received", applied)
                await self._fire_callbacks("node_discovered", data)
            elif event_type == MeshEvents.TELEMETRY_UPDATED:
                await self._fire_callbacks("telemetry_response", data)
        except Exception as e:
            logger.error(f"Error handling mesh event {event_type}: {e}")

    async def _handle_new_message(self, data: dict) -> None:
        # Deduplicate by packet hash so reconnects don't queue the same packet multiple times.
        pkt_hash = data.get("packet_hash")
        if pkt_hash and self._check_dedup(
            self._seen_txt, pkt_hash, self._seen_txt_ttl, self._seen_txt_max
        ):
            return

        sender_key_hex = data.get("contact_pubkey", "")
        sender_key = bytes.fromhex(sender_key_hex) if sender_key_hex else b""
        # Handler publishes "message_text"; accept "text" for compatibility
        message_text = (data.get("message_text") or data.get("text") or "").rstrip("\x00")
        # Extract SNR/RSSI from network info if available (same as channel path)
        network_info = data.get("network_info", {})
        snr = network_info.get("snr")
        rssi = network_info.get("rssi")
        msg = QueuedMessage(
            sender_key=sender_key,
            txt_type=data.get("txt_type", data.get("flags", 0)),
            timestamp=data.get("timestamp", int(time.time())),
            text=message_text,
            is_channel=False,
            path_len=0,
            snr=snr if snr is not None else 0.0,
            rssi=rssi if rssi is not None else 0,
        )
        self.message_queue.push(msg)
        await self._fire_callbacks(
            "message_received",
            sender_key,
            message_text,
            msg.timestamp,
            msg.txt_type,
            pkt_hash,
            snr if snr is not None else 0.0,
            rssi if rssi is not None else 0,
        )

    async def _handle_new_channel_message(self, data: dict) -> None:
        # Do not push our own (outgoing) channel messages to the client as incoming.
        if data.get("is_outgoing"):
            return

        # Deduplicate by packet hash so we queue one frame per logical message, matching
        # firmware: Mesh.cpp only calls onChannelMessageRecv when !_tables->hasSeen(pkt).
        pkt_hash = data.get("packet_hash")
        if pkt_hash and self._check_dedup(
            self._seen_grp_txt, pkt_hash, self._seen_grp_txt_ttl, self._seen_grp_txt_max
        ):
            return

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
        # Extract SNR/RSSI from network info if available
        network_info = data.get("network_info", {})
        snr = network_info.get("snr")
        rssi = network_info.get("rssi")

        msg = QueuedMessage(
            sender_key=b"",
            txt_type=0,
            timestamp=data.get("timestamp", int(time.time())),
            text=display_text,
            is_channel=True,
            channel_idx=channel_idx,
            path_len=path_len,
            snr=snr if snr is not None else 0.0,
            rssi=rssi if rssi is not None else 0,
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
            pkt_hash,
            snr,
            rssi,
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

    def _schedule_fire_callbacks(self, event_name: str, *args: Any) -> None:
        """Schedule _fire_callbacks from sync code (e.g. set_channel). No-op if no running loop."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._fire_callbacks(event_name, *args))
        except RuntimeError:
            pass

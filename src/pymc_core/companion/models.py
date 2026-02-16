"""Data models for companion radio state objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Contact:
    """Represents a mesh network contact."""

    public_key: bytes  # 32 bytes (Ed25519)
    name: str = ""  # up to 32 chars
    adv_type: int = 0  # ADV_TYPE_CHAT/REPEATER/ROOM/SENSOR
    flags: int = 0  # bitfield
    out_path_len: int = -1  # -1 = unknown, 0 = direct, >0 = multi-hop
    out_path: bytes = b""  # routing path bytes
    last_advert_timestamp: int = 0  # remote timestamp
    lastmod: int = 0  # local modification timestamp
    gps_lat: float = 0.0  # degrees
    gps_lon: float = 0.0  # degrees
    sync_since: int = 0  # for filtered iteration


@dataclass
class Channel:
    """Represents a group communication channel."""

    name: str  # up to 32 chars
    secret: bytes  # 16-byte PSK


@dataclass
class NodePrefs:
    """Node configuration preferences (equivalent to firmware NodePrefs)."""

    node_name: str = "pyMC"
    adv_type: int = 1  # ADV_TYPE_CHAT
    tx_power_dbm: int = 20
    frequency_hz: int = 915000000
    bandwidth_hz: int = 250000
    spreading_factor: int = 10
    coding_rate: int = 5
    latitude: float = 0.0
    longitude: float = 0.0
    advert_loc_policy: int = 0  # ADVERT_LOC_NONE
    multi_acks: int = 0
    telemetry_mode_base: int = 0  # TELEM_MODE_DENY
    telemetry_mode_location: int = 0
    telemetry_mode_environment: int = 0
    manual_add_contacts: int = 0
    autoadd_config: int = 0
    rx_delay_base: float = 0.0
    airtime_factor: float = 0.0


@dataclass
class SentResult:
    """Result of a message send operation."""

    success: bool
    is_flood: bool = False
    expected_ack: Optional[int] = None
    timeout_ms: Optional[int] = None


@dataclass
class PacketStats:
    """Packet transmission/reception statistics."""

    flood_tx: int = 0
    flood_rx: int = 0
    direct_tx: int = 0
    direct_rx: int = 0
    tx_errors: int = 0


@dataclass
class AdvertPath:
    """Recently heard advertiser path information."""

    public_key_prefix: bytes  # 7 bytes
    name: str = ""
    path_len: int = 0
    path: bytes = b""
    recv_timestamp: int = 0


@dataclass
class QueuedMessage:
    """A message stored in the offline queue."""

    sender_key: bytes  # 32 bytes
    txt_type: int = 0
    timestamp: int = 0
    text: str = ""
    is_channel: bool = False
    channel_idx: int = 0  # only meaningful if is_channel
    path_len: int = 0

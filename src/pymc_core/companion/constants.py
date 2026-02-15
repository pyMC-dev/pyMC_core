"""Companion radio constants for application-layer mesh networking features."""

from __future__ import annotations

from enum import IntEnum

# ---------------------------------------------------------------------------
# ADV Types (contact/node classification)
# ---------------------------------------------------------------------------
ADV_TYPE_CHAT = 1
ADV_TYPE_REPEATER = 2
ADV_TYPE_ROOM = 3
ADV_TYPE_SENSOR = 4

# ---------------------------------------------------------------------------
# Text Types
# ---------------------------------------------------------------------------
TXT_TYPE_PLAIN = 0
TXT_TYPE_CLI_DATA = 1
TXT_TYPE_SIGNED_PLAIN = 2

# ---------------------------------------------------------------------------
# Telemetry Modes
# ---------------------------------------------------------------------------
TELEM_MODE_DENY = 0
TELEM_MODE_ALLOW_FLAGS = 1
TELEM_MODE_ALLOW_ALL = 2

# ---------------------------------------------------------------------------
# Advert Location Policy
# ---------------------------------------------------------------------------
ADVERT_LOC_NONE = 0
ADVERT_LOC_SHARE = 1

# ---------------------------------------------------------------------------
# Auto-Add Config Bitmask
# ---------------------------------------------------------------------------
AUTOADD_OVERWRITE_OLDEST = 0x01
AUTOADD_CHAT = 0x02
AUTOADD_REPEATER = 0x04
AUTOADD_ROOM = 0x08
AUTOADD_SENSOR = 0x10

# ---------------------------------------------------------------------------
# Message Send Result
# ---------------------------------------------------------------------------
MSG_SEND_FAILED = 0
MSG_SEND_SENT_FLOOD = 1
MSG_SEND_SENT_DIRECT = 2

# ---------------------------------------------------------------------------
# Stats Types
# ---------------------------------------------------------------------------
STATS_TYPE_CORE = 0
STATS_TYPE_RADIO = 1
STATS_TYPE_PACKETS = 2

# ---------------------------------------------------------------------------
# Binary request types (CMD_SEND_BINARY_REQ / PUSH_CODE_BINARY_RESPONSE)
# ---------------------------------------------------------------------------
class BinaryReqType(IntEnum):
    """Binary request type codes (companion frame protocol)."""
    STATUS = 0x01
    KEEP_ALIVE = 0x02
    TELEMETRY = 0x03
    MMA = 0x04
    ACL = 0x05
    NEIGHBOURS = 0x06

# ---------------------------------------------------------------------------
# Protocol Codes (used in create_protocol_request / send_protocol_request)
# ---------------------------------------------------------------------------
PROTOCOL_CODE_RAW_DATA = 0x00
PROTOCOL_CODE_BINARY_REQ = 0x02
PROTOCOL_CODE_ANON_REQ = 0x07

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_RESPONSE_TIMEOUT_MS = 10000
DEFAULT_MAX_CONTACTS = 1000
DEFAULT_OFFLINE_QUEUE_SIZE = 512
DEFAULT_MAX_CHANNELS = 40
CONTACT_NAME_SIZE = 32
MAX_SIGN_DATA_SIZE = 8192  # 8KB signing buffer (matches firmware)

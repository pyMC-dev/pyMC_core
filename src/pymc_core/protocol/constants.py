# protocol_consts.py
"""Mesh protocol constants extracted from the C++ firmware."""

# ---------------------------------------------------------------------------
# Header bit‑field layout
# ---------------------------------------------------------------------------
PH_ROUTE_MASK = 0x03  # bits 0‑1
PH_TYPE_SHIFT = 2
PH_TYPE_MASK = 0x0F  # bits 2‑5 (4 bits)
PH_VER_SHIFT = 6
PH_VER_MASK = 0x03  # bits 6‑7 (2 bits)

# ---------------------------------------------------------------------------
# Route‑type values (2 bits)
# ---------------------------------------------------------------------------
ROUTE_TYPE_TRANSPORT_FLOOD = 0x00
ROUTE_TYPE_FLOOD = 0x01
ROUTE_TYPE_DIRECT = 0x02
ROUTE_TYPE_TRANSPORT_DIRECT = 0x03

# ---------------------------------------------------------------------------
# Payload‑type values (4 bits)
# ---------------------------------------------------------------------------
PAYLOAD_TYPE_REQ = 0x00
PAYLOAD_TYPE_RESPONSE = 0x01
PAYLOAD_TYPE_TXT_MSG = 0x02
PAYLOAD_TYPE_ACK = 0x03
PAYLOAD_TYPE_ADVERT = 0x04
PAYLOAD_TYPE_GRP_TXT = 0x05
PAYLOAD_TYPE_GRP_DATA = 0x06
PAYLOAD_TYPE_ANON_REQ = 0x07
PAYLOAD_TYPE_PATH = 0x08
PAYLOAD_TYPE_TRACE = 0x09
PAYLOAD_TYPE_MULTIPART = 0x0A
PAYLOAD_TYPE_CONTROL = 0x0B
PAYLOAD_TYPE_RAW_CUSTOM = 0x0F

# ---------------------------------------------------------------------------
# Payload version values (2 bits)
# ---------------------------------------------------------------------------
PAYLOAD_VER_1 = 0x00  # Currently supported
PAYLOAD_VER_2 = 0x01  # Reserved for future use
MAX_SUPPORTED_PAYLOAD_VERSION = PAYLOAD_VER_2  # Accept versions 0-1

# ---------------------------------------------------------------------------
# Misc sizes
# ---------------------------------------------------------------------------
MAX_ADVERT_DATA_SIZE = 96
PUB_KEY_SIZE = 32
SIGNATURE_SIZE = 64
PATH_HASH_SIZE = 1
CIPHER_MAC_SIZE = 32  # SHA‑256 HMAC
CIPHER_BLOCK_SIZE = 16
MAX_PACKET_PAYLOAD = 256  # firmware's default

MAX_PATH_SIZE = 64
MAX_PACKET_PAYLOAD = 256
MAX_HASH_SIZE = 32  # SHA-256 truncated

NAME_MAX_LEN = 16  # Max length of a contact name

TIMESTAMP_SIZE = 4  # 4 bytes for a timestamp (32-bit unsigned int)
# ---------------------------------------------------------------------------

# Node Advert Flags (bitfield values)
ADVERT_FLAG_IS_CHAT_NODE = 0x01
ADVERT_FLAG_IS_REPEATER = 0x02
ADVERT_FLAG_IS_ROOM_SERVER = 0x03
ADVERT_FLAG_IS_SENSOR = 0x04
ADVERT_FLAG_HAS_LOCATION = 0x10
ADVERT_FLAG_HAS_FEATURE1 = 0x20
ADVERT_FLAG_HAS_FEATURE2 = 0x40
ADVERT_FLAG_HAS_NAME = 0x80


def describe_advert_flags(flags: int) -> str:
    labels = []

    # Extract node type from bits 0-3
    node_type = flags & 0x0F
    if node_type == ADVERT_FLAG_IS_CHAT_NODE:
        labels.append("is chat node")
    elif node_type == ADVERT_FLAG_IS_REPEATER:
        labels.append("is repeater")
    elif node_type == ADVERT_FLAG_IS_ROOM_SERVER:
        labels.append("is room server")
    elif node_type == 0x04:
        labels.append("is sensor")

    # Check feature flags (bits 4-7)
    if flags & ADVERT_FLAG_HAS_LOCATION:
        labels.append("has location")
    if flags & ADVERT_FLAG_HAS_FEATURE1:
        labels.append("has feature 1")
    if flags & ADVERT_FLAG_HAS_FEATURE2:
        labels.append("has feature 2")
    if flags & ADVERT_FLAG_HAS_NAME:
        labels.append("has name")

    return ", ".join(labels) or "none"


# Contact Types (derived from advert flags)
CONTACT_TYPE_UNKNOWN = 0
CONTACT_TYPE_CHAT_NODE = 1
CONTACT_TYPE_REPEATER = 2
CONTACT_TYPE_ROOM_SERVER = 3  # Equivalent to C++ ADV_TYPE_ROOM
CONTACT_TYPE_HYBRID = 4


# Protocol Request Types
REQ_TYPE_GET_STATUS = 0x01          # Get repeater stats (RepeaterStats struct)
REQ_TYPE_GET_TELEMETRY_DATA = 0x03  # Get telemetry data (CayenneLPP)
TELEM_PERM_BASE = 0x01
TELEM_PERM_LOCATION = 0x02
TELEM_PERM_ENVIRONMENT = 0x04

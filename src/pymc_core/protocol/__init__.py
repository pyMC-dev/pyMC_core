"""
Mesh protocol layer - low-level packet structure and crypto
"""

# Import commonly used constants explicitly
from .constants import (
    ADVERT_FLAG_HAS_FEATURE1,
    ADVERT_FLAG_HAS_FEATURE2,
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
    CIPHER_BLOCK_SIZE,
    CIPHER_MAC_SIZE,
    CONTACT_TYPE_CHAT_NODE,
    CONTACT_TYPE_HYBRID,
    CONTACT_TYPE_REPEATER,
    CONTACT_TYPE_ROOM_SERVER,
    CONTACT_TYPE_UNKNOWN,
    MAX_ADVERT_DATA_SIZE,
    MAX_HASH_SIZE,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    NAME_MAX_LEN,
    PATH_HASH_SIZE,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_GRP_DATA,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RAW_CUSTOM,
    PAYLOAD_TYPE_REQ,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    PAYLOAD_VER_1,
    PH_ROUTE_MASK,
    PH_TYPE_MASK,
    PH_TYPE_SHIFT,
    PH_VER_MASK,
    PH_VER_SHIFT,
    PUB_KEY_SIZE,
    REQ_TYPE_GET_STATUS,
    REQ_TYPE_GET_TELEMETRY_DATA,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_DIRECT,
    ROUTE_TYPE_TRANSPORT_FLOOD,
    SIGNATURE_SIZE,
    TELEM_PERM_BASE,
    TELEM_PERM_ENVIRONMENT,
    TELEM_PERM_LOCATION,
    TIMESTAMP_SIZE,
    describe_advert_flags,
)
from .crypto import CryptoUtils

# Import identity classes after other imports to avoid circular dependencies
from .identity import Identity, LocalIdentity
from .modem_identity import ModemIdentity
from .packet import Packet

# PacketBuilder imports from other protocol modules so import it last
from .packet_builder import PacketBuilder
from .packet_filter import PacketFilter
from .packet_utils import (
    PacketDataUtils,
    PacketHashingUtils,
    PacketHeaderUtils,
    PacketTimingUtils,
    PacketValidationUtils,
    RouteTypeUtils,
)
from .transport_keys import calc_transport_code, get_auto_key_for
from .utils import decode_appdata, parse_advert_payload

__all__ = [
    # Core classes
    "Packet",
    "PacketBuilder",
    "PacketFilter",
    "CryptoUtils",
    "LocalIdentity",
    "ModemIdentity",
    "Identity",
    # Utility functions
    "parse_advert_payload",
    "decode_appdata",
    "describe_advert_flags",
    "get_auto_key_for",
    "calc_transport_code",
    # Utility classes
    "PacketValidationUtils",
    "PacketDataUtils",
    "PacketHeaderUtils",
    "PacketHashingUtils",
    "RouteTypeUtils",
    "PacketTimingUtils",
    # Header constants
    "PH_ROUTE_MASK",
    "PH_TYPE_SHIFT",
    "PH_TYPE_MASK",
    "PH_VER_SHIFT",
    "PH_VER_MASK",
    # Route types
    "ROUTE_TYPE_TRANSPORT_FLOOD",
    "ROUTE_TYPE_FLOOD",
    "ROUTE_TYPE_DIRECT",
    "ROUTE_TYPE_TRANSPORT_DIRECT",
    # Payload types
    "PAYLOAD_TYPE_REQ",
    "PAYLOAD_TYPE_RESPONSE",
    "PAYLOAD_TYPE_TXT_MSG",
    "PAYLOAD_TYPE_ACK",
    "PAYLOAD_TYPE_ADVERT",
    "PAYLOAD_TYPE_GRP_TXT",
    "PAYLOAD_TYPE_GRP_DATA",
    "PAYLOAD_TYPE_ANON_REQ",
    "PAYLOAD_TYPE_PATH",
    "PAYLOAD_TYPE_TRACE",
    "PAYLOAD_TYPE_RAW_CUSTOM",
    # Payload versions
    "PAYLOAD_VER_1",
    # Sizes
    "MAX_ADVERT_DATA_SIZE",
    "PUB_KEY_SIZE",
    "SIGNATURE_SIZE",
    "PATH_HASH_SIZE",
    "CIPHER_MAC_SIZE",
    "CIPHER_BLOCK_SIZE",
    "MAX_PACKET_PAYLOAD",
    "MAX_PATH_SIZE",
    "MAX_HASH_SIZE",
    "NAME_MAX_LEN",
    "TIMESTAMP_SIZE",
    # Advert flags
    "ADVERT_FLAG_IS_CHAT_NODE",
    "ADVERT_FLAG_IS_REPEATER",
    "ADVERT_FLAG_IS_ROOM_SERVER",
    "ADVERT_FLAG_HAS_LOCATION",
    "ADVERT_FLAG_HAS_FEATURE1",
    "ADVERT_FLAG_HAS_FEATURE2",
    "ADVERT_FLAG_HAS_NAME",
    # Contact types
    "CONTACT_TYPE_UNKNOWN",
    "CONTACT_TYPE_CHAT_NODE",
    "CONTACT_TYPE_REPEATER",
    "CONTACT_TYPE_ROOM_SERVER",
    "CONTACT_TYPE_HYBRID",
    # Protocol request types
    "REQ_TYPE_GET_STATUS",
    "REQ_TYPE_GET_TELEMETRY_DATA",
    "TELEM_PERM_BASE",
    "TELEM_PERM_LOCATION",
    "TELEM_PERM_ENVIRONMENT",
]

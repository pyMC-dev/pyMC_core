"""
PyMC_Core - A Python MeshCore library with SPI LoRa radio support
Clean, simple API for building mesh network applications.
"""

__version__ = "1.0.8"

# Core mesh functionality
from .node.node import MeshNode
from .protocol.crypto import CryptoUtils
from .protocol.identity import LocalIdentity
from .protocol.packet import Packet

__all__ = [
    # Core API
    "MeshNode",
    "LocalIdentity",
    "Packet",
    "CryptoUtils",
    # Version
    "__version__",
]

# Conditional import for CompanionRadio
try:
    from .companion.companion_radio import CompanionRadio

    _COMPANION_AVAILABLE = True
except ImportError:
    _COMPANION_AVAILABLE = False
    CompanionRadio = None

if _COMPANION_AVAILABLE:
    __all__.append("CompanionRadio")


# End of mesh package exports

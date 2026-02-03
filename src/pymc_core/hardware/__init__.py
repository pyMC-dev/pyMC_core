"""
Hardware abstraction layer for PyMC_Core
"""

from .base import LoRaRadio

# Conditional import for WsRadio (requires websockets)
try:
    from .wsradio import WsRadio

    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False
    WsRadio = None

# Conditional import for SX1262Radio (requires spidev)
try:
    from .sx1262_wrapper import SX1262Radio

    _SX1262_AVAILABLE = True
except ImportError:
    _SX1262_AVAILABLE = False
    SX1262Radio = None

# Conditional import for KissSerialWrapper (requires pyserial)
try:
    from .kiss_serial_wrapper import KissSerialWrapper

    _KISS_SERIAL_AVAILABLE = True
except ImportError:
    _KISS_SERIAL_AVAILABLE = False
    KissSerialWrapper = None

# Conditional import for KissModemWrapper (requires pyserial)
try:
    from .kiss_modem_wrapper import KissModemWrapper

    _KISS_MODEM_AVAILABLE = True
except ImportError:
    _KISS_MODEM_AVAILABLE = False
    KissModemWrapper = None

__all__ = ["LoRaRadio"]

# Add WsRadio to exports if available
if _WS_AVAILABLE:
    __all__.append("WsRadio")

# Add SX1262Radio to exports if available
if _SX1262_AVAILABLE:
    __all__.append("SX1262Radio")

# Add KissSerialWrapper to exports if available
if _KISS_SERIAL_AVAILABLE:
    __all__.append("KissSerialWrapper")

# Add KissModemWrapper to exports if available
if _KISS_MODEM_AVAILABLE:
    __all__.append("KissModemWrapper")

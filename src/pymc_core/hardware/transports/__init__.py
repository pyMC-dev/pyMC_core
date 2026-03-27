"""
SPI Transport Layer
Abstraction for different SPI backends (spidev, CH341, etc.)
"""

from .ch341_spi_transport import CH341SPITransport
from .spi_transport import SPITransport, SPITransportError
from .spidev_transport import SPIDevTransport

__all__ = [
    "SPITransport",
    "SPITransportError",
    "SPIDevTransport",
    "CH341SPITransport",
]

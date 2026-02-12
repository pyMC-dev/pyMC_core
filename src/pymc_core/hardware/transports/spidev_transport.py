"""
SPIdev Transport Implementation
Linux spidev-based SPI transport for Raspberry Pi and compatible boards
"""

import logging
from typing import List

try:
    import spidev
except ImportError:
    spidev = None

from .spi_transport import SPITransport, SPITransportError

logger = logging.getLogger(__name__)


class SPIDevTransport(SPITransport):
    """Linux spidev implementation of SPI transport"""

    def __init__(self):
        """Initialize spidev transport"""
        # Initialize state first (for __del__ safety)
        self._is_open = False
        self._spi = None
        self._bus = -1
        self._cs = -1
        self._speed = 2000000

        if spidev is None:
            raise SPITransportError("spidev module not available. Install: pip install spidev")

        self._spi = spidev.SpiDev()

    def open(self, bus: int, cs: int, speed: int = 2000000) -> bool:
        """
        Open spidev connection

        Args:
            bus: SPI bus number (e.g., 0 for /dev/spidev0.X)
            cs: Chip select number (e.g., 0 for /dev/spidev0.0)
            speed: SPI clock speed in Hz (default: 2MHz)

        Returns:
            True if successful, False otherwise
        """
        try:
            if self._is_open:
                logger.warning("SPI already open, closing first")
                self.close()

            self._spi.open(bus, cs)
            self._bus = bus
            self._cs = cs
            self._speed = speed

            # Set default SPI parameters
            self._spi.max_speed_hz = speed
            self._spi.mode = 0  # CPOL=0, CPHA=0
            self._spi.lsbfirst = False  # MSB first

            self._is_open = True
            logger.info(f"SPIdev opened: /dev/spidev{bus}.{cs} @ {speed}Hz")
            return True

        except Exception as e:
            logger.error(f"Failed to open spidev: {e}")
            self._is_open = False
            return False

    def close(self) -> None:
        """Close spidev connection"""
        if self._is_open:
            try:
                self._spi.close()
                logger.debug(f"SPIdev closed: /dev/spidev{self._bus}.{self._cs}")
            except Exception as e:
                logger.error(f"Error closing spidev: {e}")
            finally:
                self._is_open = False

    def transfer(self, data: List[int]) -> List[int]:
        """
        Perform full-duplex SPI transfer using xfer2

        Args:
            data: List of bytes to send

        Returns:
            List of bytes received
        """
        if not self._is_open:
            raise SPITransportError("SPI not open")

        try:
            # xfer2 keeps CS asserted between bytes (full-duplex transfer)
            result = self._spi.xfer2(data)
            return result
        except Exception as e:
            raise SPITransportError(f"SPI transfer failed: {e}")

    def set_mode(self, mode: int) -> None:
        """
        Set SPI mode

        Args:
            mode: SPI mode (0-3)
        """
        if not self._is_open:
            raise SPITransportError("SPI not open")

        if mode not in [0, 1, 2, 3]:
            raise ValueError(f"Invalid SPI mode: {mode}. Must be 0-3")

        self._spi.mode = mode
        logger.debug(f"SPI mode set to {mode}")

    def set_speed(self, speed: int) -> None:
        """
        Set SPI clock speed

        Args:
            speed: Clock speed in Hz
        """
        if not self._is_open:
            raise SPITransportError("SPI not open")

        self._spi.max_speed_hz = speed
        self._speed = speed
        logger.debug(f"SPI speed set to {speed}Hz")

    def set_bit_order(self, lsb_first: bool) -> None:
        """
        Set bit order

        Args:
            lsb_first: True for LSB first, False for MSB first
        """
        if not self._is_open:
            raise SPITransportError("SPI not open")

        self._spi.lsbfirst = lsb_first
        logger.debug(f"SPI bit order set to {'LSB' if lsb_first else 'MSB'} first")

    @property
    def is_open(self) -> bool:
        """Check if spidev is open"""
        return self._is_open

    def __del__(self):
        """Cleanup on deletion"""
        if self._is_open:
            self.close()

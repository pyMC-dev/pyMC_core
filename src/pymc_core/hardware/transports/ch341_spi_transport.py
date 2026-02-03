"""
CH341 SPI Transport Implementation
USB-based SPI transport using CH341 USB-to-SPI adapter
"""

import logging
from typing import List, Optional

from ..ch341.ch341_async import CH341Async, CH341Error
from .spi_transport import SPITransport, SPITransportError

logger = logging.getLogger(__name__)


class CH341SPITransport(SPITransport):
    """CH341 USB implementation of SPI transport"""

    def __init__(self, vid: int = 0x1A86, pid: int = 0x5512, auto_setup_gpio: bool = True):
        """
        Initialize CH341 SPI transport

        Args:
            vid: USB Vendor ID (default: 0x1a86 for CH341)
            pid: USB Product ID (default: 0x5512 for CH341)
            auto_setup_gpio: Automatically setup CH341GPIOManager and set it
                globally (default: True)
        """
        self._vid = vid
        self._pid = pid
        self._ch341: Optional[CH341Async] = None
        self._is_open = False
        self._speed = 2000000  # Not directly configurable on CH341
        self._mode = 0
        self._lsb_first = False
        self._gpio_manager = None

        # Automatically setup GPIO manager if requested
        if auto_setup_gpio:
            self._setup_gpio_manager()

    def _setup_gpio_manager(self):
        """Setup CH341 GPIO manager and set it as the global GPIO manager"""
        try:
            from ..ch341.ch341_gpio_manager import CH341GPIOManager
            from ..lora.LoRaRF.SX126x import set_gpio_manager

            self._gpio_manager = CH341GPIOManager(vid=self._vid, pid=self._pid)
            set_gpio_manager(self._gpio_manager)
            logger.info("CH341 GPIO manager automatically initialized")
        except Exception as e:
            logger.warning(f"Failed to setup CH341 GPIO manager: {e}")

    def open(self, bus: int, cs: int, speed: int = 2000000) -> bool:
        """
        Open CH341 USB connection

        Note: CH341 doesn't use traditional bus/cs numbering.
        These parameters are accepted for interface compatibility but ignored.
        CS is controlled via GPIO in the underlying driver.

        Args:
            bus: Ignored (for interface compatibility)
            cs: Ignored (for interface compatibility)
            speed: Ignored (CH341 has fixed SPI speed ~1-4MHz depending on model)

        Returns:
            True if successful, False otherwise
        """
        try:
            if self._is_open:
                logger.warning("CH341 already open, closing first")
                self.close()

            # Get singleton CH341 device instance
            self._ch341 = CH341Async.get_instance(vid=self._vid, pid=self._pid)

            self._is_open = True
            self._speed = speed  # Store for reference (actual speed is CH341-dependent)

            logger.info(f"CH341 SPI opened: VID={self._vid:04x}, PID={self._pid:04x}")
            return True

        except CH341Error as e:
            logger.error(f"Failed to open CH341: {e}")
            self._is_open = False
            return False

    def close(self) -> None:
        """Close CH341 USB connection"""
        if self._is_open:
            # Don't close the singleton device, just mark transport as closed
            logger.debug("CH341 SPI transport closed (device remains open)")
            self._is_open = False

    def transfer(self, data: List[int]) -> List[int]:
        """
        Perform SPI transfer via CH341

        Args:
            data: List of bytes to send

        Returns:
            List of bytes received
        """
        if not self._is_open or not self._ch341:
            raise SPITransportError("CH341 SPI not open")

        try:
            # Convert list to bytes
            data_bytes = bytes(data)

            # CH341 performs full-duplex SPI: write and read simultaneously
            # For full-duplex SPI, read_len=0 means we only want the echo back
            # (CH341 always returns writecnt + readcnt bytes)
            # Since we want N bytes out and N bytes in (standard full-duplex):
            # - writecnt = len(data)
            # - readcnt = 0 (no additional reads beyond the write echo)
            # This returns the data that was clocked in while we clocked out data_bytes
            result = self._ch341.spi_transfer_async(data_bytes, read_len=0)

            # Convert bytes to list
            return list(result)

        except Exception as e:
            raise SPITransportError(f"CH341 SPI transfer failed: {e}")

    def xfer2(self, data: List[int]) -> List[int]:
        """
        Alias for transfer() to match spidev interface

        Args:
            data: List of bytes to send

        Returns:
            List of bytes received
        """
        # logger.info(f"[CH341-SPI] xfer2() called with {len(data)} bytes: {data[:8]}...")
        # start = __import__("time").time()
        try:
            result = self.transfer(data)
            # elapsed = __import__("time").time() - start
            # logger.info(f"[CH341-SPI] xfer2() completed in {elapsed*1000:.1f}ms")
            return result
        except Exception:
            # elapsed = __import__("time").time() - start
            # logger.error(f"[CH341-SPI] xfer2() failed after {elapsed*1000:.1f}ms: {e}")
            raise

    def set_mode(self, mode: int) -> None:
        """
        Set SPI mode (limited support on CH341)

        Note: CH341 has limited SPI mode configuration.
        This is stored but may not affect the hardware.

        Args:
            mode: SPI mode (0-3)
        """
        if mode not in [0, 1, 2, 3]:
            raise ValueError(f"Invalid SPI mode: {mode}. Must be 0-3")

        self._mode = mode
        logger.warning(f"CH341 SPI mode set to {mode} (may not be fully supported by hardware)")

    def set_speed(self, speed: int) -> None:
        """
        Set SPI clock speed (not configurable on CH341)

        Note: CH341 has a fixed SPI clock speed (~1-4MHz depending on model).
        This value is stored for reference only.

        Args:
            speed: Clock speed in Hz (stored but not applied)
        """
        self._speed = speed
        logger.warning(f"CH341 SPI speed requested: {speed}Hz (CH341 uses fixed hardware speed)")

    def set_bit_order(self, lsb_first: bool) -> None:
        """
        Set bit order

        Note: CH341 driver handles bit reversal internally.
        This setting is stored but may not affect behavior.

        Args:
            lsb_first: True for LSB first, False for MSB first
        """
        self._lsb_first = lsb_first
        logger.debug(f"CH341 SPI bit order set to {'LSB' if lsb_first else 'MSB'} first")

    @property
    def is_open(self) -> bool:
        """Check if CH341 is open"""
        return self._is_open

    @property
    def gpio_manager(self):
        """Get the CH341 GPIO manager (if auto-setup was enabled)"""
        return self._gpio_manager

    def __del__(self):
        """Cleanup on deletion"""
        if self._is_open:
            self.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False

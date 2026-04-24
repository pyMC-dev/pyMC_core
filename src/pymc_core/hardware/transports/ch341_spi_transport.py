"""
CH341 SPI Transport Implementation
USB-based SPI transport using CH341 USB-to-SPI adapter
"""

import logging
import os
from typing import List, Optional

from ..ch341.ch341_async import CH341Async, CH341Error
from .spi_transport import SPITransport, SPITransportError

logger = logging.getLogger(__name__)


def _is_container() -> bool:
    """Detect if running inside an LXC/Docker/systemd-nspawn container."""
    # Check for /.dockerenv
    if os.path.exists("/.dockerenv"):
        return True
    # Check /run/host/container-manager (systemd-based)
    if os.path.exists("/run/host/container-manager"):
        return True
    # Check for container= environment variable (set by LXC/systemd-nspawn)
    if os.environ.get("container"):
        return True
    # Check /proc/1/environ for container= (LXC sets this on PID 1)
    try:
        with open("/proc/1/environ", "rb") as f:
            env = f.read()
            if b"container=" in env:
                return True
    except (OSError, PermissionError):
        pass
    return False


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
            logger.error(f"Failed to setup CH341 GPIO manager: {e}")
            # Detect specific error types for better guidance
            err_str = str(e)
            if "No backend available" in err_str:
                hint = (
                    f"CH341 GPIO manager initialization failed: {e}. "
                    f"The libusb library is not installed. "
                    f"Install it with: sudo apt-get install libusb-1.0-0"
                )
            else:
                hint = (
                    f"CH341 GPIO manager initialization failed: {e}. "
                    f"Check USB connection, permissions (udev rules), and that the "
                    f"CH341 device is accessible."
                )
            if _is_container():
                hint += (
                    "\n\n*** CONTAINER DETECTED ***\n"
                    "Udev rules inside a container have NO effect.\n"
                    "You must install the udev rule on the HOST machine:\n"
                    "  echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"1a86\", "
                    'ATTR{idProduct}=="5512", MODE="0666"\' '
                    "| sudo tee /etc/udev/rules.d/99-ch341.rules\n"
                    "  sudo udevadm control --reload-rules\n"
                    "  sudo udevadm trigger --subsystem-match=usb --action=change\n"
                    "Then unplug/replug the CH341 adapter."
                )
            raise RuntimeError(hint) from e

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

        try:
            result = self.transfer(data)
            return result
        except Exception:
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

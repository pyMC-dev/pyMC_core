"""
SPI Transport Interface
Base abstraction for SPI communication to support multiple backends (spidev, CH341, etc.)
"""

from abc import ABC, abstractmethod
from typing import List


class SPITransport(ABC):
    """Abstract base class for SPI transport implementations"""

    @abstractmethod
    def open(self, bus: int, cs: int, speed: int = 2000000) -> bool:
        """
        Open SPI connection

        Args:
            bus: SPI bus number
            cs: Chip select number
            speed: SPI clock speed in Hz

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Close SPI connection and cleanup resources"""
        pass

    @abstractmethod
    def transfer(self, data: List[int]) -> List[int]:
        """
        Perform full-duplex SPI transfer

        Args:
            data: List of bytes to send

        Returns:
            List of bytes received (same length as data)
        """
        pass

    @abstractmethod
    def set_mode(self, mode: int) -> None:
        """
        Set SPI mode (0-3)

        Args:
            mode: SPI mode (CPOL | CPHA)
                0: CPOL=0, CPHA=0
                1: CPOL=0, CPHA=1
                2: CPOL=1, CPHA=0
                3: CPOL=1, CPHA=1
        """
        pass

    @abstractmethod
    def set_speed(self, speed: int) -> None:
        """
        Set SPI clock speed

        Args:
            speed: Clock speed in Hz
        """
        pass

    @abstractmethod
    def set_bit_order(self, lsb_first: bool) -> None:
        """
        Set bit order

        Args:
            lsb_first: True for LSB first, False for MSB first
        """
        pass

    @property
    @abstractmethod
    def is_open(self) -> bool:
        """Check if transport is open and ready"""
        pass


class SPITransportError(Exception):
    """Base exception for SPI transport errors"""

    pass

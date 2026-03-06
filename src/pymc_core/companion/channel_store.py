"""In-memory channel storage compatible with MeshNode's channel_db interface."""

from __future__ import annotations

from typing import Optional

from .constants import DEFAULT_MAX_CHANNELS
from .models import Channel


class ChannelStore:
    """In-memory channel storage compatible with MeshNode's channel_db interface.

    Provides both the interface expected by GroupTextHandler (get_channels returning
    list of dicts) and companion radio operations (get/set/remove by index).
    """

    def __init__(self, max_channels: int = DEFAULT_MAX_CHANNELS):
        self._channels: list[Optional[Channel]] = [None] * max_channels
        self._max_channels = max_channels

    @property
    def max_channels(self) -> int:
        """Maximum number of channels (read-only). Used by companion protocol device info."""
        return self._max_channels

    # ------------------------------------------------------------------
    # Interface expected by GroupTextHandler / PacketBuilder
    # ------------------------------------------------------------------

    def get_channels(self) -> list[dict]:
        """Return channels as list of dicts with 'name' and 'secret' keys.

        The secret is returned as a hex string, which is what the existing
        GroupTextHandler and PacketBuilder expect.
        """
        result = []
        for ch in self._channels:
            if ch is not None:
                result.append(
                    {
                        "name": ch.name,
                        "secret": ch.secret.hex(),
                    }
                )
        return result

    # ------------------------------------------------------------------
    # Companion radio methods
    # ------------------------------------------------------------------

    def get(self, idx: int) -> Optional[Channel]:
        """Get a channel by index. Returns None if index invalid or empty."""
        if 0 <= idx < self._max_channels:
            return self._channels[idx]
        return None

    def set(self, idx: int, channel: Channel) -> bool:
        """Set a channel at the given index. Returns False if index out of range."""
        if 0 <= idx < self._max_channels:
            self._channels[idx] = channel
            return True
        return False

    def remove(self, idx: int) -> bool:
        """Remove a channel at the given index. Returns False if index invalid or already empty."""
        if 0 <= idx < self._max_channels and self._channels[idx] is not None:
            self._channels[idx] = None
            return True
        return False

    def find_by_name(self, name: str) -> Optional[int]:
        """Find a channel index by name. Returns None if not found."""
        for idx, ch in enumerate(self._channels):
            if ch is not None and ch.name == name:
                return idx
        return None

    def get_count(self) -> int:
        """Return the number of configured channels."""
        return sum(1 for ch in self._channels if ch is not None)

    def clear(self) -> None:
        """Remove all channels."""
        self._channels = [None] * self._max_channels

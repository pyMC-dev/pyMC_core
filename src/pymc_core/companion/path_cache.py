"""Path cache for tracking recently heard advertiser paths."""

from __future__ import annotations

from collections import deque
from typing import Optional

from .models import AdvertPath


class PathCache:
    """Tracks recently heard advertiser paths.

    Stores path information received from advertisements and path updates,
    matching the firmware's advert_paths table. Paths are keyed by public
    key prefix and updated on each new advertisement.
    """

    def __init__(self, max_entries: int = 16):
        self._paths: deque[AdvertPath] = deque()
        self._max = max_entries

    def update(self, advert_path: AdvertPath) -> None:
        """Add or update a path entry.

        If a path with the same public key prefix already exists, it is
        removed and the new entry is appended (LRU refresh). If the cache
        is full, the oldest entry is evicted.
        """
        # Remove existing entry with same prefix (LRU refresh to tail)
        for existing in self._paths:
            if existing.public_key_prefix == advert_path.public_key_prefix:
                self._paths.remove(existing)
                break

        # Evict oldest if full
        if len(self._paths) >= self._max:
            self._paths.popleft()
        self._paths.append(advert_path)

    def get_by_prefix(self, prefix: bytes) -> Optional[AdvertPath]:
        """Lookup a path by public key prefix.

        Args:
            prefix: Public key prefix to search for (matches the start
                    of stored public_key_prefix fields).
        """
        for path in self._paths:
            if path.public_key_prefix[: len(prefix)] == prefix:
                return path
        return None

    def get_all(self) -> list[AdvertPath]:
        """Return all cached paths."""
        return list(self._paths)

    def clear(self) -> None:
        """Remove all cached paths."""
        self._paths.clear()

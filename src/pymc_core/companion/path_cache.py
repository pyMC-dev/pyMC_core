"""Path cache for tracking recently heard advertiser paths."""

from typing import Optional

from .models import AdvertPath


class PathCache:
    """Tracks recently heard advertiser paths.

    Stores path information received from advertisements and path updates,
    matching the firmware's advert_paths table. Paths are keyed by public
    key prefix and updated on each new advertisement.
    """

    def __init__(self, max_entries: int = 16):
        self._paths: list[AdvertPath] = []
        self._max = max_entries

    def update(self, advert_path: AdvertPath):
        """Add or update a path entry.

        If a path with the same public key prefix already exists, it is
        replaced. If the cache is full, the oldest entry is evicted.
        """
        # Check for existing entry with same prefix
        for i, existing in enumerate(self._paths):
            if existing.public_key_prefix == advert_path.public_key_prefix:
                self._paths[i] = advert_path
                return

        # Add new entry, evicting oldest if full
        if len(self._paths) >= self._max:
            self._paths.pop(0)
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

    def clear(self):
        """Remove all cached paths."""
        self._paths.clear()

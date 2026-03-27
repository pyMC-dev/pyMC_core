"""Minimal region helpers built on top of transport keys."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from .packet import Packet
from .transport_keys import calc_transport_code, get_auto_key_for

# Region flags mirror the MeshCore C++ definitions in RegionMap.h
REGION_DENY_FLOOD = 0x01
REGION_DENY_DIRECT = 0x02  # reserved for future use


@dataclass
class RegionEntry:
    """Single region definition."""

    id: int
    parent: int = 0
    flags: int = 0
    name: str = ""
    private_keys: Optional[List[bytes]] = None


class RegionMap:
    """In-memory region registry with packet→region matching."""

    def __init__(self, regions: Optional[Iterable[RegionEntry]] = None) -> None:
        self._regions: list[RegionEntry] = list(regions or [])

    # ------------------------------------------------------------------
    # Basic CRUD
    # ------------------------------------------------------------------
    def add_region(self, entry: RegionEntry) -> None:
        self._regions.append(entry)

    def extend(self, entries: Sequence[RegionEntry]) -> None:
        self._regions.extend(entries)

    @property
    def regions(self) -> list[RegionEntry]:
        return list(self._regions)

    # ------------------------------------------------------------------
    # Matching helpers
    # ------------------------------------------------------------------
    def _iter_region_keys(self, region: RegionEntry) -> Iterable[bytes]:
        """Yield all transport keys for a region."""
        # Private regions: caller supplies explicit keys (e.g. from secure store)
        if region.private_keys:
            for key in region.private_keys:
                if len(key) == 16:
                    yield key
            return

        name = region.name or ""
        if not name:
            return

        # Public hashtag region: firmware treats names starting with '#' as
        # canonical, and everything else as an "implicit hashtag" region.
        if name[0] == "#":
            canonical = name
        else:
            canonical = f"#{name}"

        # Reuse the existing SHA-256 → 16-byte key logic
        try:
            yield get_auto_key_for(canonical)
        except ValueError:
            # Invalid region name; ignore it rather than raising in callers.
            return

    def find_match(self, packet: Packet, *, mask: int = 0) -> Optional[RegionEntry]:
        """Return the first RegionEntry whose scope matches this packet.

        Args:
            packet: Parsed Packet instance with transport_codes populated.
            mask: Bitmask of REGION_DENY_* flags to honour. Regions where
                ``flags & mask != 0`` are skipped (mirrors C++ behaviour).

        Returns:
            The first matching RegionEntry, or None if no match is found.
        """
        # No transport code present → cannot match to a region.
        if not packet.has_transport_codes():
            return None

        code = packet.transport_codes[0]
        if not code:
            return None

        for region in self._regions:
            # Skip regions that explicitly deny this traffic type.
            if region.flags & mask:
                continue
            for key in self._iter_region_keys(region):
                try:
                    expected = calc_transport_code(key, packet)
                except Exception:
                    continue
                if expected == code:
                    return region
        return None

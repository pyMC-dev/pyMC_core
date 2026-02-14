"""Packet and radio statistics collector for companion radio."""

import time

from .models import PacketStats


class StatsCollector:
    """Collects packet transmission/reception statistics.

    Tracks flood vs direct packet counts, errors, and uptime.
    Matches the firmware's statistics reporting via CMD_GET_STATS.
    """

    def __init__(self):
        self.packets = PacketStats()
        self._start_time = time.time()

    def record_tx(self, is_flood: bool):
        """Record a successful transmission."""
        if is_flood:
            self.packets.flood_tx += 1
        else:
            self.packets.direct_tx += 1

    def record_rx(self, is_flood: bool):
        """Record a successful reception."""
        if is_flood:
            self.packets.flood_rx += 1
        else:
            self.packets.direct_rx += 1

    def record_tx_error(self):
        """Record a transmission error."""
        self.packets.tx_errors += 1

    def get_uptime_secs(self) -> int:
        """Return the number of seconds since the collector was created."""
        return int(time.time() - self._start_time)

    def get_totals(self) -> dict:
        """Return a summary of all statistics."""
        return {
            "flood_tx": self.packets.flood_tx,
            "flood_rx": self.packets.flood_rx,
            "direct_tx": self.packets.direct_tx,
            "direct_rx": self.packets.direct_rx,
            "tx_errors": self.packets.tx_errors,
            "total_tx": self.packets.flood_tx + self.packets.direct_tx,
            "total_rx": self.packets.flood_rx + self.packets.direct_rx,
            "uptime_secs": self.get_uptime_secs(),
        }

    def reset(self):
        """Reset all counters and restart uptime."""
        self.packets = PacketStats()
        self._start_time = time.time()

"""Tests for the lightweight RegionMap helper."""

from __future__ import annotations

from pymc_core.protocol import LocalIdentity, Packet, PacketBuilder
from pymc_core.protocol.constants import ROUTE_TYPE_TRANSPORT_FLOOD
from pymc_core.protocol.region_map import REGION_DENY_FLOOD, RegionEntry, RegionMap
from pymc_core.protocol.transport_keys import calc_transport_code, get_auto_key_for


def _make_scoped_packet(region_name: str) -> Packet:
    """Create a transport-flood advert tagged for the given public region."""
    identity = LocalIdentity()
    pkt = PacketBuilder.create_advert(
        local_identity=identity,
        name="test",
        route_type="flood",
    )
    # Derive key/code exactly as CompanionBase._apply_flood_scope does
    if not region_name.startswith("#"):
        region_name = f"#{region_name}"
    key = get_auto_key_for(region_name)
    code = calc_transport_code(key, pkt)
    pkt.transport_codes[0] = code
    pkt.transport_codes[1] = 0
    pkt.header = (pkt.header & ~0x03) | ROUTE_TYPE_TRANSPORT_FLOOD
    return pkt


class TestRegionMapMatching:
    def test_match_explicit_hashtag_name(self):
        region = RegionEntry(id=1, name="#nl-li")
        rmap = RegionMap([region])
        pkt = _make_scoped_packet("#nl-li")

        match = rmap.find_match(pkt)

        assert match is not None
        assert match.id == 1
        assert match.name == "#nl-li"

    def test_match_implicit_hashtag_name(self):
        # Firmware treats "name" and "#name" the same for auto regions.
        region = RegionEntry(id=2, name="nl-li")
        rmap = RegionMap([region])
        pkt = _make_scoped_packet("nl-li")

        match = rmap.find_match(pkt)

        assert match is not None
        assert match.id == 2
        assert match.name == "nl-li"

    def test_respects_region_deny_flag(self):
        """Region with REGION_DENY_FLOOD is ignored when mask requests flood filtering."""
        allowed = RegionEntry(id=3, name="#allowed")
        denied = RegionEntry(id=4, name="#denied", flags=REGION_DENY_FLOOD)
        rmap = RegionMap([denied, allowed])

        pkt = _make_scoped_packet("#denied")

        # With mask=0, the denied region is still eligible and should match.
        match_any = rmap.find_match(pkt, mask=0)
        assert match_any is not None
        assert match_any.id == 4

        # With REGION_DENY_FLOOD mask, denied region is skipped → no match.
        match_filtered = rmap.find_match(pkt, mask=REGION_DENY_FLOOD)
        assert match_filtered is None

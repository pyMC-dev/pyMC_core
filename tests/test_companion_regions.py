"""Tests for companion flood-scope / region support."""

from __future__ import annotations

import pytest

from pymc_core.companion import CompanionRadio
from pymc_core.companion.models import Contact
from pymc_core.protocol import LocalIdentity, Packet, PacketBuilder
from pymc_core.protocol.constants import (
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from pymc_core.protocol.transport_keys import calc_transport_code, get_auto_key_for

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_flood_packet() -> Packet:
    """Create a minimal flood-routed advert packet for testing."""
    identity = LocalIdentity()
    return PacketBuilder.create_advert(
        local_identity=identity,
        name="test",
        route_type="flood",
    )


def _make_direct_packet() -> Packet:
    """Create a minimal direct-routed advert packet for testing."""
    identity = LocalIdentity()
    return PacketBuilder.create_advert(
        local_identity=identity,
        name="test",
        route_type="direct",
    )


class MockRadio:
    """Minimal mock radio for CompanionRadio."""

    def __init__(self):
        self.rx_callback = None
        self.sent: list[bytes] = []

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes) -> bool:
        self.sent.append(data)
        return True


def _make_companion() -> CompanionRadio:
    """Create a CompanionRadio with a mock radio for testing."""
    radio = MockRadio()
    identity = LocalIdentity()
    return CompanionRadio(radio=radio, identity=identity, node_name="test")


def _make_peer_contact(name: str) -> Contact:
    """Return a contact with a valid Ed25519 public key."""
    peer = LocalIdentity()
    return Contact(public_key=peer.get_public_key(), name=name)


# ---------------------------------------------------------------------------
# _apply_flood_scope unit tests
# ---------------------------------------------------------------------------


class TestApplyFloodScope:
    def test_sets_transport_codes_on_flood_packet(self):
        companion = _make_companion()
        key = get_auto_key_for("#usa")
        companion.set_flood_scope(key)
        pkt = _make_flood_packet()

        companion._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] != 0
        assert pkt.transport_codes[1] == 0

    def test_transport_code_matches_calc(self):
        companion = _make_companion()
        key = get_auto_key_for("#test-region")
        companion.set_flood_scope(key)
        pkt = _make_flood_packet()

        expected_code = calc_transport_code(key, pkt)
        companion._apply_flood_scope(pkt)

        assert pkt.transport_codes[0] == expected_code

    def test_noop_when_no_key_set(self):
        companion = _make_companion()
        pkt = _make_flood_packet()
        original_header = pkt.header

        companion._apply_flood_scope(pkt)

        assert pkt.header == original_header
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    def test_noop_on_direct_packet(self):
        companion = _make_companion()
        key = get_auto_key_for("#usa")
        companion.set_flood_scope(key)
        pkt = _make_direct_packet()
        original_header = pkt.header

        companion._apply_flood_scope(pkt)

        assert pkt.header == original_header
        assert pkt.get_route_type() == ROUTE_TYPE_DIRECT
        assert pkt.transport_codes == [0, 0]


# ---------------------------------------------------------------------------
# set_flood_region tests
# ---------------------------------------------------------------------------


class TestSetFloodRegion:
    def test_derives_key_with_hash_prefix(self):
        companion = _make_companion()
        companion.set_flood_region("#usa")
        assert companion._flood_transport_key == get_auto_key_for("#usa")

    def test_auto_adds_hash_prefix(self):
        companion = _make_companion()
        companion.set_flood_region("usa")
        assert companion._flood_transport_key == get_auto_key_for("#usa")

    def test_clear_with_none(self):
        companion = _make_companion()
        companion.set_flood_region("usa")
        assert companion._flood_transport_key is not None
        companion.set_flood_region(None)
        assert companion._flood_transport_key is None

    def test_same_key_with_or_without_prefix(self):
        c1 = _make_companion()
        c2 = _make_companion()
        c1.set_flood_region("europe")
        c2.set_flood_region("#europe")
        assert c1._flood_transport_key == c2._flood_transport_key


# ---------------------------------------------------------------------------
# set_flood_scope tests
# ---------------------------------------------------------------------------


class TestSetFloodScope:
    def test_stores_16_byte_key(self):
        companion = _make_companion()
        key = b"\x01" * 16
        companion.set_flood_scope(key)
        assert companion._flood_transport_key == key

    def test_truncates_longer_key(self):
        companion = _make_companion()
        key = b"\x02" * 32
        companion.set_flood_scope(key)
        assert companion._flood_transport_key == b"\x02" * 16

    def test_clear_with_none(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        companion.set_flood_scope(None)
        assert companion._flood_transport_key is None


# ---------------------------------------------------------------------------
# CompanionRadio dispatcher sync
# ---------------------------------------------------------------------------


class TestRadioDispatcherSync:
    def test_set_flood_scope_syncs_to_dispatcher(self):
        companion = _make_companion()
        key = get_auto_key_for("#test")
        companion.set_flood_scope(key)
        assert companion.node.dispatcher.flood_transport_key == key

    def test_set_flood_region_syncs_to_dispatcher(self):
        companion = _make_companion()
        companion.set_flood_region("test")
        expected = get_auto_key_for("#test")
        assert companion.node.dispatcher.flood_transport_key == expected

    def test_clear_syncs_to_dispatcher(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        assert companion.node.dispatcher.flood_transport_key is not None
        companion.set_flood_scope(None)
        assert companion.node.dispatcher.flood_transport_key is None


# ---------------------------------------------------------------------------
# Integration: advertise with flood scope
# ---------------------------------------------------------------------------


class TestAdvertiseWithFloodScope:
    @pytest.mark.asyncio
    async def test_advertise_flood_with_scope_sends_transport_flood(self):
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="scoped")
        companion.set_flood_region("usa")

        await companion.start()
        try:
            await companion.advertise(flood=True)
        finally:
            await companion.stop()

        # Verify the sent packet has transport codes
        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] != 0
        assert pkt.transport_codes[1] == 0

    @pytest.mark.asyncio
    async def test_advertise_flood_without_scope_sends_normal_flood(self):
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="noscope")
        # No flood scope set

        await companion.start()
        try:
            await companion.advertise(flood=True)
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

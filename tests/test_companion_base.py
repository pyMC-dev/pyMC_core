"""Tests for companion base: ResponseWaiter, adv_type_to_flags, and base API via CompanionRadio."""

import pytest

from pymc_core.companion import CompanionBridge
from pymc_core.companion.companion_base import ResponseWaiter, adv_type_to_flags
from pymc_core.companion.constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_REPEATER,
    ADV_TYPE_ROOM,
    ADV_TYPE_SENSOR,
)
from pymc_core.protocol import LocalIdentity, Packet
from pymc_core.protocol.constants import (
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
    ADVERT_FLAG_IS_SENSOR,
    PAYLOAD_TYPE_TRACE,
    ROUTE_TYPE_DIRECT,
)
from pymc_core.protocol.utils import determine_contact_type_from_flags, get_contact_type_name

# ---------------------------------------------------------------------------
# ResponseWaiter
# ---------------------------------------------------------------------------


class TestResponseWaiter:
    def test_initial_state(self):
        w = ResponseWaiter()
        assert w.data["success"] is False
        assert w.data["text"] is None
        assert w.data["parsed"] == {}

    def test_callback_sets_data_and_event(self):
        w = ResponseWaiter()
        w.callback(True, "hello", {"k": "v"})
        assert w.data["success"] is True
        assert w.data["text"] == "hello"
        assert w.data["parsed"] == {"k": "v"}
        assert w.event.is_set()

    @pytest.mark.asyncio
    async def test_wait_returns_after_callback(self):
        w = ResponseWaiter()
        w.callback(True, "done", {"x": 1})
        result = await w.wait(timeout=1.0)
        assert result["success"] is True
        assert result["text"] == "done"
        assert result["parsed"] == {"x": 1}
        assert "timeout" not in result

    @pytest.mark.asyncio
    async def test_wait_timeout(self):
        w = ResponseWaiter()
        result = await w.wait(timeout=0.05)
        assert result["timeout"] is True
        assert result["success"] is False


# ---------------------------------------------------------------------------
# adv_type_to_flags
# ---------------------------------------------------------------------------


class TestAdvTypeToFlags:
    def test_chat(self):
        assert adv_type_to_flags(ADV_TYPE_CHAT) == ADVERT_FLAG_IS_CHAT_NODE

    def test_repeater(self):
        assert adv_type_to_flags(ADV_TYPE_REPEATER) == ADVERT_FLAG_IS_REPEATER

    def test_room(self):
        assert adv_type_to_flags(ADV_TYPE_ROOM) == ADVERT_FLAG_IS_ROOM_SERVER

    def test_sensor(self):
        assert adv_type_to_flags(ADV_TYPE_SENSOR) == ADVERT_FLAG_IS_SENSOR

    def test_unknown_defaults_to_chat(self):
        assert adv_type_to_flags(99) == ADVERT_FLAG_IS_CHAT_NODE
        assert adv_type_to_flags(0) == ADVERT_FLAG_IS_CHAT_NODE


class TestDetermineContactTypeFromFlags:
    """Wire advert flags (low nibble) map to ADV_TYPE_* (1=chat, 2=repeater, 3=room, 4=sensor)."""

    def test_sensor_flags_map_to_adv_type_sensor(self):
        assert determine_contact_type_from_flags(0x04) == ADV_TYPE_SENSOR
        assert determine_contact_type_from_flags(0x14) == ADV_TYPE_SENSOR  # with HAS_LOCATION
        assert get_contact_type_name(4) == "Sensor"

    def test_all_node_types(self):
        assert determine_contact_type_from_flags(0x01) == ADV_TYPE_CHAT
        assert determine_contact_type_from_flags(0x02) == ADV_TYPE_REPEATER
        assert determine_contact_type_from_flags(0x03) == ADV_TYPE_ROOM
        assert determine_contact_type_from_flags(0x04) == ADV_TYPE_SENSOR

    def test_unknown(self):
        assert determine_contact_type_from_flags(0x05) == 0
        assert determine_contact_type_from_flags(0) == 0


# ---------------------------------------------------------------------------
# _apply_path_hash_mode
# ---------------------------------------------------------------------------


def _make_bridge(path_hash_mode: int = 0) -> CompanionBridge:
    """Create a minimal CompanionBridge for testing _apply_path_hash_mode."""

    async def _noop_injector(pkt, wait_for_ack=False):
        return True

    bridge = CompanionBridge(LocalIdentity(), _noop_injector, node_name="Test")
    bridge.prefs.path_hash_mode = path_hash_mode
    return bridge


class TestApplyPathHashMode:
    def test_encodes_on_zero_hops(self):
        """path_hash_mode=1 on a fresh packet (0 hops) → path_len=0x40."""
        bridge = _make_bridge(path_hash_mode=1)
        pkt = Packet()
        pkt.header = 0x06
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"test")
        pkt.payload_len = 4

        bridge._apply_path_hash_mode(pkt)

        assert pkt.path_len == 0x40  # (1 << 6) | 0 = 0x40
        assert pkt.get_path_hash_size() == 2
        assert pkt.get_path_hash_count() == 0

    def test_skips_nonzero_hops(self):
        """Packets with existing hops (stored contact path) are untouched."""
        bridge = _make_bridge(path_hash_mode=2)
        pkt = Packet()
        pkt.header = 0x06
        # 3 hops with 1-byte hashes
        pkt.set_path(b"\xAA\xBB\xCC")
        pkt.payload = bytearray(b"test")
        pkt.payload_len = 4

        original_path_len = pkt.path_len
        bridge._apply_path_hash_mode(pkt)

        # path_len unchanged — the contact path is preserved
        assert pkt.path_len == original_path_len
        assert pkt.get_path_hash_count() == 3

    def test_all_modes(self):
        """Verify mode 0→0x00, mode 1→0x40, mode 2→0x80 on fresh packets."""
        expected = {
            0: (0x00, 1),  # (path_len, hash_size)
            1: (0x40, 2),
            2: (0x80, 3),
        }
        for mode, (expected_path_len, expected_hash_size) in expected.items():
            bridge = _make_bridge(path_hash_mode=mode)
            pkt = Packet()
            pkt.header = 0x06
            pkt.path_len = 0
            pkt.path = bytearray()
            pkt.payload = bytearray(b"x")
            pkt.payload_len = 1

            bridge._apply_path_hash_mode(pkt)

            assert pkt.path_len == expected_path_len, (
                f"mode={mode}: expected path_len=0x{expected_path_len:02X}, "
                f"got 0x{pkt.path_len:02X}"
            )
            assert pkt.get_path_hash_size() == expected_hash_size, (
                f"mode={mode}: expected hash_size={expected_hash_size}, "
                f"got {pkt.get_path_hash_size()}"
            )

    def test_skips_trace_packets(self):
        """Trace packets use path for SNR values, not routing hashes."""
        bridge = _make_bridge(path_hash_mode=1)
        pkt = Packet()
        # Trace packet: payload_type=PAYLOAD_TYPE_TRACE, route_type=ROUTE_TYPE_DIRECT
        pkt.header = (PAYLOAD_TYPE_TRACE << 2) | ROUTE_TYPE_DIRECT
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"trace_data")
        pkt.payload_len = 10

        bridge._apply_path_hash_mode(pkt)

        # path_len must stay 0 — NOT 0x40
        assert pkt.path_len == 0
        assert pkt.get_path_hash_size() == 1
        assert pkt.get_path_hash_count() == 0

    def test_sets_path_hash_mode_applied_marker(self):
        """Companion sets _path_hash_mode_applied so dispatcher does not overwrite."""
        bridge = _make_bridge(path_hash_mode=1)
        pkt = Packet()
        pkt.header = 0x06
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"x")
        pkt.payload_len = 1

        bridge._apply_path_hash_mode(pkt)

        assert getattr(pkt, "_path_hash_mode_applied", False) is True

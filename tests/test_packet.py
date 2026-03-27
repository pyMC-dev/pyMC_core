import pytest

from pymc_core.protocol import Packet
from pymc_core.protocol.packet_utils import PathUtils


# Packet tests
def test_packet_creation():
    """Test basic packet creation and properties."""
    packet = Packet()
    assert packet is not None

    # Test header manipulation
    packet.header = 0x12
    assert packet.get_payload_type() == 4  # 0x12 >> 2 = 4 (bits 2-5: 0100)
    assert packet.get_route_type() == 2  # 0x12 & 0x03 = 2 (bits 0-1: 10)

    # Test payload
    test_payload = b"Hello, World!"
    packet.payload = bytearray(test_payload)
    packet.payload_len = len(test_payload)
    assert packet.get_payload() == test_payload


def test_packet_validation():
    """Test packet validation."""
    packet = Packet()
    packet.header = 0x12
    packet.payload = bytearray(b"test")
    packet.payload_len = 4

    # Should validate successfully
    packet._validate_lengths()


# --- Multi-byte path support ---


class TestPacketSetPath:
    """Tests for Packet.set_path() and path accessor methods."""

    def test_set_path_default_1byte_hashes(self):
        """set_path without encoded path_len assumes 1-byte hashes."""
        pkt = Packet()
        pkt.header = 0x02  # ROUTE_TYPE_DIRECT
        pkt.payload = bytearray(b"data")
        pkt.payload_len = 4

        pkt.set_path(b"\xAA\xBB\xCC")

        assert pkt.path == bytearray(b"\xAA\xBB\xCC")
        assert pkt.path_len == 3  # encode_path_len(1, 3) == 3
        assert pkt.get_path_hash_size() == 1
        assert pkt.get_path_hash_count() == 3
        assert pkt.get_path_byte_len() == 3

    def test_set_path_with_2byte_encoded(self):
        """set_path with 2-byte hash encoded path_len."""
        pkt = Packet()
        pkt.header = 0x02
        pkt.payload = bytearray(b"data")
        pkt.payload_len = 4

        # 2 hops × 2-byte hashes = 4 bytes of path data
        encoded = PathUtils.encode_path_len(2, 2)  # 0x42
        pkt.set_path(b"\x01\x02\x03\x04", path_len_encoded=encoded)

        assert pkt.path_len == 0x42
        assert pkt.get_path_hash_size() == 2
        assert pkt.get_path_hash_count() == 2
        assert pkt.get_path_byte_len() == 4
        assert pkt.path == bytearray(b"\x01\x02\x03\x04")

    def test_set_path_with_3byte_encoded(self):
        """set_path with 3-byte hash encoded path_len."""
        pkt = Packet()
        pkt.header = 0x02
        pkt.payload = bytearray(b"data")
        pkt.payload_len = 4

        # 3 hops × 3-byte hashes = 9 bytes of path data
        encoded = PathUtils.encode_path_len(3, 3)  # 0x83
        path_data = bytes(range(9))
        pkt.set_path(path_data, path_len_encoded=encoded)

        assert pkt.path_len == 0x83
        assert pkt.get_path_hash_size() == 3
        assert pkt.get_path_hash_count() == 3
        assert pkt.get_path_byte_len() == 9
        assert pkt.path == bytearray(path_data)

    def test_set_path_empty(self):
        """set_path with empty path."""
        pkt = Packet()
        pkt.header = 0x02
        pkt.payload = bytearray(b"data")
        pkt.payload_len = 4

        pkt.set_path(b"")

        assert pkt.path_len == 0
        assert pkt.get_path_hash_size() == 1
        assert pkt.get_path_hash_count() == 0
        assert pkt.get_path_byte_len() == 0

    def test_set_path_64_bytes_raises_without_encoded(self):
        """64-byte path without path_len_encoded would encode as 0 hops (64 & 0x3F)."""
        pkt = Packet()
        pkt.header = 0x02
        pkt.payload = bytearray(b"data")
        pkt.payload_len = 4

        with pytest.raises(ValueError, match="path length 64 exceeds maximum encodable"):
            pkt.set_path(bytes(64))

        # With explicit path_len_encoded (63 hops) path must be 63 bytes
        encoded_63 = PathUtils.encode_path_len(1, 63)
        pkt.set_path(bytes(63), path_len_encoded=encoded_63)
        assert pkt.path_len == 0x3F
        assert pkt.get_path_byte_len() == 63


class TestGetPathHashes:
    """Tests for Packet.get_path_hashes() and get_path_hashes_hex()."""

    def test_1byte_hashes(self):
        pkt = Packet()
        pkt.set_path(b"\xAA\xBB\xCC")
        assert pkt.get_path_hashes() == [b"\xAA", b"\xBB", b"\xCC"]

    def test_2byte_hashes(self):
        pkt = Packet()
        encoded = PathUtils.encode_path_len(2, 2)
        pkt.set_path(b"\xAA\xBB\xCC\xDD", path_len_encoded=encoded)
        assert pkt.get_path_hashes() == [b"\xAA\xBB", b"\xCC\xDD"]

    def test_3byte_hashes(self):
        pkt = Packet()
        encoded = PathUtils.encode_path_len(3, 2)
        pkt.set_path(b"\xAA\xBB\xCC\xDD\xEE\xFF", path_len_encoded=encoded)
        assert pkt.get_path_hashes() == [b"\xAA\xBB\xCC", b"\xDD\xEE\xFF"]

    def test_hex_2byte(self):
        pkt = Packet()
        encoded = PathUtils.encode_path_len(2, 2)
        pkt.set_path(b"\xAA\xBB\xCC\xDD", path_len_encoded=encoded)
        assert pkt.get_path_hashes_hex() == ["AABB", "CCDD"]

    def test_hex_1byte_backward_compat(self):
        pkt = Packet()
        pkt.set_path(b"\xB5\xA3\xF2")
        assert pkt.get_path_hashes_hex() == ["B5", "A3", "F2"]

    def test_empty_path(self):
        pkt = Packet()
        pkt.path_len = 0
        pkt.path = bytearray()
        assert pkt.get_path_hashes() == []
        assert pkt.get_path_hashes_hex() == []

    def test_zero_hops_with_hash_mode(self):
        """0 hops but hash_size=2 (originated with path_hash_mode=1)."""
        pkt = Packet()
        pkt.path_len = PathUtils.encode_path_len(2, 0)  # 0x40
        pkt.path = bytearray()
        assert pkt.get_path_hashes() == []
        assert pkt.get_path_hashes_hex() == []


class TestPacketRoundTrip:
    """Tests for write_to → read_from round-trip with multi-byte paths."""

    def _make_packet(self, header, path_data, path_len_encoded, payload):
        """Helper to build a packet with given path encoding."""
        pkt = Packet()
        pkt.header = header
        pkt.set_path(path_data, path_len_encoded)
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)
        return pkt

    def test_roundtrip_no_path(self):
        """Round-trip with empty path."""
        pkt = self._make_packet(0x05, b"", 0, b"hello")
        raw = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(raw)

        assert pkt2.header == 0x05
        assert pkt2.path_len == 0
        assert pkt2.get_path_byte_len() == 0
        assert pkt2.path == bytearray()
        assert pkt2.get_payload() == b"hello"

    def test_roundtrip_1byte_hashes(self):
        """Round-trip with 1-byte hashes (backward compatible)."""
        path = b"\xAA\xBB\xCC"
        pkt = self._make_packet(0x06, path, PathUtils.encode_path_len(1, 3), b"payload")
        raw = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(raw)

        assert pkt2.get_path_hash_size() == 1
        assert pkt2.get_path_hash_count() == 3
        assert pkt2.get_path_byte_len() == 3
        assert pkt2.path == bytearray(path)
        assert pkt2.get_payload() == b"payload"

    def test_roundtrip_2byte_hashes(self):
        """Round-trip with 2-byte hashes."""
        # 4 hops × 2 bytes = 8 bytes path
        path = bytes(range(8))
        encoded = PathUtils.encode_path_len(2, 4)
        pkt = self._make_packet(0x06, path, encoded, b"test")
        raw = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(raw)

        assert pkt2.path_len == encoded
        assert pkt2.get_path_hash_size() == 2
        assert pkt2.get_path_hash_count() == 4
        assert pkt2.get_path_byte_len() == 8
        assert pkt2.path == bytearray(path)
        assert pkt2.get_payload() == b"test"

    def test_roundtrip_3byte_hashes(self):
        """Round-trip with 3-byte hashes."""
        # 3 hops × 3 bytes = 9 bytes path
        path = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99])
        encoded = PathUtils.encode_path_len(3, 3)
        pkt = self._make_packet(0x06, path, encoded, b"msg")
        raw = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(raw)

        assert pkt2.path_len == encoded
        assert pkt2.get_path_hash_size() == 3
        assert pkt2.get_path_hash_count() == 3
        assert pkt2.get_path_byte_len() == 9
        assert pkt2.path == bytearray(path)
        assert pkt2.get_payload() == b"msg"

    def test_roundtrip_max_2byte_path(self):
        """Round-trip with maximum valid 2-byte hash path (32 hops × 2 = 64 bytes)."""
        path = bytes(range(64))
        encoded = PathUtils.encode_path_len(2, 32)
        pkt = self._make_packet(0x06, path, encoded, b"x")
        raw = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(raw)

        assert pkt2.get_path_hash_size() == 2
        assert pkt2.get_path_hash_count() == 32
        assert pkt2.get_path_byte_len() == 64
        assert pkt2.path == bytearray(path)

    def test_roundtrip_max_3byte_path(self):
        """Round-trip with maximum valid 3-byte hash path (21 hops × 3 = 63 bytes)."""
        path = bytes(range(63))
        encoded = PathUtils.encode_path_len(3, 21)
        pkt = self._make_packet(0x06, path, encoded, b"x")
        raw = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(raw)

        assert pkt2.get_path_hash_size() == 3
        assert pkt2.get_path_hash_count() == 21
        assert pkt2.get_path_byte_len() == 63
        assert pkt2.path == bytearray(path)

    def test_roundtrip_1byte_backward_compat(self):
        """Backward compatibility: 1-byte hash packets identical to legacy format."""
        # Build the packet the OLD way (direct assignment)
        pkt_old = Packet()
        pkt_old.header = 0x06
        pkt_old.path = bytearray(b"\x01\x02\x03")
        pkt_old.path_len = 3
        pkt_old.payload = bytearray(b"test")
        pkt_old.payload_len = 4
        raw_old = pkt_old.write_to()

        # Build the packet the NEW way (set_path)
        pkt_new = Packet()
        pkt_new.header = 0x06
        pkt_new.set_path(b"\x01\x02\x03")
        pkt_new.payload = bytearray(b"test")
        pkt_new.payload_len = 4
        raw_new = pkt_new.write_to()

        # Wire formats must be identical
        assert raw_old == raw_new

    def test_read_from_invalid_path_len_raises(self):
        """read_from rejects reserved hash_size=4 encoding."""
        # Hand-craft a raw packet with path_len 0xC1 (hash_size=4, invalid)
        raw = bytes([0x06, 0xC1])  # header + invalid path_len
        pkt = Packet()
        with pytest.raises(ValueError, match="invalid path_len encoding"):
            pkt.read_from(raw)

    def test_read_from_truncated_path_raises(self):
        """read_from rejects packet with insufficient path bytes."""
        # 2 hops × 2-byte hashes = 4 bytes expected, but only provide 2
        encoded = PathUtils.encode_path_len(2, 2)  # needs 4 bytes of path
        raw = bytes([0x06, encoded, 0xAA, 0xBB])  # header + path_len + only 2 path bytes
        pkt = Packet()
        with pytest.raises(ValueError, match="truncated path"):
            pkt.read_from(raw)

    def test_get_raw_length_multibyte(self):
        """get_raw_length accounts for multi-byte path encoding."""
        pkt = Packet()
        pkt.header = 0x06
        # 5 hops × 2-byte hashes = 10 bytes path
        pkt.set_path(bytes(10), PathUtils.encode_path_len(2, 5))
        pkt.payload = bytearray(b"test")
        pkt.payload_len = 4

        # raw_length = header(1) + path_len_byte(1) + path(10) + payload(4) = 16
        assert pkt.get_raw_length() == 16

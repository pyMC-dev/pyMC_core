import struct

import pytest

from pymc_core.protocol.constants import MAX_PACKET_PAYLOAD, MAX_PATH_SIZE
from pymc_core.protocol.packet_utils import (
    PacketDataUtils,
    PacketHashingUtils,
    PacketValidationUtils,
    PathUtils,
)


class TestPacketValidationUtils:
    def test_validate_routing_path_valid_inputs(self):
        """Test routing path validation with valid inputs."""
        # Valid integer path
        path = [1, 2, 3, 255]
        result = PacketValidationUtils.validate_routing_path(path)
        assert result == [1, 2, 3, 255]

        # Valid hex string path
        path = ["01", "FF", "A5"]
        result = PacketValidationUtils.validate_routing_path(path)
        assert result == [1, 255, 165]

        # Mixed types
        path = [1, "FF", 255, "00"]
        result = PacketValidationUtils.validate_routing_path(path)
        assert result == [1, 255, 255, 0]

        # Float conversion
        path = [1.0, 2.5, 255.9]
        result = PacketValidationUtils.validate_routing_path(path)
        assert result == [1, 2, 255]

    def test_validate_routing_path_invalid_inputs(self):
        """Test routing path validation with invalid inputs."""
        # Not a list
        with pytest.raises(ValueError, match="routing_path must be a list"):
            PacketValidationUtils.validate_routing_path("not_a_list")

        # Path too long
        long_path = [0] * (MAX_PATH_SIZE + 1)
        with pytest.raises(
            ValueError,
            match=f"Path length {len(long_path)} exceeds maximum {MAX_PATH_SIZE}",
        ):
            PacketValidationUtils.validate_routing_path(long_path)

        # Invalid hex string - too short
        with pytest.raises(ValueError, match="hex string 'F' too short"):
            PacketValidationUtils.validate_routing_path(["F"])

        # Invalid hex characters
        with pytest.raises(ValueError, match="contains invalid hex characters"):
            PacketValidationUtils.validate_routing_path(["GG"])

        # Value out of range - negative
        with pytest.raises(ValueError, match="value -1 out of range"):
            PacketValidationUtils.validate_routing_path([-1])

        # Value out of range - too high
        with pytest.raises(ValueError, match="value 256 out of range"):
            PacketValidationUtils.validate_routing_path([256])

        # Invalid type
        with pytest.raises(ValueError, match="invalid type .* for value"):
            PacketValidationUtils.validate_routing_path([None])

    def test_validate_packet_bounds(self):
        """Test packet bounds validation."""
        # Valid bounds
        PacketValidationUtils.validate_packet_bounds(0, 4, 10, "test error")
        PacketValidationUtils.validate_packet_bounds(6, 4, 10, "test error")

        # Invalid bounds - not enough data
        with pytest.raises(ValueError, match="test error"):
            PacketValidationUtils.validate_packet_bounds(7, 4, 10, "test error")

        # Edge case - exact boundary
        PacketValidationUtils.validate_packet_bounds(6, 4, 10, "test error")

    def test_validate_buffer_lengths(self):
        """Test buffer length validation."""
        # Valid lengths
        PacketValidationUtils.validate_buffer_lengths(5, 5, 10, 10)

        # Invalid path length
        with pytest.raises(ValueError, match="path_len mismatch: expected 5, got 6"):
            PacketValidationUtils.validate_buffer_lengths(5, 6, 10, 10)

        # Invalid payload length
        with pytest.raises(ValueError, match="payload_len mismatch: expected 10, got 15"):
            PacketValidationUtils.validate_buffer_lengths(5, 5, 10, 15)

    def test_validate_payload_size(self):
        """Test payload size validation."""
        # Valid sizes
        PacketValidationUtils.validate_payload_size(100)
        PacketValidationUtils.validate_payload_size(MAX_PACKET_PAYLOAD)

        # Invalid size - too large
        with pytest.raises(
            ValueError,
            match=f"payload too large: {MAX_PACKET_PAYLOAD + 1} > {MAX_PACKET_PAYLOAD}",
        ):
            PacketValidationUtils.validate_payload_size(MAX_PACKET_PAYLOAD + 1)


class TestPacketDataUtils:
    def test_pack_timestamp_data(self):
        """Test timestamp + data packing."""
        timestamp = 1234567890
        data1 = b"hello"
        data2 = 42
        data3 = "world"

        result = PacketDataUtils.pack_timestamp_data(timestamp, data1, data2, data3)

        # Should start with timestamp as little-endian 4 bytes
        expected_timestamp = struct.pack("<I", timestamp)
        assert result.startswith(expected_timestamp)

        # Should contain the data parts
        assert data1 in result
        assert bytes([data2]) in result  # Integer packed as single byte
        assert data3.encode() in result

    def test_pack_timestamp_data_edge_cases(self):
        """Test edge cases for timestamp data packing."""
        # No additional data
        result = PacketDataUtils.pack_timestamp_data(1234567890)
        expected_timestamp = struct.pack("<I", 1234567890)
        assert result == expected_timestamp

        # Large timestamp
        large_timestamp = 2**32 - 1  # Max uint32
        result = PacketDataUtils.pack_timestamp_data(large_timestamp)
        expected = struct.pack("<I", large_timestamp)
        assert result == expected

        # Zero timestamp
        result = PacketDataUtils.pack_timestamp_data(0)
        expected = struct.pack("<I", 0)
        assert result == expected


class TestPacketHashingUtils:
    def test_hash_string_returns_full_uppercase_hex(self):
        payload_type = 0x05
        path_len = 0
        payload = bytes.fromhex(
            "D9BA8E4EA9444822AC56B4D52AC3C0044C6AE402997BB9805CCB331EC3378DCE339F2D"
        )

        expected_hex = "887B9BE6056D0B0517AF3A04AC2478EDFC2AB731936DEA525041500E7ADE74D3"

        result = PacketHashingUtils.calculate_packet_hash_string(
            payload_type=payload_type,
            path_len=path_len,
            payload=payload,
            length=None,
        )

        assert result == expected_hex
        assert result.isupper()

    def test_hash_string_truncates_to_requested_length(self):
        payload_type = 0x05
        path_len = 1
        payload = bytes.fromhex(
            "D9BA8E4EA9444822AC56B4D52AC3C0044C6AE402997BB9805CCB331EC3378DCE339F2D"
        )

        expected_hex = "887B9BE6056D0B05"

        truncated = PacketHashingUtils.calculate_packet_hash_string(
            payload_type=payload_type,
            path_len=path_len,
            payload=payload,
            length=16,
        )

        assert truncated == expected_hex[:16]
        assert len(truncated) == 16
        assert truncated.isupper()


class TestPathUtils:
    """Tests for multi-byte path encoding/decoding utilities."""

    # --- get_path_hash_size ---

    def test_hash_size_1byte(self):
        """Bits 6-7 == 0b00 → hash_size = 1."""
        assert PathUtils.get_path_hash_size(0x00) == 1
        assert PathUtils.get_path_hash_size(0x05) == 1
        assert PathUtils.get_path_hash_size(0x3F) == 1  # max hop count, 1-byte hashes

    def test_hash_size_2byte(self):
        """Bits 6-7 == 0b01 → hash_size = 2."""
        assert PathUtils.get_path_hash_size(0x40) == 2
        assert PathUtils.get_path_hash_size(0x45) == 2
        assert PathUtils.get_path_hash_size(0x7F) == 2

    def test_hash_size_3byte(self):
        """Bits 6-7 == 0b10 → hash_size = 3."""
        assert PathUtils.get_path_hash_size(0x80) == 3
        assert PathUtils.get_path_hash_size(0x8A) == 3
        assert PathUtils.get_path_hash_size(0xBF) == 3

    def test_hash_size_reserved(self):
        """Bits 6-7 == 0b11 → hash_size = 4 (reserved, invalid)."""
        assert PathUtils.get_path_hash_size(0xC0) == 4

    # --- get_path_hash_count ---

    def test_hash_count_extracts_lower_6_bits(self):
        """Hash count is the lower 6 bits (0-63)."""
        assert PathUtils.get_path_hash_count(0x00) == 0
        assert PathUtils.get_path_hash_count(0x05) == 5
        assert PathUtils.get_path_hash_count(0x3F) == 63
        # Upper bits should be masked off
        assert PathUtils.get_path_hash_count(0x45) == 5  # 0b01_000101
        assert PathUtils.get_path_hash_count(0x8A) == 10  # 0b10_001010
        assert PathUtils.get_path_hash_count(0xC0) == 0  # 0b11_000000

    # --- get_path_byte_len ---

    def test_byte_len_1byte_hashes(self):
        """1-byte hashes: byte_len = hop_count * 1."""
        assert PathUtils.get_path_byte_len(0x00) == 0
        assert PathUtils.get_path_byte_len(0x01) == 1
        assert PathUtils.get_path_byte_len(0x05) == 5
        assert PathUtils.get_path_byte_len(0x3F) == 63

    def test_byte_len_2byte_hashes(self):
        """2-byte hashes: byte_len = hop_count * 2."""
        assert PathUtils.get_path_byte_len(0x40) == 0  # 0 hops × 2
        assert PathUtils.get_path_byte_len(0x41) == 2  # 1 hop × 2
        assert PathUtils.get_path_byte_len(0x45) == 10  # 5 hops × 2
        assert PathUtils.get_path_byte_len(0x60) == 64  # 32 hops × 2 = 64

    def test_byte_len_3byte_hashes(self):
        """3-byte hashes: byte_len = hop_count * 3."""
        assert PathUtils.get_path_byte_len(0x80) == 0  # 0 hops × 3
        assert PathUtils.get_path_byte_len(0x81) == 3  # 1 hop × 3
        assert PathUtils.get_path_byte_len(0x8A) == 30  # 10 hops × 3
        assert PathUtils.get_path_byte_len(0x95) == 63  # 21 hops × 3 = 63

    # --- encode_path_len ---

    def test_encode_1byte_hashes(self):
        """1-byte hashes: encoded = (0 << 6) | count = count."""
        assert PathUtils.encode_path_len(1, 0) == 0x00
        assert PathUtils.encode_path_len(1, 1) == 0x01
        assert PathUtils.encode_path_len(1, 5) == 0x05
        assert PathUtils.encode_path_len(1, 63) == 0x3F

    def test_encode_2byte_hashes(self):
        """2-byte hashes: encoded = (1 << 6) | count."""
        assert PathUtils.encode_path_len(2, 0) == 0x40
        assert PathUtils.encode_path_len(2, 1) == 0x41
        assert PathUtils.encode_path_len(2, 5) == 0x45
        assert PathUtils.encode_path_len(2, 32) == 0x60

    def test_encode_3byte_hashes(self):
        """3-byte hashes: encoded = (2 << 6) | count."""
        assert PathUtils.encode_path_len(3, 0) == 0x80
        assert PathUtils.encode_path_len(3, 1) == 0x81
        assert PathUtils.encode_path_len(3, 10) == 0x8A
        assert PathUtils.encode_path_len(3, 21) == 0x95

    def test_encode_decode_roundtrip(self):
        """encode → get_path_hash_size + get_path_hash_count roundtrip."""
        for hash_size in (1, 2, 3):
            for count in (0, 1, 10, 63):
                encoded = PathUtils.encode_path_len(hash_size, count)
                assert PathUtils.get_path_hash_size(encoded) == hash_size
                assert PathUtils.get_path_hash_count(encoded) == count
                assert PathUtils.get_path_byte_len(encoded) == hash_size * count

    # --- is_valid_path_len ---

    def test_valid_path_len_1byte(self):
        """1-byte hashes: valid up to MAX_PATH_SIZE hops."""
        assert PathUtils.is_valid_path_len(0x00) is True  # 0 hops
        assert PathUtils.is_valid_path_len(0x01) is True  # 1 hop
        assert PathUtils.is_valid_path_len(0x3F) is True  # 63 hops, 63 bytes ≤ MAX_PATH_SIZE(64)

    def test_valid_path_len_2byte(self):
        """2-byte hashes: valid when hop_count * 2 ≤ MAX_PATH_SIZE."""
        assert PathUtils.is_valid_path_len(0x40) is True  # 0 hops
        assert PathUtils.is_valid_path_len(0x41) is True  # 1 hop × 2 = 2
        assert PathUtils.is_valid_path_len(0x60) is True  # 32 hops × 2 = 64 ≤ MAX_PATH_SIZE
        assert PathUtils.is_valid_path_len(0x61) is False  # 33 hops × 2 = 66 > MAX_PATH_SIZE

    def test_valid_path_len_3byte(self):
        """3-byte hashes: valid when hop_count * 3 ≤ MAX_PATH_SIZE."""
        assert PathUtils.is_valid_path_len(0x80) is True  # 0 hops
        assert PathUtils.is_valid_path_len(0x95) is True  # 21 hops × 3 = 63 ≤ MAX_PATH_SIZE
        assert PathUtils.is_valid_path_len(0x96) is False  # 22 hops × 3 = 66 > MAX_PATH_SIZE

    def test_valid_path_len_reserved_hash_size(self):
        """Hash size 4 (bits 6-7 == 0b11) is reserved and always invalid."""
        assert PathUtils.is_valid_path_len(0xC0) is False  # hash_size=4, 0 hops
        assert PathUtils.is_valid_path_len(0xC1) is False  # hash_size=4, 1 hop
        assert PathUtils.is_valid_path_len(0xFF) is False  # hash_size=4, 63 hops

    # --- Backward compatibility ---

    def test_1byte_backward_compatible(self):
        """For 1-byte hashes, encoded path_len == raw hop count == byte count."""
        for n in range(0, 64):
            encoded = PathUtils.encode_path_len(1, n)
            assert encoded == n
            assert PathUtils.get_path_byte_len(encoded) == n

    def test_encode_path_len_rejects_hop_count_64(self):
        """Hop count is 6 bits (0-63); 64 would mask to 0 and produce invalid packet."""
        with pytest.raises(ValueError, match="hop count must be 0-63"):
            PathUtils.encode_path_len(1, 64)
        with pytest.raises(ValueError, match="hop count must be 0-63"):
            PathUtils.encode_path_len(1, 100)

    def test_is_path_at_max_hops(self):
        """is_path_at_max_hops is True when path bytes/hops are at limit for hash size."""
        # No path
        assert PathUtils.is_path_at_max_hops(0) is False
        # 1-byte hashes: max 63 hops
        assert PathUtils.is_path_at_max_hops(PathUtils.encode_path_len(1, 62)) is False
        assert PathUtils.is_path_at_max_hops(PathUtils.encode_path_len(1, 63)) is True
        # 2-byte hashes: max 32 hops (64 bytes)
        assert PathUtils.is_path_at_max_hops(PathUtils.encode_path_len(2, 31)) is False
        assert PathUtils.is_path_at_max_hops(PathUtils.encode_path_len(2, 32)) is True
        # 3-byte hashes: max 21 hops (63 bytes)
        assert PathUtils.is_path_at_max_hops(PathUtils.encode_path_len(3, 20)) is False
        assert PathUtils.is_path_at_max_hops(PathUtils.encode_path_len(3, 21)) is True

    # --- TRACE payload (Mesh.cpp flags & 0x03) ---

    def test_trace_payload_hash_width(self):
        """TRACE uses 1 << (flags & 3) bytes per hop, not Packet path_len encoding."""
        assert PathUtils.trace_payload_hash_width(0) == 1
        assert PathUtils.trace_payload_hash_width(1) == 2
        assert PathUtils.trace_payload_hash_width(2) == 4
        assert PathUtils.trace_payload_hash_width(3) == 8
        assert PathUtils.trace_payload_hash_width(0xFF) == 8

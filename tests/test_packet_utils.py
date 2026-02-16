import struct

import pytest

from pymc_core.protocol.constants import MAX_PACKET_PAYLOAD, MAX_PATH_SIZE
from pymc_core.protocol.packet_utils import (
    PacketDataUtils,
    PacketHashingUtils,
    PacketValidationUtils,
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

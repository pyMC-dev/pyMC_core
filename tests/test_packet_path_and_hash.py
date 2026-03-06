"""
Tests for packet hash calculation, path handling, and deduplication behaviour.

Validates that the Python implementation matches the C++ MeshCore firmware,
specifically:
  - Hash only includes payload_type + payload (not path/header/transport codes)
  - TRACE packets additionally include path_len as uint16_t LE in the hash
  - Payload is truncated to payload_len before hashing
  - Path modifications (append for flood, consume for direct) don't affect hash
  - Round-trip serialization preserves hash identity
"""

import hashlib
import struct

import pytest

from pymc_core.protocol import Packet
from pymc_core.protocol.constants import (
    MAX_HASH_SIZE,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    MAX_SUPPORTED_PAYLOAD_VERSION,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    PH_TYPE_SHIFT,
    PH_VER_SHIFT,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_DIRECT,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from pymc_core.protocol.packet_utils import PacketHashingUtils, PacketValidationUtils

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_header(payload_type: int, route_type: int, version: int = 0) -> int:
    """Build a header byte from components (mirrors PacketHeaderUtils.make_header)."""
    return route_type | (payload_type << PH_TYPE_SHIFT) | (version << 6)


def _cpp_reference_hash(payload_type: int, path_len: int, payload: bytes) -> bytes:
    """
    Reference implementation that exactly mirrors C++ Packet::calculatePacketHash().

    C++ source (MeshCore/src/Packet.cpp):
        SHA256 sha;
        uint8_t t = getPayloadType();
        sha.update(&t, 1);
        if (t == PAYLOAD_TYPE_TRACE) {
            sha.update(&path_len, sizeof(path_len));  // uint16_t, 2 bytes LE
        }
        sha.update(payload, payload_len);
        sha.finalize(hash, MAX_HASH_SIZE);             // MAX_HASH_SIZE == 8 in C++
    """
    sha = hashlib.sha256()
    sha.update(bytes([payload_type]))
    if payload_type == PAYLOAD_TYPE_TRACE:
        sha.update(struct.pack("<H", path_len))  # uint16_t little-endian
    sha.update(payload)
    # C++ truncates to 8 bytes; Python MAX_HASH_SIZE is 32 but first 8 match
    return sha.digest()


def _build_packet(
    payload_type: int,
    route_type: int,
    payload: bytes,
    path: bytes = b"",
    version: int = 0,
) -> Packet:
    """Build a Packet with the given fields set correctly."""
    pkt = Packet()
    pkt.header = _make_header(payload_type, route_type, version)
    pkt.payload = bytearray(payload)
    pkt.payload_len = len(payload)
    pkt.path = bytearray(path)
    pkt.path_len = len(path)
    return pkt


# ===================================================================
# 1. Basic hash correctness — matches reference C++ implementation
# ===================================================================


class TestPacketHashBasic:
    """Verify hash output matches the C++ reference for various packet types."""

    def test_txt_msg_hash_matches_reference(self):
        """TXT_MSG: hash = SHA256(payload_type || payload)[:MAX_HASH_SIZE]"""
        payload = b"\xAB\x12Hello, mesh world!"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)

        expected = _cpp_reference_hash(PAYLOAD_TYPE_TXT_MSG, 0, payload)[:MAX_HASH_SIZE]
        assert pkt.calculate_packet_hash() == expected

    def test_ack_hash_matches_reference(self):
        """ACK packets hash identically to the reference."""
        payload = struct.pack("<I", 0xDEADBEEF)  # 4-byte ACK CRC
        pkt = _build_packet(PAYLOAD_TYPE_ACK, ROUTE_TYPE_DIRECT, payload, path=b"\x42")

        expected = _cpp_reference_hash(PAYLOAD_TYPE_ACK, 1, payload)[:MAX_HASH_SIZE]
        assert pkt.calculate_packet_hash() == expected

    def test_advert_hash_matches_reference(self):
        """ADVERT packets hash identically to the reference."""
        payload = bytes(range(96))  # pub_key + timestamp + signature + app_data
        pkt = _build_packet(PAYLOAD_TYPE_ADVERT, ROUTE_TYPE_FLOOD, payload)

        expected = _cpp_reference_hash(PAYLOAD_TYPE_ADVERT, 0, payload)[:MAX_HASH_SIZE]
        assert pkt.calculate_packet_hash() == expected

    def test_trace_hash_includes_path_len_as_uint16(self):
        """TRACE: hash = SHA256(payload_type || path_len_u16_LE || payload)"""
        payload = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"
        path = b"\xAA\xBB\xCC"
        pkt = _build_packet(PAYLOAD_TYPE_TRACE, ROUTE_TYPE_DIRECT, payload, path=path)

        expected = _cpp_reference_hash(PAYLOAD_TYPE_TRACE, 3, payload)[:MAX_HASH_SIZE]
        assert pkt.calculate_packet_hash() == expected

    def test_trace_different_path_len_gives_different_hash(self):
        """Changing path_len on a TRACE packet must change the hash."""
        payload = b"\x01\x02\x03\x04"

        pkt_a = _build_packet(PAYLOAD_TYPE_TRACE, ROUTE_TYPE_DIRECT, payload, path=b"\xAA")
        pkt_b = _build_packet(PAYLOAD_TYPE_TRACE, ROUTE_TYPE_DIRECT, payload, path=b"\xAA\xBB")

        assert pkt_a.calculate_packet_hash() != pkt_b.calculate_packet_hash()

    def test_trace_path_len_uint16_not_uint8(self):
        """
        Verify path_len is packed as uint16_t LE (2 bytes), not uint8 (1 byte).

        If incorrectly using 1 byte, the hash of path_len=3 would be
        SHA256(0x09 || 0x03 || payload) instead of
        SHA256(0x09 || 0x03 0x00 || payload).
        """
        payload = b"trace_test"
        path_len = 3

        # Correct: 2-byte LE
        sha_correct = hashlib.sha256()
        sha_correct.update(bytes([PAYLOAD_TYPE_TRACE]))
        sha_correct.update(struct.pack("<H", path_len))
        sha_correct.update(payload)
        correct_hash = sha_correct.digest()[:MAX_HASH_SIZE]

        # Wrong: 1-byte
        sha_wrong = hashlib.sha256()
        sha_wrong.update(bytes([PAYLOAD_TYPE_TRACE]))
        sha_wrong.update(bytes([path_len]))
        sha_wrong.update(payload)
        wrong_hash = sha_wrong.digest()[:MAX_HASH_SIZE]

        # They must differ
        assert correct_hash != wrong_hash

        # Packet must match the correct one
        pkt = _build_packet(PAYLOAD_TYPE_TRACE, ROUTE_TYPE_DIRECT, payload, path=bytes(path_len))
        assert pkt.calculate_packet_hash() == correct_hash
        assert pkt.calculate_packet_hash() != wrong_hash


# ===================================================================
# 2. Hash excludes header, path, route type, transport codes
# ===================================================================


class TestPacketHashExclusions:
    """Verify that fields NOT in the C++ hash don't affect the Python hash."""

    def test_hash_independent_of_route_type(self):
        """Same payload_type + payload, different route → same hash."""
        payload = b"route_test_data"
        pkt_flood = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)
        pkt_direct = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_DIRECT, payload)

        assert pkt_flood.calculate_packet_hash() == pkt_direct.calculate_packet_hash()

    def test_hash_independent_of_path_content(self):
        """Changing path bytes doesn't change hash (except for TRACE path_len)."""
        payload = b"path_test_data"

        pkt_no_path = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)
        pkt_with_path = _build_packet(
            PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, path=b"\xAA\xBB\xCC"
        )

        assert pkt_no_path.calculate_packet_hash() == pkt_with_path.calculate_packet_hash()

    def test_hash_independent_of_path_length_for_non_trace(self):
        """For non-TRACE packets, path_len doesn't affect hash."""
        payload = b"non_trace"

        pkt_a = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)
        pkt_b = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, path=bytes(10))

        assert pkt_a.calculate_packet_hash() == pkt_b.calculate_packet_hash()

    def test_hash_independent_of_transport_codes(self):
        """Transport codes are not part of the hash."""
        payload = b"transport_test"

        pkt_plain = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)
        pkt_transport = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_TRANSPORT_FLOOD, payload)
        pkt_transport.transport_codes = [0x1234, 0x5678]

        assert pkt_plain.calculate_packet_hash() == pkt_transport.calculate_packet_hash()

    def test_hash_independent_of_version_bits(self):
        """Header version bits don't affect hash."""
        payload = b"version_test"

        pkt_v0 = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, version=0)
        pkt_v1 = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, version=1)

        assert pkt_v0.calculate_packet_hash() == pkt_v1.calculate_packet_hash()

    def test_different_payload_type_gives_different_hash(self):
        """Different payload_type with same payload → different hash."""
        payload = b"type_test_data"

        pkt_txt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)
        pkt_adv = _build_packet(PAYLOAD_TYPE_ADVERT, ROUTE_TYPE_FLOOD, payload)

        assert pkt_txt.calculate_packet_hash() != pkt_adv.calculate_packet_hash()


# ===================================================================
# 3. payload_len truncation — hash must use only payload[:payload_len]
# ===================================================================


class TestPayloadLenTruncation:
    """Verify hash uses payload[:payload_len], not the full bytearray buffer."""

    def test_hash_uses_payload_len_not_buffer_size(self):
        """
        If payload buffer is larger than payload_len, only the first
        payload_len bytes should be hashed (matching C++ behaviour).
        """
        actual_data = b"real_payload"
        trailing_junk = b"\xFF" * 20

        # Packet with exact payload
        pkt_exact = Packet()
        pkt_exact.header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        pkt_exact.payload = bytearray(actual_data)
        pkt_exact.payload_len = len(actual_data)
        pkt_exact.path = bytearray()
        pkt_exact.path_len = 0

        # Packet with oversized buffer but correct payload_len
        pkt_oversized = Packet()
        pkt_oversized.header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        pkt_oversized.payload = bytearray(actual_data + trailing_junk)
        pkt_oversized.payload_len = len(actual_data)  # NOT len(buffer)
        pkt_oversized.path = bytearray()
        pkt_oversized.path_len = 0

        assert pkt_exact.calculate_packet_hash() == pkt_oversized.calculate_packet_hash()

    def test_hash_changes_when_payload_len_changes(self):
        """Extending payload_len should change the hash (more data hashed)."""
        data = b"ABCDEFGHIJ"

        pkt_short = Packet()
        pkt_short.header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        pkt_short.payload = bytearray(data)
        pkt_short.payload_len = 5
        pkt_short.path = bytearray()
        pkt_short.path_len = 0

        pkt_full = Packet()
        pkt_full.header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        pkt_full.payload = bytearray(data)
        pkt_full.payload_len = 10
        pkt_full.path = bytearray()
        pkt_full.path_len = 0

        assert pkt_short.calculate_packet_hash() != pkt_full.calculate_packet_hash()

    def test_trace_hash_uses_payload_len_truncation_too(self):
        """TRACE packets also respect payload_len truncation."""
        data = b"TRACE_DATA_PLUS_JUNK"

        pkt = Packet()
        pkt.header = _make_header(PAYLOAD_TYPE_TRACE, ROUTE_TYPE_DIRECT)
        pkt.payload = bytearray(data)
        pkt.payload_len = 10  # Only first 10 bytes matter
        pkt.path = bytearray(b"\xAA\xBB")
        pkt.path_len = 2

        expected = _cpp_reference_hash(PAYLOAD_TYPE_TRACE, 2, data[:10])[:MAX_HASH_SIZE]
        assert pkt.calculate_packet_hash() == expected


# ===================================================================
# 4. Flood forwarding: path append must not change duplicate detection
# ===================================================================


class TestFloodPathAppend:
    """Simulate flood forwarding and verify hash stability."""

    def test_hash_stable_after_path_append(self):
        """
        Flood forwarding appends local_hash to path. Since path is NOT
        in the hash (for non-TRACE), the hash must remain identical.
        """
        payload = b"\xAB\x12encrypted_data_here"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, path=b"\x01\x02")

        hash_before = pkt.calculate_packet_hash()

        # Simulate flood_forward: append local hash
        local_hash = 0x42
        pkt.path.append(local_hash)
        pkt.path_len = len(pkt.path)

        hash_after = pkt.calculate_packet_hash()

        assert hash_before == hash_after

    def test_hash_stable_after_multiple_hops(self):
        """Hash stays the same through multiple flood hops."""
        payload = b"multi_hop_test"
        pkt = _build_packet(PAYLOAD_TYPE_ADVERT, ROUTE_TYPE_FLOOD, payload)

        original_hash = pkt.calculate_packet_hash()

        # Simulate 5 hops, each appending their local hash
        for i in range(5):
            pkt.path.append(0x10 + i)
            pkt.path_len = len(pkt.path)

        assert pkt.calculate_packet_hash() == original_hash

    def test_max_path_flood(self):
        """Hash is correct even when path is at MAX_PATH_SIZE - 1."""
        payload = b"big_path_test"
        existing_path = bytes(range(MAX_PATH_SIZE - 1))
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, path=existing_path)

        hash_before = pkt.calculate_packet_hash()

        # Append one more hop (now at MAX_PATH_SIZE)
        pkt.path.append(0xFF)
        pkt.path_len = len(pkt.path)
        assert pkt.path_len == MAX_PATH_SIZE

        assert pkt.calculate_packet_hash() == hash_before


# ===================================================================
# 5. Direct forwarding: path consume must not change duplicate detection
# ===================================================================


class TestDirectPathConsume:
    """Simulate direct forwarding path consumption and verify hash stability."""

    def test_hash_stable_after_path_consume(self):
        """
        Direct forwarding removes first byte from path (removeSelfFromPath).
        Hash must remain the same for non-TRACE packets.
        """
        payload = b"direct_msg"
        path = b"\x42\xAA\xBB"  # [our_hash, next, final]
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_DIRECT, payload, path=path)

        hash_before = pkt.calculate_packet_hash()

        # Simulate direct_forward: consume first byte
        pkt.path = bytearray(pkt.path[1:])
        pkt.path_len = len(pkt.path)

        assert pkt.calculate_packet_hash() == hash_before

    def test_hash_stable_after_full_path_consumed(self):
        """Hash stays same even when entire path is consumed (final hop)."""
        payload = b"last_hop_msg"
        path = b"\x42"  # Only our hash
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_DIRECT, payload, path=path)

        hash_before = pkt.calculate_packet_hash()

        # Consume the last hop
        pkt.path = bytearray()
        pkt.path_len = 0

        assert pkt.calculate_packet_hash() == hash_before

    def test_trace_hash_changes_after_path_consume(self):
        """
        TRACE packets include path_len in the hash, so consuming a hop
        DOES change the hash. This is by design (C++ CAVEAT comment).
        """
        payload = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"
        path = b"\x42\xAA\xBB"
        pkt = _build_packet(PAYLOAD_TYPE_TRACE, ROUTE_TYPE_DIRECT, payload, path=path)

        hash_with_3_hops = pkt.calculate_packet_hash()

        # Consume first hop
        pkt.path = bytearray(pkt.path[1:])
        pkt.path_len = len(pkt.path)

        hash_with_2_hops = pkt.calculate_packet_hash()

        # TRACE hashes MUST differ because path_len changed
        assert hash_with_3_hops != hash_with_2_hops


# ===================================================================
# 6. Serialization round-trip preserves hash
# ===================================================================


class TestSerializationHashPreservation:
    """Verify that write_to → read_from round-trip preserves the packet hash."""

    def test_flood_roundtrip_preserves_hash(self):
        payload = b"roundtrip_flood"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, path=b"\xAA\xBB")

        original_hash = pkt.calculate_packet_hash()

        wire_bytes = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(wire_bytes)

        assert pkt2.calculate_packet_hash() == original_hash

    def test_direct_roundtrip_preserves_hash(self):
        payload = b"roundtrip_direct"
        path = b"\x42\xAA\xBB"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_DIRECT, payload, path=path)

        original_hash = pkt.calculate_packet_hash()

        wire_bytes = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(wire_bytes)

        assert pkt2.calculate_packet_hash() == original_hash

    def test_transport_flood_roundtrip_preserves_hash(self):
        payload = b"roundtrip_transport"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_TRANSPORT_FLOOD, payload, path=b"\x01")
        pkt.transport_codes = [0xABCD, 0x1234]

        original_hash = pkt.calculate_packet_hash()

        wire_bytes = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(wire_bytes)

        assert pkt2.calculate_packet_hash() == original_hash

    def test_trace_roundtrip_preserves_hash(self):
        payload = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"
        path = b"\xAA\xBB"
        pkt = _build_packet(PAYLOAD_TYPE_TRACE, ROUTE_TYPE_DIRECT, payload, path=path)

        original_hash = pkt.calculate_packet_hash()

        wire_bytes = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(wire_bytes)

        assert pkt2.calculate_packet_hash() == original_hash
        assert pkt2.path_len == 2

    def test_roundtrip_after_flood_append_preserves_hash(self):
        """
        Simulate: receive → hash → flood_forward (append path) → serialize →
        deserialize → hash. Non-TRACE hash should still match original.
        """
        payload = b"multihop_roundtrip"
        pkt = _build_packet(PAYLOAD_TYPE_ADVERT, ROUTE_TYPE_FLOOD, payload, path=b"\x01")

        original_hash = pkt.calculate_packet_hash()

        # Flood forward: append local hash
        pkt.path.append(0x42)
        pkt.path_len = len(pkt.path)

        # Serialize + deserialize
        wire = pkt.write_to()
        pkt2 = Packet()
        pkt2.read_from(wire)

        assert pkt2.calculate_packet_hash() == original_hash
        assert pkt2.path_len == 2
        assert list(pkt2.path) == [0x01, 0x42]


# ===================================================================
# 7. PacketHashingUtils standalone tests
# ===================================================================


class TestPacketHashingUtilsStandalone:
    """Test the static utility directly, confirming C++ compatibility."""

    def test_non_trace_ignores_path_len(self):
        """Static util: path_len argument is ignored for non-TRACE."""
        payload = b"static_test"
        h0 = PacketHashingUtils.calculate_packet_hash(PAYLOAD_TYPE_TXT_MSG, 0, payload)
        h5 = PacketHashingUtils.calculate_packet_hash(PAYLOAD_TYPE_TXT_MSG, 5, payload)
        h63 = PacketHashingUtils.calculate_packet_hash(PAYLOAD_TYPE_TXT_MSG, 63, payload)
        assert h0 == h5 == h63

    def test_trace_uses_path_len(self):
        """Static util: path_len matters for TRACE."""
        payload = b"trace_static"
        h0 = PacketHashingUtils.calculate_packet_hash(PAYLOAD_TYPE_TRACE, 0, payload)
        h1 = PacketHashingUtils.calculate_packet_hash(PAYLOAD_TYPE_TRACE, 1, payload)
        assert h0 != h1

    def test_empty_payload_hashes_correctly(self):
        """Edge case: empty payload."""
        h = PacketHashingUtils.calculate_packet_hash(PAYLOAD_TYPE_TXT_MSG, 0, b"")
        expected = hashlib.sha256(bytes([PAYLOAD_TYPE_TXT_MSG])).digest()[:MAX_HASH_SIZE]
        assert h == expected

    def test_crc_matches_first_4_bytes_of_hash(self):
        """CRC should be little-endian uint32 of first 4 hash bytes."""
        payload = b"crc_test"
        h = PacketHashingUtils.calculate_packet_hash(PAYLOAD_TYPE_TXT_MSG, 0, payload)
        crc = PacketHashingUtils.calculate_crc(PAYLOAD_TYPE_TXT_MSG, 0, payload)
        assert crc == int.from_bytes(h[:4], "little")

    def test_hash_string_uppercase_hex(self):
        """Hash string output must be uppercase hex."""
        payload = b"hex_test"
        s = PacketHashingUtils.calculate_packet_hash_string(PAYLOAD_TYPE_TXT_MSG, 0, payload)
        assert s == s.upper()
        # Must be valid hex
        int(s, 16)

    def test_hash_string_truncation(self):
        """Hash string truncation should return first N characters."""
        payload = b"trunc_test"
        full = PacketHashingUtils.calculate_packet_hash_string(PAYLOAD_TYPE_TXT_MSG, 0, payload)
        trunc = PacketHashingUtils.calculate_packet_hash_string(
            PAYLOAD_TYPE_TXT_MSG, 0, payload, length=16
        )
        assert trunc == full[:16]
        assert len(trunc) == 16


# ===================================================================
# 8. Edge cases and regression guards
# ===================================================================


class TestEdgeCases:
    def test_max_payload_hashes_correctly(self):
        """MAX_PACKET_PAYLOAD-sized payload should hash without error."""
        from pymc_core.protocol.constants import MAX_PACKET_PAYLOAD

        payload = bytes(range(256)) * (MAX_PACKET_PAYLOAD // 256 + 1)
        payload = payload[:MAX_PACKET_PAYLOAD]

        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)
        h = pkt.calculate_packet_hash()
        assert len(h) == MAX_HASH_SIZE

    def test_single_byte_payload(self):
        """Single byte payload hashes correctly."""
        pkt = _build_packet(PAYLOAD_TYPE_ACK, ROUTE_TYPE_FLOOD, b"\x00")
        h = pkt.calculate_packet_hash()
        expected = _cpp_reference_hash(PAYLOAD_TYPE_ACK, 0, b"\x00")[:MAX_HASH_SIZE]
        assert h == expected

    def test_path_at_max_size(self):
        """Packet with MAX_PATH_SIZE path still hashes correctly."""
        payload = b"max_path"
        path = bytes(range(MAX_PATH_SIZE))
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, path=path)

        expected = _cpp_reference_hash(PAYLOAD_TYPE_TXT_MSG, MAX_PATH_SIZE, payload)[:MAX_HASH_SIZE]
        assert pkt.calculate_packet_hash() == expected

    def test_do_not_retransmit_does_not_affect_hash(self):
        """mark_do_not_retransmit uses a flag, not header mutation — hash unchanged."""
        payload = b"retransmit_test"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)

        hash_before = pkt.calculate_packet_hash()
        pkt.mark_do_not_retransmit()
        hash_after = pkt.calculate_packet_hash()

        # Python uses _do_not_retransmit flag, not header=0xFF, so hash is preserved
        assert hash_before == hash_after
        assert pkt.is_marked_do_not_retransmit()

    def test_header_0xff_sentinel_changes_payload_type(self):
        """
        In C++, markDoNotRetransmit sets header=0xFF which changes
        payload_type to 0x3F & 0x0F = 0x0F. Python avoids this by
        using a separate flag, but let's confirm the header stays intact.
        """
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, b"test")
        original_type = pkt.get_payload_type()

        pkt.mark_do_not_retransmit()

        # Header should NOT be mutated in Python implementation
        assert pkt.get_payload_type() == original_type


# ===================================================================
# 9. Bad / malformed packets — must be rejected by validation
# ===================================================================


class TestBadPacketDeserialization:
    """Verify that read_from rejects malformed wire data."""

    def test_empty_bytes_raises(self):
        """Zero-length data should raise (no header byte)."""
        pkt = Packet()
        with pytest.raises((ValueError, IndexError)):
            pkt.read_from(b"")

    def test_single_byte_only_header(self):
        """Just a header byte, no path_len — should raise."""
        header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        pkt = Packet()
        with pytest.raises(ValueError, match="missing path_len"):
            pkt.read_from(bytes([header]))

    def test_unsupported_version_rejected(self):
        """Version > MAX_SUPPORTED_PAYLOAD_VERSION should be rejected."""
        bad_version = MAX_SUPPORTED_PAYLOAD_VERSION + 1
        # Craft header with unsupported version in bits 6-7
        header = (
            ROUTE_TYPE_FLOOD
            | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT)
            | (bad_version << PH_VER_SHIFT)
        )
        wire = bytes([header, 0])  # header + path_len=0, no payload
        pkt = Packet()
        with pytest.raises(ValueError, match="Unsupported packet version"):
            pkt.read_from(wire)

    def test_path_len_exceeds_max(self):
        """Encoded path_len that decodes to > MAX_PATH_SIZE (64) bytes must be rejected."""
        from pymc_core.protocol.packet_utils import PathUtils

        header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        # 33 hops × 2 bytes = 66 path bytes (exceeds MAX_PATH_SIZE)
        bad_path_len = PathUtils.encode_path_len(hash_size=2, hash_count=33)
        wire = bytes([header, bad_path_len]) + bytes(66) + b"payload"
        pkt = Packet()
        with pytest.raises(ValueError, match="path_len too large"):
            pkt.read_from(wire)

    def test_path_len_255_rejected(self):
        """path_len=255 (reserved hash_size 4) must be rejected."""
        header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        wire = bytes([header, 0xFF]) + bytes(255)
        pkt = Packet()
        with pytest.raises(ValueError, match="invalid path_len encoding"):
            pkt.read_from(wire)

    def test_truncated_path_rejected(self):
        """path_len says 10 bytes but only 3 are provided."""
        header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        wire = bytes([header, 10]) + bytes(3)  # claims 10, only gives 3
        pkt = Packet()
        with pytest.raises(ValueError, match="truncated path"):
            pkt.read_from(wire)

    def test_transport_codes_truncated(self):
        """Transport route type needs 4 bytes of transport codes — provide only 2."""
        header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_TRANSPORT_FLOOD)
        wire = bytes([header]) + bytes(2)  # only 2 bytes, need 4
        pkt = Packet()
        with pytest.raises(ValueError, match="missing transport codes"):
            pkt.read_from(wire)

    def test_transport_codes_missing_entirely(self):
        """Transport route type with no data after header."""
        header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_TRANSPORT_DIRECT)
        wire = bytes([header])
        pkt = Packet()
        with pytest.raises(ValueError, match="missing transport codes"):
            pkt.read_from(wire)

    def test_oversized_payload_rejected(self):
        """Payload exceeding MAX_PACKET_PAYLOAD must be rejected."""
        header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        oversized_payload = bytes(MAX_PACKET_PAYLOAD + 1)
        wire = bytes([header, 0]) + oversized_payload  # path_len=0
        pkt = Packet()
        with pytest.raises(ValueError, match="payload too large"):
            pkt.read_from(wire)

    def test_path_len_exact_max_accepted(self):
        """Encoded path_len that decodes to exactly MAX_PATH_SIZE (64) bytes should be accepted."""
        from pymc_core.protocol.packet_utils import PathUtils

        header = _make_header(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD)
        # 32 hops × 2 bytes = 64 path bytes (exactly MAX_PATH_SIZE)
        path_len_byte = PathUtils.encode_path_len(hash_size=2, hash_count=32)
        path_data = bytes(MAX_PATH_SIZE)
        wire = bytes([header, path_len_byte]) + path_data + b"ok"
        pkt = Packet()
        pkt.read_from(wire)
        assert pkt.path_len == path_len_byte
        assert len(pkt.path) == MAX_PATH_SIZE
        assert pkt.payload == bytearray(b"ok")


class TestBadPacketSerialization:
    """Verify that write_to rejects internally inconsistent packets."""

    def test_write_mismatched_path_len(self):
        """path_len doesn't match actual path buffer → write_to should reject."""
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, b"test", path=b"\x01\x02")
        pkt.path_len = 5  # lie: says 5, buffer is 2
        with pytest.raises(ValueError, match="path_len mismatch"):
            pkt.write_to()

    def test_write_mismatched_payload_len(self):
        """payload_len doesn't match actual payload buffer → should reject."""
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, b"data")
        pkt.payload_len = 10  # lie: says 10, buffer is 4
        with pytest.raises(ValueError, match="payload_len mismatch"):
            pkt.write_to()

    def test_write_zero_payload_len_with_data(self):
        """payload_len=0 but buffer has data → should reject."""
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, b"data")
        pkt.payload_len = 0
        with pytest.raises(ValueError, match="payload_len mismatch"):
            pkt.write_to()


class TestBadPacketRoutingPath:
    """Verify routing path validation catches bad values."""

    def test_path_not_a_list(self):
        with pytest.raises(ValueError, match="routing_path must be a list"):
            PacketValidationUtils.validate_routing_path("not_a_list")

    def test_path_too_long(self):
        long_path = [0] * (MAX_PATH_SIZE + 1)
        with pytest.raises(ValueError, match="exceeds maximum"):
            PacketValidationUtils.validate_routing_path(long_path)

    def test_path_negative_value(self):
        with pytest.raises(ValueError, match="out of range"):
            PacketValidationUtils.validate_routing_path([-1])

    def test_path_value_above_255(self):
        with pytest.raises(ValueError, match="out of range"):
            PacketValidationUtils.validate_routing_path([256])

    def test_path_invalid_hex_chars(self):
        with pytest.raises(ValueError, match="invalid hex"):
            PacketValidationUtils.validate_routing_path(["ZZ"])

    def test_path_none_element(self):
        with pytest.raises(ValueError, match="invalid type"):
            PacketValidationUtils.validate_routing_path([None])


class TestBadPacketCorruptedWireData:
    """
    Simulate real-world corruption scenarios — bit flips, truncation,
    garbage data — and verify they don't silently produce wrong results.
    """

    def test_random_garbage_rejected_or_benign(self):
        """
        Random bytes should either parse to a valid (but meaningless) packet
        or raise ValueError — never crash with an unhandled exception.
        """
        import random

        rng = random.Random(42)  # deterministic seed
        for _ in range(100):
            length = rng.randint(0, 300)
            garbage = bytes(rng.randint(0, 255) for _ in range(length))
            pkt = Packet()
            try:
                pkt.read_from(garbage)
                # If it parsed, make sure hash doesn't crash
                pkt.calculate_packet_hash()
            except (ValueError, IndexError):
                pass  # Expected for most garbage

    def test_bit_flip_in_header_version(self):
        """Flipping version bits to unsupported version → rejected."""
        payload = b"bit_flip_test"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)
        wire = bytearray(pkt.write_to())
        # Flip bits 6-7 to version 3 (unsupported)
        wire[0] = (wire[0] & 0x3F) | (0x03 << 6)
        pkt2 = Packet()
        with pytest.raises(ValueError, match="Unsupported packet version"):
            pkt2.read_from(bytes(wire))

    def test_truncated_at_every_position(self):
        """Truncating a valid packet at each byte position should raise or parse safely."""
        payload = b"truncation_test"
        path = b"\xAA\xBB\xCC"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, path=path)
        wire = pkt.write_to()

        for cut_pos in range(len(wire)):
            truncated = wire[:cut_pos]
            pkt2 = Packet()
            try:
                pkt2.read_from(truncated)
                # If it parsed with truncated data, payload must be shorter
                assert pkt2.payload_len <= len(payload)
            except (ValueError, IndexError):
                pass  # Expected

    def test_corrupted_path_len_inflated(self):
        """
        Corrupt path_len to be larger than actual data following it.
        Should raise truncated path error.
        """
        payload = b"path_inflate_test"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, path=b"\x01\x02")
        wire = bytearray(pkt.write_to())
        # path_len is at index 1 for FLOOD packets (no transport codes)
        wire[1] = 50  # Claims 50 bytes of path but only 2 exist
        pkt2 = Packet()
        with pytest.raises(ValueError, match="truncated path"):
            pkt2.read_from(bytes(wire))

    def test_corrupted_path_len_zero(self):
        """
        Setting path_len to 0 on a packet that originally had a path
        should parse successfully but path will be empty and payload
        will absorb the original path bytes.
        """
        payload = b"test"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload, path=b"\xAA\xBB")
        wire = bytearray(pkt.write_to())
        wire[1] = 0  # Zero out path_len
        pkt2 = Packet()
        pkt2.read_from(bytes(wire))
        assert pkt2.path_len == 0
        assert len(pkt2.path) == 0
        # Original path bytes are now absorbed into payload
        assert pkt2.payload_len == len(payload) + 2

    def test_transport_flood_with_corrupted_transport_codes(self):
        """
        Transport codes are 4 bytes. Corrupt them and verify the packet
        still parses (transport codes have no validation) but hash is
        unaffected since transport codes aren't in the hash.
        """
        payload = b"transport_corrupt"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_TRANSPORT_FLOOD, payload)
        pkt.transport_codes = [0x1111, 0x2222]
        original_hash = pkt.calculate_packet_hash()

        wire = bytearray(pkt.write_to())
        # Corrupt transport codes at bytes 1-4
        wire[1] = 0xFF
        wire[2] = 0xFF
        wire[3] = 0xFF
        wire[4] = 0xFF

        pkt2 = Packet()
        pkt2.read_from(bytes(wire))
        # Transport codes are corrupted but hash is unaffected
        assert pkt2.calculate_packet_hash() == original_hash
        assert pkt2.transport_codes == [0xFFFF, 0xFFFF]

    def test_header_route_type_flip_changes_wire_format(self):
        """
        Flipping route bits from FLOOD (0x01) to TRANSPORT_FLOOD (0x00)
        means read_from expects 4 transport code bytes that aren't there.
        """
        payload = b"route_flip"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD, payload)
        wire = bytearray(pkt.write_to())
        # Flip route bits: FLOOD (01) → TRANSPORT_FLOOD (00)
        wire[0] = wire[0] & ~0x03  # Clear route bits → 0x00 = TRANSPORT_FLOOD
        pkt2 = Packet()
        # Now it expects 4 transport code bytes that aren't there
        with pytest.raises(ValueError):
            pkt2.read_from(bytes(wire))

    def test_double_deserialize_is_idempotent(self):
        """Deserializing the same wire bytes twice should produce identical results."""
        payload = b"double_deser"
        pkt = _build_packet(PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_DIRECT, payload, path=b"\x42\xAA")
        wire = pkt.write_to()

        pkt1 = Packet()
        pkt1.read_from(wire)

        pkt2 = Packet()
        pkt2.read_from(wire)

        assert pkt1.calculate_packet_hash() == pkt2.calculate_packet_hash()
        assert pkt1.header == pkt2.header
        assert pkt1.path == pkt2.path
        assert pkt1.payload == pkt2.payload

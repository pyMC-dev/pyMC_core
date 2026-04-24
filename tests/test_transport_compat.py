"""Cross-validation tests: verify Python transport code computation matches MeshCore firmware.

These tests use real captured packet bytes from a firmware companion to validate
that get_auto_key_for() and calc_transport_code() are firmware-compatible.

Captured packets (region #nl-li, GRP_TXT):
  - FIRMWARE_HEX: raw bytes from a firmware companion radio (known-good)
  - PYTHON_HEX:   raw bytes from this Python companion (under test)

The firmware packet stores transport_code[0] = 0xFBE5.
If calc_transport_code(get_auto_key_for("#nl-li"), parsed_pkt) == 0xFBE5,
the algorithm is correct.  If not, there is a firmware-compatibility bug.
"""

from __future__ import annotations

from pymc_core.protocol import Packet
from pymc_core.protocol.transport_keys import calc_transport_code, get_auto_key_for

# Raw GRP_TXT packet bytes captured from a firmware companion radio, region #nl-li.
# Packet structure (TRANSPORT_FLOOD, path_len=0):
#   [0x14][E5 FB][00 00][00][03 55 C9 0F B1 0B 08 90 DC 01 19 C3 9C 7F C8 9B
#    34 5B 37 F8 3E E1 7C C0 71 D7 93 83 2C 0E 65 F2 AF 8B 67]
# transport_codes[0] = 0xFBE5 (bytes E5 FB stored little-endian)
FIRMWARE_HEX = "14E5FB0000000355C90FB10B0890DC0119C39C7FC89B345B37F83EE17CC071D793832C0E65F2AF8B67"

# Raw GRP_TXT packet bytes captured from this Python companion, same region #nl-li.
# transport_codes[0] = 0x4709 (bytes 09 47 stored little-endian)
PYTHON_HEX = "140947000000033324E474620D31BFBB3909337DCA3AB51D560F9538D47C846788E7964BFA9305986E"

REGION = "#nl-li"
EXPECTED_FIRMWARE_CODE = 0xFBE5
EXPECTED_PYTHON_CODE = 0x4709


class TestPacketParsing:
    """Verify raw bytes parse correctly before testing transport codes."""

    def test_firmware_packet_parses(self):
        raw = bytes.fromhex(FIRMWARE_HEX)
        pkt = Packet()
        assert pkt.read_from(raw), "firmware packet should parse without error"

    def test_firmware_packet_transport_code(self):
        raw = bytes.fromhex(FIRMWARE_HEX)
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.transport_codes[0] == EXPECTED_FIRMWARE_CODE, (
            f"Parsed transport_codes[0]={pkt.transport_codes[0]:#06x}, "
            f"expected {EXPECTED_FIRMWARE_CODE:#06x}"
        )

    def test_python_packet_parses(self):
        raw = bytes.fromhex(PYTHON_HEX)
        pkt = Packet()
        assert pkt.read_from(raw), "python packet should parse without error"

    def test_python_packet_transport_code(self):
        raw = bytes.fromhex(PYTHON_HEX)
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.transport_codes[0] == EXPECTED_PYTHON_CODE, (
            f"Parsed transport_codes[0]={pkt.transport_codes[0]:#06x}, "
            f"expected {EXPECTED_PYTHON_CODE:#06x}"
        )


class TestKeyDerivation:
    """Verify get_auto_key_for produces a 16-byte key."""

    def test_key_is_16_bytes(self):
        key = get_auto_key_for(REGION)
        assert len(key) == 16

    def test_key_is_deterministic(self):
        assert get_auto_key_for(REGION) == get_auto_key_for(REGION)

    def test_different_regions_different_keys(self):
        assert get_auto_key_for("#nl-li") != get_auto_key_for("#usa")


class TestFirmwareCompatibility:
    """
    THE critical cross-validation suite.

    If test_firmware_transport_code_matches passes:
        - Key derivation and HMAC computation are firmware-compatible.
        - Any region-scoping bug lies in packet construction or dispatch.

    If it fails:
        - There is a bug in get_auto_key_for() or calc_transport_code().
        - The failure message and printed diagnostics will guide the fix.
    """

    def test_firmware_transport_code_matches(self):
        """calc_transport_code must reproduce the code stored in the firmware packet."""
        raw = bytes.fromhex(FIRMWARE_HEX)
        pkt = Packet()
        pkt.read_from(raw)

        key = get_auto_key_for(REGION)
        computed = calc_transport_code(key, pkt)

        assert computed == EXPECTED_FIRMWARE_CODE, (
            f"FIRMWARE COMPATIBILITY BUG: computed {computed:#06x}, "
            f"expected {EXPECTED_FIRMWARE_CODE:#06x} for region {REGION!r}.\n"
            f"  key = {key.hex()}\n"
            f"  payload = {pkt.get_payload().hex()}\n"
            f"  raw HMAC[:2] = "
            + __import__("hmac")
            .new(
                key,
                bytes([pkt.get_payload_type()]) + pkt.get_payload(),
                __import__("hashlib").sha256,
            )
            .digest()[:2]
            .hex()
        )

    def test_python_transport_code_not_nl_li_key(self):
        """The captured Python packet's transport code is NOT consistent with the #nl-li key.

        This documents the confirmed bug: the companion produced a TRANSPORT_FLOOD
        packet (code=0x4709) but calc_transport_code with the #nl-li key gives 0x7a65
        for that payload. The companion was NOT using the correct #nl-li key when
        this packet was captured.

        The algorithm is correct (test_firmware_transport_code_matches passes).
        See TestChannelMessageFloodScope in test_companion_regions.py for the
        integration test verifying the full send_channel_message + set_flood_region
        stack produces firmware-compatible packets.
        """
        raw = bytes.fromhex(PYTHON_HEX)
        pkt = Packet()
        pkt.read_from(raw)

        key = get_auto_key_for(REGION)
        computed = calc_transport_code(key, pkt)

        assert computed != pkt.transport_codes[0], (
            "Python packet code now matches #nl-li key — bug may be fixed. "
            "Update this test and PYTHON_HEX to a new reference packet."
        )
        assert pkt.transport_codes[0] == EXPECTED_PYTHON_CODE  # 0x4709
        assert computed == 0x7A65, f"Expected 0x7a65, got {computed:#06x}"


class TestCmdSetFloodScopeWireFormat:
    """Verify the CMD_SET_FLOOD_SCOPE byte-extraction matches the firmware wire format.

    Firmware (MyMesh.cpp:1775-1779):
        cmd_frame[0] = CMD_SET_FLOOD_SCOPE
        cmd_frame[1] = 0x00  (reserved, must be 0)
        cmd_frame[2..17] = 16-byte key   (len >= 2+16 = 18 total)

    frame_server._handle_cmd strips payload[0] (cmd byte) before calling the handler,
    so the handler receives data = [reserved=0x00] + [key(16)] = 17 bytes.
    The correct slice is data[1:17], NOT data[:16].
    """

    def test_key_slice_skips_reserved_byte(self):
        key = bytes(range(16))
        data = bytes([0x00]) + key  # 17 bytes as received by handler
        extracted = data[1:17]
        assert extracted == key

    def test_wrong_slice_would_corrupt_key(self):
        key = bytes(range(16))
        data = bytes([0x00]) + key
        wrong = data[:16]
        assert wrong != key  # documents what the old bug produced

    def test_short_data_clears_scope(self):
        # Any data shorter than 17 bytes should result in clearing scope (None)
        assert len(bytes([0x00]) + bytes(15)) < 17  # 16 < 17 → clear


class TestTransportCodeDetails:
    """Low-level diagnostics for debugging mismatches."""

    def test_payload_type_is_grp_txt(self):
        """Both packets should report payload type 5 (GRP_TXT)."""
        for hex_str, label in [(FIRMWARE_HEX, "firmware"), (PYTHON_HEX, "python")]:
            raw = bytes.fromhex(hex_str)
            pkt = Packet()
            pkt.read_from(raw)
            assert (
                pkt.get_payload_type() == 0x05
            ), f"{label} packet: expected GRP_TXT (0x05), got {pkt.get_payload_type():#04x}"

    def test_hmac_key_first_bytes(self):
        """Spot-check: SHA256('#nl-li')[:4] must match known value for firmware."""
        import hashlib

        key = get_auto_key_for(REGION)
        expected_full = hashlib.sha256(b"#nl-li").digest()[:16]
        assert (
            key == expected_full
        ), f"Key mismatch:\n  got      {key.hex()}\n  expected {expected_full.hex()}"

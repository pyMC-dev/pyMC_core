"""
Tests for MeshCore KISS Modem Wrapper

Tests the KISS frame encoding/decoding, command/response handling,
and LoRaRadio interface implementation.
"""

import struct
import threading
from unittest.mock import MagicMock, patch

import pytest

from pymc_core.hardware.kiss_modem_wrapper import (
    CMD_DATA,
    CMD_ENCRYPT_DATA,
    CMD_GET_AIRTIME,
    CMD_GET_BATTERY,
    CMD_GET_IDENTITY,
    CMD_GET_NOISE_FLOOR,
    CMD_GET_RADIO,
    CMD_GET_RANDOM,
    CMD_GET_STATS,
    CMD_GET_TX_POWER,
    CMD_GET_VERSION,
    CMD_HASH,
    CMD_KEY_EXCHANGE,
    CMD_PING,
    CMD_SET_RADIO,
    CMD_SET_TX_POWER,
    CMD_SIGN_DATA,
    CMD_VERIFY_SIGNATURE,
    HW_CMD_GET_DEVICE_NAME,
    HW_CMD_GET_MCU_TEMP,
    HW_CMD_GET_SIGNAL_REPORT,
    HW_CMD_GET_VERSION,
    HW_CMD_REBOOT,
    HW_CMD_SET_SIGNAL_REPORT,
    HW_RESP_DEVICE_NAME,
    HW_RESP_MCU_TEMP,
    HW_RESP_OK,
    HW_RESP_SIGNAL_REPORT,
    KISS_CMD_FULLDUPLEX,
    KISS_CMD_PERSISTENCE,
    KISS_CMD_SETHARDWARE,
    KISS_CMD_SLOTTIME,
    KISS_CMD_TXTAIL,
    KISS_FEND,
    KISS_FESC,
    KISS_TFEND,
    KISS_TFESC,
    RESP_AIRTIME,
    RESP_BATTERY,
    RESP_ENCRYPTED,
    RESP_ERROR,
    RESP_HASH,
    RESP_IDENTITY,
    RESP_NOISE_FLOOR,
    RESP_OK,
    RESP_PONG,
    RESP_RADIO,
    RESP_RANDOM,
    RESP_SHARED_SECRET,
    RESP_SIGNATURE,
    RESP_STATS,
    RESP_TX_DONE,
    RESP_TX_POWER,
    RESP_VERIFY,
    RESP_VERSION,
    HW_RESP_RX_META,
    KissModemWrapper,
)


class TestKissFrameEncoding:
    """Test KISS frame encoding/decoding"""

    def test_encode_simple_frame(self):
        """Test encoding a simple frame without special characters"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        frame = modem._encode_kiss_frame(CMD_DATA, b"\x01\x02\x03")

        # Should be: FEND + CMD + data + FEND
        assert frame[0] == KISS_FEND
        assert frame[1] == CMD_DATA
        assert frame[2:5] == b"\x01\x02\x03"
        assert frame[5] == KISS_FEND

    def test_encode_frame_with_fend_escape(self):
        """Test encoding a frame containing FEND byte"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        frame = modem._encode_kiss_frame(CMD_DATA, bytes([0xC0]))  # FEND

        # FEND in data should be escaped as FESC + TFEND
        assert frame[0] == KISS_FEND
        assert frame[1] == CMD_DATA
        assert frame[2] == KISS_FESC
        assert frame[3] == KISS_TFEND
        assert frame[4] == KISS_FEND

    def test_encode_frame_with_fesc_escape(self):
        """Test encoding a frame containing FESC byte"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        frame = modem._encode_kiss_frame(CMD_DATA, bytes([0xDB]))  # FESC

        # FESC in data should be escaped as FESC + TFESC
        assert frame[0] == KISS_FEND
        assert frame[1] == CMD_DATA
        assert frame[2] == KISS_FESC
        assert frame[3] == KISS_TFESC
        assert frame[4] == KISS_FEND

    def test_encode_frame_with_multiple_escapes(self):
        """Test encoding a frame with multiple special characters"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        frame = modem._encode_kiss_frame(CMD_DATA, bytes([0xC0, 0xDB, 0xC0]))

        expected = bytes(
            [
                KISS_FEND,
                CMD_DATA,
                KISS_FESC,
                KISS_TFEND,  # escaped 0xC0
                KISS_FESC,
                KISS_TFESC,  # escaped 0xDB
                KISS_FESC,
                KISS_TFEND,  # escaped 0xC0
                KISS_FEND,
            ]
        )
        assert frame == expected

    def test_decode_simple_frame(self):
        """Test decoding Data frame then RxMeta (spec: data and metadata separate)"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received_frames = []
        modem.on_frame_received = lambda data: received_frames.append(data)

        # Data frame: FEND + 0x00 + raw_packet + FEND (no in-frame metadata)
        data_frame = bytes([KISS_FEND, CMD_DATA, 0x01, 0x02, 0x03, KISS_FEND])
        # RxMeta: FEND + 0x06 + 0xF9 + SNR + RSSI + FEND (sent immediately after Data)
        rx_meta_frame = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND])

        for byte in data_frame:
            modem._decode_kiss_byte(byte)
        for byte in rx_meta_frame:
            modem._decode_kiss_byte(byte)

        assert len(received_frames) == 1
        assert received_frames[0] == b"\x01\x02\x03"

    def test_decode_frame_with_escapes(self):
        """Test decoding Data frame with escaped FEND, then RxMeta"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received_frames = []
        modem.on_frame_received = lambda data: received_frames.append(data)

        # Data frame: payload is escaped 0xC0 (FESC + TFEND)
        data_frame = bytes(
            [KISS_FEND, CMD_DATA, KISS_FESC, KISS_TFEND, KISS_FEND]
        )
        rx_meta_frame = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND])

        for byte in data_frame:
            modem._decode_kiss_byte(byte)
        for byte in rx_meta_frame:
            modem._decode_kiss_byte(byte)

        assert len(received_frames) == 1
        assert received_frames[0] == bytes([0xC0])

    def test_decode_extracts_rssi_snr(self):
        """Test that RSSI and SNR are extracted from RxMeta frame"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        data_frame = bytes([KISS_FEND, CMD_DATA, 0xAA, 0xBB, KISS_FEND])
        # RxMeta: SNR=0x10 (4.0 dB), RSSI=0xB0 (-80)
        rx_meta_frame = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND])

        for byte in data_frame:
            modem._decode_kiss_byte(byte)
        for byte in rx_meta_frame:
            modem._decode_kiss_byte(byte)

        assert modem.stats["last_snr"] == pytest.approx(4.0)
        assert modem.stats["last_rssi"] == -80

    def test_rx_callback_receives_per_packet_rssi_snr(self):
        """Test that a 3-arg callback receives (data, rssi, snr) per Data+RxMeta pair"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        def capture(data, rssi, snr):
            received.append((data, rssi, snr))

        modem.on_frame_received = capture

        # First packet: Data then RxMeta (SNR=4.0 dB, RSSI=-80)
        data1 = bytes([KISS_FEND, CMD_DATA, 0x01, 0x02, KISS_FEND])
        meta1 = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND])
        for byte in data1:
            modem._decode_kiss_byte(byte)
        for byte in meta1:
            modem._decode_kiss_byte(byte)

        # Second packet: Data then RxMeta (SNR=2.0 dB, RSSI=-100)
        data2 = bytes([KISS_FEND, CMD_DATA, 0x03, 0x04, KISS_FEND])
        meta2 = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x08, 0x9C, KISS_FEND])
        for byte in data2:
            modem._decode_kiss_byte(byte)
        for byte in meta2:
            modem._decode_kiss_byte(byte)

        assert len(received) == 2
        assert received[0] == (b"\x01\x02", -80, 4.0)
        assert received[1] == (b"\x03\x04", -100, 2.0)

    def test_data_frame_without_rx_meta_does_not_call_callback(self):
        """Spec: Data frame queues payload; callback only on following RxMeta"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda data: received.append(data)

        # Only Data frame, no RxMeta
        data_frame = bytes([KISS_FEND, CMD_DATA, 0x01, 0x02, 0x03, KISS_FEND])
        for byte in data_frame:
            modem._decode_kiss_byte(byte)

        assert len(received) == 0
        assert len(modem._pending_rx_queue) == 1
        assert modem._pending_rx_queue[0] == b"\x01\x02\x03"

    def test_port_non_zero_discarded(self):
        """Frames with port != 0 are ignored (type byte 0x10 = port 1, cmd 0)"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda data: received.append(data)

        # Type 0x10: port=1, cmd=0 (Data on port 1) - should be discarded
        frame = bytes([KISS_FEND, 0x10, 0x01, 0x02, 0x03, KISS_FEND])
        for byte in frame:
            modem._decode_kiss_byte(byte)

        assert len(received) == 0
        assert len(modem._pending_rx_queue) == 0


class TestCommandResponses:
    """Test command sending and response parsing"""

    def test_send_command_encodes_correctly(self):
        """Test that _send_command sends SetHardware frame (FEND + 0x06 + sub_cmd + data + FEND)"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        mock_serial = MagicMock()
        mock_serial.is_open = True
        modem.serial_conn = mock_serial
        modem.is_connected = True

        modem._send_command(CMD_GET_VERSION, timeout=0.1)

        assert mock_serial.write.called
        written_frame = mock_serial.write.call_args[0][0]

        assert written_frame[0] == KISS_FEND
        assert written_frame[1] == KISS_CMD_SETHARDWARE  # type SetHardware
        assert written_frame[2] == HW_CMD_GET_VERSION     # sub_cmd GetVersion
        assert written_frame[-1] == KISS_FEND

    def test_response_parsing_identity(self):
        """Test parsing SetHardware Identity response (FEND + 0x06 + 0x21 + pubkey + FEND)"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        pubkey = bytes(range(32))
        raw_bytes = (
            bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_IDENTITY]) + pubkey + bytes([KISS_FEND])
        )

        modem._response_event = threading.Event()
        modem._pending_response = None

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert modem._pending_response is not None
        assert modem._pending_response[0] == RESP_IDENTITY
        assert modem._pending_response[1] == pubkey

    def test_response_parsing_error(self):
        """Test parsing SetHardware Error response (FEND + 0x06 + 0x2A + code + FEND)"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        raw_bytes = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_ERROR, 0x05, KISS_FEND])

        modem._response_event = threading.Event()
        modem._pending_response = None

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert modem._pending_response is not None
        assert modem._pending_response[0] == RESP_ERROR
        assert modem._pending_response[1][0] == 0x05

    def test_tx_done_response(self):
        """Test SetHardware TxDone (0xF8) response sets event"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._tx_done_event = threading.Event()

        raw_bytes = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_TX_DONE, 0x01, KISS_FEND])

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert modem._tx_done_event.is_set()
        assert modem._tx_done_result is True


class TestRadioConfiguration:
    """Test radio configuration encoding"""

    def test_radio_config_struct_format(self):
        """Test that radio config is packed correctly"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        freq_hz = 869618000
        bw_hz = 62500
        sf = 8
        cr = 8

        # This is what configure_radio should pack
        expected = struct.pack("<IIBB", freq_hz, bw_hz, sf, cr)

        assert len(expected) == 10
        # Verify unpacking
        unpacked = struct.unpack("<IIBB", expected)
        assert unpacked == (freq_hz, bw_hz, sf, cr)

    def test_configure_radio_sends_correct_commands(self):
        """Test that configure_radio sends SET_RADIO and SET_TX_POWER"""
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            radio_config={
                "frequency": 869618000,
                "bandwidth": 62500,
                "spreading_factor": 8,
                "coding_rate": 8,
                "power": 22,
            },
        )

        # Track sent commands
        sent_commands = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent_commands.append((cmd, data))
            return (RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True

        result = modem.configure_radio()

        assert result is True
        assert len(sent_commands) == 2

        # First command: SET_RADIO
        assert sent_commands[0][0] == CMD_SET_RADIO
        assert len(sent_commands[0][1]) == 10  # 4 + 4 + 1 + 1

        # Second command: SET_TX_POWER
        assert sent_commands[1][0] == CMD_SET_TX_POWER
        assert sent_commands[1][1] == bytes([22])


class TestCryptoOperations:
    """Test cryptographic operation methods"""

    def test_get_random_validates_length(self):
        """Test get_random validates length parameter"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Length too small
        assert modem.get_random(0) is None

        # Length too large
        assert modem.get_random(65) is None

    def test_sign_data_sends_correct_command(self):
        """Test sign_data sends correct command"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        signature = bytes(range(64))

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_SIGN_DATA:
                return (RESP_SIGNATURE, signature)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        result = modem.sign_data(b"test data")
        assert result == signature

    def test_verify_signature_validates_lengths(self):
        """Test verify_signature validates input lengths"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Invalid pubkey length
        assert modem.verify_signature(b"short", bytes(64), b"data") is None

        # Invalid signature length
        assert modem.verify_signature(bytes(32), b"short", b"data") is None

    def test_encrypt_data_validates_key_length(self):
        """Test encrypt_data validates key length"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Invalid key length
        assert modem.encrypt_data(b"short_key", b"plaintext") is None

    def test_decrypt_data_validates_lengths(self):
        """Test decrypt_data validates input lengths"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Invalid key length
        assert modem.decrypt_data(b"short", bytes(2), b"ciphertext") is None

        # Invalid MAC length
        assert modem.decrypt_data(bytes(32), b"x", b"ciphertext") is None

    def test_key_exchange_validates_pubkey_length(self):
        """Test key_exchange validates pubkey length"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        assert modem.key_exchange(b"short_pubkey") is None


class TestLoRaRadioInterface:
    """Test LoRaRadio interface implementation"""

    def test_set_rx_callback(self):
        """Test setting RX callback"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        callback = MagicMock()
        modem.set_rx_callback(callback)

        assert modem.on_frame_received == callback

    def test_get_last_rssi(self):
        """Test get_last_rssi returns stats value"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.stats["last_rssi"] = -85

        assert modem.get_last_rssi() == -85

    def test_get_last_snr(self):
        """Test get_last_snr returns stats value"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.stats["last_snr"] = 7.5

        assert modem.get_last_snr() == 7.5

    def test_get_stats_returns_copy(self):
        """Test get_stats returns a copy of stats dict"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.stats["frames_sent"] = 100

        stats = modem.get_stats()
        stats["frames_sent"] = 999

        # Original should be unchanged
        assert modem.stats["frames_sent"] == 100


class TestSendFrame:
    """Test send_frame functionality"""

    def test_send_frame_validates_size(self):
        """Test send_frame validates packet size"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Too small (< 2 bytes)
        assert modem.send_frame(b"\x00") is False

        # Too large (> 255 bytes)
        assert modem.send_frame(bytes(256)) is False

    def test_send_frame_requires_connection(self):
        """Test send_frame requires connection"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = False

        assert modem.send_frame(b"\x00\x01") is False

    def test_send_frame_queues_to_buffer(self):
        """Test send_frame adds to TX buffer"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        assert len(modem.tx_buffer) == 0

        result = modem.send_frame(b"\x01\x02\x03")

        assert result is True
        assert len(modem.tx_buffer) == 1

        # Verify frame is properly encoded
        frame = modem.tx_buffer[0]
        assert frame[0] == KISS_FEND
        assert frame[1] == CMD_DATA
        assert frame[-1] == KISS_FEND


class TestQueryMethods:
    """Test modem query methods"""

    def test_get_radio_config_parses_response(self):
        """Test get_radio_config parses response correctly"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        freq = 869618000
        bw = 62500
        sf = 8
        cr = 8
        response_data = struct.pack("<IIBB", freq, bw, sf, cr)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_GET_RADIO:
                return (RESP_RADIO, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        config = modem.get_radio_config()

        assert config["frequency"] == freq
        assert config["bandwidth"] == bw
        assert config["spreading_factor"] == sf
        assert config["coding_rate"] == cr

    def test_get_modem_stats_parses_response(self):
        """Test get_modem_stats parses response correctly"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        rx = 100
        tx = 50
        errors = 5
        response_data = struct.pack("<III", rx, tx, errors)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_GET_STATS:
                return (RESP_STATS, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        stats = modem.get_modem_stats()

        assert stats["rx"] == rx
        assert stats["tx"] == tx
        assert stats["errors"] == errors

    def test_get_battery_parses_response(self):
        """Test get_battery parses millivolt response"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        millivolts = 3700
        response_data = struct.pack("<H", millivolts)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_GET_BATTERY:
                return (RESP_BATTERY, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        result = modem.get_battery()
        assert result == millivolts

    def test_ping_returns_true_on_pong(self):
        """Test ping returns True when modem responds with PONG"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_PING:
                return (RESP_PONG, b"")
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.ping() is True

    def test_ping_returns_false_on_timeout(self):
        """Test ping returns False on timeout"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            return None  # Simulate timeout

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.ping() is False

    def test_get_mcu_temp_parses_response(self):
        """Test get_mcu_temp parses signed int16 tenths of °C"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        # 253 tenths = 25.3 °C
        response_data = struct.pack("<h", 253)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_MCU_TEMP:
                return (HW_RESP_MCU_TEMP, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_mcu_temp() == pytest.approx(25.3)

    def test_get_mcu_temp_returns_none_on_no_callback_error(self):
        """Test get_mcu_temp returns None when modem returns NoCallback error"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_MCU_TEMP:
                return (RESP_ERROR, bytes([0x03]))  # HW_ERR_NO_CALLBACK
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_mcu_temp() is None

    def test_get_device_name_parses_utf8(self):
        """Test get_device_name returns UTF-8 decoded string"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        name = "TestDevice"
        response_data = name.encode("utf-8")

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_DEVICE_NAME:
                return (HW_RESP_DEVICE_NAME, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_device_name() == "TestDevice"

    def test_reboot_sends_command(self):
        """Test reboot sends HW_CMD_REBOOT SetHardware command"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        sent = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent.append((cmd, data))
            return (HW_RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True

        modem.reboot()

        assert len(sent) == 1
        assert sent[0][0] == HW_CMD_REBOOT
        assert sent[0][1] == b""


class TestEventLoop:
    """Test event loop integration for thread-safe async"""

    def test_set_event_loop(self):
        """Test setting event loop"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        loop = MagicMock()

        modem.set_event_loop(loop)

        assert modem._event_loop is loop

    def test_dispatch_uses_event_loop_when_set(self):
        """Test that dispatch uses call_soon_threadsafe when loop is set"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        loop = MagicMock()
        modem.set_event_loop(loop)

        callback = MagicMock()
        modem.on_frame_received = callback

        modem._dispatch_rx_callback(b"test", -80, 4.0)

        # Should have called call_soon_threadsafe
        loop.call_soon_threadsafe.assert_called_once()

    def test_dispatch_direct_when_no_event_loop(self):
        """Test that dispatch invokes callback directly when no loop set"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []

        def callback(data, rssi, snr):
            received.append((data, rssi, snr))

        modem.on_frame_received = callback

        modem._dispatch_rx_callback(b"test", -80, 4.0)

        assert len(received) == 1
        assert received[0] == (b"test", -80, 4.0)


class TestRadioConfigCompatibility:
    """Test radio config key compatibility"""

    def test_power_key(self):
        """Test that 'power' key is used"""
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            radio_config={"power": 15},
        )

        sent_commands = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent_commands.append((cmd, data))
            return (RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True

        modem.configure_radio()

        # Find SET_TX_POWER command
        tx_power_cmd = next((c for c in sent_commands if c[0] == CMD_SET_TX_POWER), None)
        assert tx_power_cmd is not None
        assert tx_power_cmd[1] == bytes([15])

    def test_tx_power_key_fallback(self):
        """Test that 'tx_power' key is used when 'power' is not present"""
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            radio_config={"tx_power": 20},
        )

        sent_commands = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent_commands.append((cmd, data))
            return (RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True

        modem.configure_radio()

        # Find SET_TX_POWER command
        tx_power_cmd = next((c for c in sent_commands if c[0] == CMD_SET_TX_POWER), None)
        assert tx_power_cmd is not None
        assert tx_power_cmd[1] == bytes([20])

    def test_power_takes_precedence_over_tx_power(self):
        """Test that 'power' takes precedence over 'tx_power'"""
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            radio_config={"power": 10, "tx_power": 20},
        )

        sent_commands = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent_commands.append((cmd, data))
            return (RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True

        modem.configure_radio()

        # Find SET_TX_POWER command - should use 'power' value
        tx_power_cmd = next((c for c in sent_commands if c[0] == CMD_SET_TX_POWER), None)
        assert tx_power_cmd is not None
        assert tx_power_cmd[1] == bytes([10])


class TestKissTuningMethods:
    """Test KISS config commands: persistence, slottime, txtail, full_duplex, signal report"""

    def test_set_kiss_persistence_sends_correct_frame(self):
        """Test set_kiss_persistence sends KISS_CMD_PERSISTENCE with value 0-255"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        result = modem.set_kiss_persistence(63)
        assert result is True
        assert len(written) == 1
        # FEND + 0x02 + 0x3F + FEND
        assert written[0][0] == KISS_FEND
        assert written[0][1] == KISS_CMD_PERSISTENCE
        assert written[0][2] == 63
        assert written[0][3] == KISS_FEND

    def test_set_kiss_persistence_clamps_value(self):
        """Test set_kiss_persistence clamps to 0-255"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        modem.set_kiss_persistence(300)
        assert written[0][2] == 255
        written.clear()
        modem.set_kiss_persistence(-1)
        assert written[0][2] == 0

    def test_set_kiss_slottime_sends_correct_frame(self):
        """Test set_kiss_slottime sends KISS_CMD_SLOTTIME with value in 10ms units"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        result = modem.set_kiss_slottime(100)
        assert result is True
        assert len(written) == 1
        assert written[0][0] == KISS_FEND
        assert written[0][1] == KISS_CMD_SLOTTIME
        assert written[0][2] == 10  # 100ms / 10
        assert written[0][3] == KISS_FEND

    def test_set_kiss_txtail_sends_correct_frame(self):
        """Test set_kiss_txtail sends KISS_CMD_TXTAIL with value in 10ms units"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        result = modem.set_kiss_txtail(50)
        assert result is True
        assert written[0][1] == KISS_CMD_TXTAIL
        assert written[0][2] == 5  # 50ms / 10

    def test_set_kiss_full_duplex_sends_correct_frame(self):
        """Test set_kiss_full_duplex sends KISS_CMD_FULLDUPLEX 0x01 or 0x00"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        modem.set_kiss_full_duplex(True)
        assert written[0][1] == KISS_CMD_FULLDUPLEX
        assert written[0][2] == 0x01
        written.clear()
        modem.set_kiss_full_duplex(False)
        assert written[0][2] == 0x00

    def test_set_signal_report_returns_true_on_ok_response(self):
        """Test set_signal_report returns True when modem responds OK or SignalReport"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_SET_SIGNAL_REPORT:
                return (HW_RESP_SIGNAL_REPORT, bytes([0x01]))
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.set_signal_report(True) is True
        assert modem.set_signal_report(False) is True

    def test_set_signal_report_returns_true_on_ok(self):
        """Test set_signal_report returns True when modem responds HW_RESP_OK"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_SET_SIGNAL_REPORT:
                return (HW_RESP_OK, b"")
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.set_signal_report(True) is True

    def test_set_signal_report_returns_false_on_error_or_timeout(self):
        """Test set_signal_report returns False on error or timeout"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.set_signal_report(True) is False

    def test_get_signal_report_returns_true_when_enabled(self):
        """Test get_signal_report returns True when modem reports enabled"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_SIGNAL_REPORT:
                return (HW_RESP_SIGNAL_REPORT, bytes([0x01]))
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_signal_report() is True

    def test_get_signal_report_returns_false_when_disabled(self):
        """Test get_signal_report returns False when modem reports disabled"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_SIGNAL_REPORT:
                return (HW_RESP_SIGNAL_REPORT, bytes([0x00]))
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_signal_report() is False

    def test_get_signal_report_returns_none_on_timeout(self):
        """Test get_signal_report returns None on timeout or error"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_signal_report() is None


class TestContextManager:
    """Test context manager functionality"""

    def test_context_manager_calls_connect_disconnect(self):
        """Test context manager calls connect and disconnect"""
        with patch.object(KissModemWrapper, "connect", return_value=True) as mock_connect:
            with patch.object(KissModemWrapper, "disconnect") as mock_disconnect:
                with KissModemWrapper(port="/dev/null", auto_configure=False) as modem:
                    pass

                mock_connect.assert_called_once()
                mock_disconnect.assert_called_once()

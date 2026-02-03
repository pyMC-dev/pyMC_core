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
        """Test decoding a simple frame"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received_frames = []
        modem.on_frame_received = lambda data: received_frames.append(data)

        # Simulate receiving: FEND + CMD_DATA + SNR + RSSI + payload + FEND
        raw_bytes = bytes([KISS_FEND, CMD_DATA, 0x10, 0xB0, 0x01, 0x02, 0x03, KISS_FEND])

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert len(received_frames) == 1
        assert received_frames[0] == b"\x01\x02\x03"  # payload without SNR/RSSI

    def test_decode_frame_with_escapes(self):
        """Test decoding a frame with escaped characters"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received_frames = []
        modem.on_frame_received = lambda data: received_frames.append(data)

        # Frame with escaped FEND (0xC0) in payload
        # SNR=0x10, RSSI=0xB0, payload contains 0xC0 escaped
        raw_bytes = bytes(
            [
                KISS_FEND,
                CMD_DATA,
                0x10,
                0xB0,  # SNR, RSSI
                KISS_FESC,
                KISS_TFEND,  # escaped 0xC0
                KISS_FEND,
            ]
        )

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert len(received_frames) == 1
        assert received_frames[0] == bytes([0xC0])

    def test_decode_extracts_rssi_snr(self):
        """Test that RSSI and SNR are extracted from received frames"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # SNR = 0x10 (4.0 dB when divided by 4)
        # RSSI = 0xB0 (-80 dBm as signed byte)
        raw_bytes = bytes([KISS_FEND, CMD_DATA, 0x10, 0xB0, 0xAA, 0xBB, KISS_FEND])

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert modem.stats["last_snr"] == pytest.approx(4.0)
        assert modem.stats["last_rssi"] == -80


class TestCommandResponses:
    """Test command sending and response parsing"""

    def test_send_command_encodes_correctly(self):
        """Test that _send_command creates correct KISS frame"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        # Mock serial connection
        mock_serial = MagicMock()
        mock_serial.is_open = True
        modem.serial_conn = mock_serial
        modem.is_connected = True

        # Send command with short timeout (will timeout since no response)
        modem._send_command(CMD_GET_VERSION, timeout=0.1)

        # Verify frame was written
        assert mock_serial.write.called
        written_frame = mock_serial.write.call_args[0][0]

        assert written_frame[0] == KISS_FEND
        assert written_frame[1] == CMD_GET_VERSION
        assert written_frame[-1] == KISS_FEND

    def test_response_parsing_identity(self):
        """Test parsing identity response"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Simulate response: RESP_IDENTITY + 32 bytes pubkey
        pubkey = bytes(range(32))
        raw_bytes = bytes([KISS_FEND, RESP_IDENTITY]) + pubkey + bytes([KISS_FEND])

        # Set up response capture
        modem._response_event = threading.Event()
        modem._pending_response = None

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert modem._pending_response is not None
        assert modem._pending_response[0] == RESP_IDENTITY
        assert modem._pending_response[1] == pubkey

    def test_response_parsing_error(self):
        """Test parsing error response"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Simulate error response
        raw_bytes = bytes([KISS_FEND, RESP_ERROR, 0x05, KISS_FEND])  # ERR_UNKNOWN_CMD

        modem._response_event = threading.Event()
        modem._pending_response = None

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert modem._pending_response is not None
        assert modem._pending_response[0] == RESP_ERROR
        assert modem._pending_response[1][0] == 0x05

    def test_tx_done_response(self):
        """Test TX done response sets event"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._tx_done_event = threading.Event()

        # Simulate TX done success
        raw_bytes = bytes([KISS_FEND, RESP_TX_DONE, 0x01, KISS_FEND])

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

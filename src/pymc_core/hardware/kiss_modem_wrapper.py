"""
MeshCore KISS Modem Protocol Wrapper

Implements the MeshCore KISS modem protocol for sending/receiving
MeshCore packets over LoRa and cryptographic operations.

Protocol reference: https://github.com/meshcore-dev/MeshCore
"""

import asyncio
import inspect
import logging
import struct
import threading
from collections import deque
from typing import Any, Callable, Dict, Optional, Union

# RX callback: (data) for backward compat, or (data, rssi, snr) for per-packet metrics
RxCallback = Union[
    Callable[[bytes], None],
    Callable[[bytes, Optional[int], Optional[float]], None],
]


def _invoke_rx_callback(
    callback: RxCallback,
    data: bytes,
    rssi: int,
    snr: float,
) -> None:
    """Invoke RX callback with 1 or 3 args depending on what it accepts."""
    try:
        sig = inspect.signature(callback)
        nparams = len([p for p in sig.parameters if p != "self"])
    except (ValueError, TypeError):
        nparams = 1
    if nparams >= 3:
        callback(data, rssi, snr)
    else:
        callback(data)

import serial

from .base import LoRaRadio

# KISS Protocol Constants (shared with standard KISS)
KISS_FEND = 0xC0  # Frame End
KISS_FESC = 0xDB  # Frame Escape
KISS_TFEND = 0xDC  # Transposed Frame End
KISS_TFESC = 0xDD  # Transposed Frame Escape

# MeshCore KISS Modem Request Commands (Host -> Modem)
# Based on actual KissModem.cpp implementation
CMD_DATA = 0x00
CMD_GET_IDENTITY = 0x01
CMD_GET_RANDOM = 0x02
CMD_VERIFY_SIGNATURE = 0x03
CMD_SIGN_DATA = 0x04
CMD_ENCRYPT_DATA = 0x05
CMD_DECRYPT_DATA = 0x06
CMD_KEY_EXCHANGE = 0x07
CMD_HASH = 0x08
CMD_SET_RADIO = 0x09
CMD_SET_TX_POWER = 0x0A
CMD_GET_RADIO = 0x0B
CMD_GET_TX_POWER = 0x0C
CMD_GET_VERSION = 0x0D
CMD_GET_CURRENT_RSSI = 0x0E
CMD_IS_CHANNEL_BUSY = 0x0F
CMD_GET_AIRTIME = 0x10
CMD_GET_NOISE_FLOOR = 0x11
CMD_GET_STATS = 0x12
CMD_GET_BATTERY = 0x13
CMD_PING = 0x14
CMD_GET_SENSORS = 0x15

# MeshCore KISS Modem Response Commands (Modem -> Host)
RESP_IDENTITY = 0x21
RESP_RANDOM = 0x22
RESP_VERIFY = 0x23
RESP_SIGNATURE = 0x24
RESP_ENCRYPTED = 0x25
RESP_DECRYPTED = 0x26
RESP_SHARED_SECRET = 0x27
RESP_HASH = 0x28
RESP_OK = 0x29
RESP_RADIO = 0x2A
RESP_TX_POWER = 0x2B
RESP_VERSION = 0x2C
RESP_ERROR = 0x2D
RESP_TX_DONE = 0x2E
RESP_CURRENT_RSSI = 0x2F
RESP_CHANNEL_BUSY = 0x30
RESP_AIRTIME = 0x31
RESP_NOISE_FLOOR = 0x32
RESP_STATS = 0x33
RESP_BATTERY = 0x34
RESP_PONG = 0x35
RESP_SENSORS = 0x36

# Error Codes
ERR_INVALID_LENGTH = 0x01
ERR_INVALID_PARAM = 0x02
ERR_NO_CALLBACK = 0x03
ERR_MAC_FAILED = 0x04
ERR_UNKNOWN_CMD = 0x05
ERR_ENCRYPT_FAILED = 0x06
ERR_TX_PENDING = 0x07

# Buffer and timing constants
MAX_FRAME_SIZE = 512
RX_BUFFER_SIZE = 1024
TX_BUFFER_SIZE = 1024
DEFAULT_BAUDRATE = 115200
DEFAULT_TIMEOUT = 1.0
RESPONSE_TIMEOUT = 5.0  # Timeout for command responses

logger = logging.getLogger("KissModemWrapper")


class KissModemWrapper(LoRaRadio):
    """
    MeshCore KISS Modem Protocol Interface

    Provides full-duplex KISS protocol communication with MeshCore modem firmware.
    Supports packet transmission/reception, radio configuration, and cryptographic
    operations via the modem's identity.

    Implements the LoRaRadio interface for PyMC Core compatibility.

    Threading Model:
        This wrapper uses background threads for serial RX/TX. The RX callback
        (on_frame_received) is invoked from the RX thread by default. For async
        applications, call set_event_loop() to have callbacks scheduled onto
        the event loop via call_soon_threadsafe().

    RX Callback Signature:
        The callback may accept either:
        - (data: bytes) - backward compatible, single argument
        - (data: bytes, rssi: int, snr: float) - per-packet signal metrics

        When using the 3-argument form, rssi and snr are the values for that
        specific packet, avoiding race conditions with get_last_rssi/get_last_snr.
    """

    def __init__(
        self,
        port: str,
        baudrate: int = DEFAULT_BAUDRATE,
        timeout: float = DEFAULT_TIMEOUT,
        on_frame_received: Optional[RxCallback] = None,
        radio_config: Optional[Dict[str, Any]] = None,
        auto_configure: bool = True,
    ):
        """
        Initialize MeshCore KISS Modem Wrapper

        Args:
            port: Serial port device path (e.g., '/dev/ttyUSB0', '/dev/ttyACM0')
            baudrate: Serial communication baud rate (default: 115200)
            timeout: Serial read timeout in seconds (default: 1.0)
            on_frame_received: Callback for received data packets. May be invoked
                              from a background thread unless set_event_loop() is used.
            radio_config: Optional radio configuration dict with keys:
                         frequency, bandwidth, spreading_factor, coding_rate,
                         power (or tx_power)
            auto_configure: If True, automatically configure radio on connect
        """
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.auto_configure = auto_configure

        self.radio_config = radio_config or {}
        self.is_configured = False

        self.serial_conn: Optional[serial.Serial] = None
        self.is_connected = False

        self.rx_buffer = deque(maxlen=RX_BUFFER_SIZE)
        self.tx_buffer = deque(maxlen=TX_BUFFER_SIZE)

        self.rx_frame_buffer = bytearray()
        self.in_frame = False
        self.escaped = False

        self.rx_thread: Optional[threading.Thread] = None
        self.tx_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        # Callbacks
        self.on_frame_received = on_frame_received

        # Event loop for thread-safe async callback invocation
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None

        # Response handling
        self._response_event = threading.Event()
        self._pending_response: Optional[tuple[int, bytes]] = None
        self._response_lock = threading.Lock()

        # TX completion tracking
        self._tx_done_event = threading.Event()
        self._tx_done_result: Optional[bool] = None

        self.stats = {
            "frames_sent": 0,
            "frames_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "frame_errors": 0,
            "buffer_overruns": 0,
            "rx_packets": 0,
            "tx_packets": 0,
            "errors": 0,
            "last_rssi": -999,
            "last_snr": -999.0,
            "noise_floor": None,
        }

        # Modem info
        self.modem_version: Optional[int] = None
        self.modem_identity: Optional[bytes] = None

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """
        Set the event loop for thread-safe async callback invocation.

        When set, RX callbacks are scheduled onto the event loop via
        call_soon_threadsafe() instead of being invoked directly from
        the RX thread. This is required for proper async integration.

        Args:
            loop: The asyncio event loop to use for callbacks
        """
        self._event_loop = loop
        logger.debug("Event loop set for thread-safe callbacks")

    def connect(self) -> bool:
        """
        Connect to serial port and start communication threads

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=self.timeout,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
            )

            self.is_connected = True
            self.stop_event.clear()

            # Start communication threads
            self.rx_thread = threading.Thread(target=self._rx_worker, daemon=True)
            self.tx_thread = threading.Thread(target=self._tx_worker, daemon=True)

            self.rx_thread.start()
            self.tx_thread.start()

            logger.info(f"KISS modem connected to {self.port} at {self.baudrate} baud")

            # Auto-configure if requested
            if self.auto_configure and self.radio_config:
                if not self.configure_radio():
                    logger.warning("Auto-configuration failed")
                    return False

            # Query modem info
            self._query_modem_info()

            return True

        except Exception as e:
            logger.error(f"Failed to connect to {self.port}: {e}")
            self.is_connected = False
            return False

    def disconnect(self):
        """Disconnect from serial port and stop threads"""
        self.is_connected = False
        self.stop_event.set()

        # Wait for threads to finish
        if self.rx_thread and self.rx_thread.is_alive():
            self.rx_thread.join(timeout=2.0)
        if self.tx_thread and self.tx_thread.is_alive():
            self.tx_thread.join(timeout=2.0)

        # Close serial connection
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()

        logger.info(f"KISS modem disconnected from {self.port}")

    def _query_modem_info(self):
        """Query modem version and identity"""
        try:
            # Get version
            version_resp = self._send_command(CMD_GET_VERSION)
            if version_resp and version_resp[0] == RESP_VERSION and len(version_resp[1]) >= 1:
                self.modem_version = version_resp[1][0]
                logger.info(f"Modem version: {self.modem_version}")

            # Get identity (public key)
            identity_resp = self._send_command(CMD_GET_IDENTITY)
            if identity_resp and identity_resp[0] == RESP_IDENTITY and len(identity_resp[1]) == 32:
                self.modem_identity = identity_resp[1]
                logger.info(f"Modem identity: {self.modem_identity.hex()[:16]}...")

        except Exception as e:
            logger.warning(f"Failed to query modem info: {e}")

    def configure_radio(self) -> bool:
        """
        Configure radio parameters

        Returns:
            True if configuration successful, False otherwise
        """
        if not self.is_connected:
            logger.error("Cannot configure radio: not connected")
            return False

        try:
            # Extract configuration parameters with defaults
            # Support both "power" and "tx_power" for compatibility with different config styles
            frequency_hz = self.radio_config.get("frequency", int(869.618 * 1000000))
            bandwidth_hz = self.radio_config.get("bandwidth", int(62500))
            sf = self.radio_config.get("spreading_factor", 8)
            cr = self.radio_config.get("coding_rate", 8)
            power = self.radio_config.get("power", self.radio_config.get("tx_power", 22))

            # Set radio parameters (frequency, bandwidth, SF, CR)
            # Format: Freq (4) + BW (4) + SF (1) + CR (1) - all little-endian
            radio_data = struct.pack("<IIBB", frequency_hz, bandwidth_hz, sf, cr)
            resp = self._send_command(CMD_SET_RADIO, radio_data)
            if not resp or resp[0] == RESP_ERROR:
                logger.error("Failed to set radio parameters")
                return False

            # Set TX power
            resp = self._send_command(CMD_SET_TX_POWER, bytes([power]))
            if not resp or resp[0] == RESP_ERROR:
                logger.error("Failed to set TX power")
                return False

            # Note: Sync word is configured at firmware build time, not at runtime

            self.is_configured = True
            logger.info(
                f"Radio configured: {frequency_hz / 1000000:.3f} MHz, "
                f"BW {bandwidth_hz / 1000:.1f} kHz, SF{sf}, CR4/{cr}, {power} dBm"
            )
            return True

        except Exception as e:
            logger.error(f"Radio configuration error: {e}")
            return False

    def send_frame(self, data: bytes) -> bool:
        """
        Send a data frame via KISS modem

        Args:
            data: Raw packet data to send (2-255 bytes)

        Returns:
            True if frame queued successfully, False otherwise
        """
        if not self.is_connected:
            logger.warning("Cannot send frame: not connected")
            return False

        if len(data) < 2 or len(data) > 255:
            logger.warning(f"Invalid frame size: {len(data)} (must be 2-255 bytes)")
            return False

        try:
            # Create KISS frame with CMD_DATA command
            kiss_frame = self._encode_kiss_frame(CMD_DATA, data)

            # Add to TX buffer
            if len(self.tx_buffer) < TX_BUFFER_SIZE:
                self.tx_buffer.append(kiss_frame)
                return True
            else:
                self.stats["buffer_overruns"] += 1
                logger.warning("TX buffer overrun")
                return False

        except Exception as e:
            logger.error(f"Failed to send frame: {e}")
            return False

    def send_frame_and_wait(self, data: bytes, timeout: float = RESPONSE_TIMEOUT) -> bool:
        """
        Send a data frame and wait for TX_DONE response

        Args:
            data: Raw packet data to send
            timeout: Timeout in seconds to wait for TX_DONE

        Returns:
            True if transmission successful, False otherwise
        """
        self._tx_done_event.clear()
        self._tx_done_result = None

        if not self.send_frame(data):
            return False

        # Wait for TX_DONE response
        if self._tx_done_event.wait(timeout):
            return self._tx_done_result or False
        else:
            logger.warning("TX_DONE timeout")
            return False

    def _send_command(
        self, cmd: int, data: bytes = b"", timeout: float = RESPONSE_TIMEOUT
    ) -> Optional[tuple[int, bytes]]:
        """
        Send a command and wait for response

        Args:
            cmd: Command byte
            data: Command data
            timeout: Response timeout in seconds

        Returns:
            Tuple of (response_cmd, response_data) or None on timeout
        """
        with self._response_lock:
            self._response_event.clear()
            self._pending_response = None

        # Create and send KISS frame
        kiss_frame = self._encode_kiss_frame(cmd, data)

        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.write(kiss_frame)
            self.serial_conn.flush()

        # Wait for response
        if self._response_event.wait(timeout):
            with self._response_lock:
                return self._pending_response
        else:
            logger.warning(f"Command 0x{cmd:02X} timeout")
            return None

    def get_radio_config(self) -> Optional[Dict[str, Any]]:
        """
        Get current radio configuration from modem

        Returns:
            Dict with frequency, bandwidth, sf, cr, or None on error
        """
        resp = self._send_command(CMD_GET_RADIO)
        if resp and resp[0] == RESP_RADIO and len(resp[1]) >= 10:
            freq, bw, sf, cr = struct.unpack("<IIBB", resp[1][:10])
            return {
                "frequency": freq,
                "bandwidth": bw,
                "spreading_factor": sf,
                "coding_rate": cr,
            }
        return None

    def get_tx_power(self) -> Optional[int]:
        """Get current TX power in dBm"""
        resp = self._send_command(CMD_GET_TX_POWER)
        if resp and resp[0] == RESP_TX_POWER and len(resp[1]) >= 1:
            return resp[1][0]
        return None

    def get_current_rssi(self) -> int:
        """Get current RSSI from modem"""
        resp = self._send_command(CMD_GET_CURRENT_RSSI)
        if resp and resp[0] == RESP_CURRENT_RSSI and len(resp[1]) >= 1:
            # RSSI is signed byte
            rssi = resp[1][0]
            if rssi > 127:
                rssi -= 256
            return rssi
        return -999

    def is_channel_busy(self) -> bool:
        """Check if channel is busy"""
        resp = self._send_command(CMD_IS_CHANNEL_BUSY)
        if resp and resp[0] == RESP_CHANNEL_BUSY and len(resp[1]) >= 1:
            return resp[1][0] == 0x01
        return False

    def get_airtime(self, packet_length: int) -> Optional[int]:
        """
        Get estimated airtime for a packet

        Args:
            packet_length: Length of packet in bytes

        Returns:
            Airtime in milliseconds or None on error
        """
        resp = self._send_command(CMD_GET_AIRTIME, bytes([packet_length]))
        if resp and resp[0] == RESP_AIRTIME and len(resp[1]) >= 4:
            return struct.unpack("<I", resp[1][:4])[0]
        return None

    def get_noise_floor(self) -> Optional[int]:
        """Get noise floor in dBm"""
        resp = self._send_command(CMD_GET_NOISE_FLOOR)
        if resp and resp[0] == RESP_NOISE_FLOOR and len(resp[1]) >= 2:
            # Noise floor is signed 16-bit
            noise = struct.unpack("<h", resp[1][:2])[0]
            self.stats["noise_floor"] = noise
            return noise
        return None

    def get_modem_stats(self) -> Optional[Dict[str, int]]:
        """
        Get modem statistics

        Returns:
            Dict with rx, tx, errors counts or None on error
        """
        resp = self._send_command(CMD_GET_STATS)
        if resp and resp[0] == RESP_STATS and len(resp[1]) >= 12:
            rx, tx, errors = struct.unpack("<III", resp[1][:12])
            return {"rx": rx, "tx": tx, "errors": errors}
        return None

    def get_battery(self) -> Optional[int]:
        """Get battery voltage in millivolts"""
        resp = self._send_command(CMD_GET_BATTERY)
        if resp and resp[0] == RESP_BATTERY and len(resp[1]) >= 2:
            return struct.unpack("<H", resp[1][:2])[0]
        return None

    def ping(self) -> bool:
        """Ping the modem to check connectivity"""
        resp = self._send_command(CMD_PING)
        return resp is not None and resp[0] == RESP_PONG

    def get_sensors(self, permissions: int = 0x07) -> Optional[bytes]:
        """
        Get sensor data in CayenneLPP format

        Args:
            permissions: Bitmask of sensors to query
                        0x01 = battery, 0x02 = GPS, 0x04 = environment

        Returns:
            CayenneLPP encoded sensor data or None
        """
        resp = self._send_command(CMD_GET_SENSORS, bytes([permissions]))
        if resp and resp[0] == RESP_SENSORS:
            return resp[1]
        return None

    # Cryptographic operations using modem's identity

    def get_identity(self) -> Optional[bytes]:
        """Get modem's public key (32 bytes)"""
        resp = self._send_command(CMD_GET_IDENTITY)
        if resp and resp[0] == RESP_IDENTITY and len(resp[1]) == 32:
            self.modem_identity = resp[1]
            return resp[1]
        return None

    def get_random(self, length: int) -> Optional[bytes]:
        """
        Get random bytes from modem

        Args:
            length: Number of random bytes (1-64)

        Returns:
            Random bytes or None on error
        """
        if length < 1 or length > 64:
            logger.error("Random length must be 1-64")
            return None
        resp = self._send_command(CMD_GET_RANDOM, bytes([length]))
        if resp and resp[0] == RESP_RANDOM:
            return resp[1]
        return None

    def sign_data(self, data: bytes) -> Optional[bytes]:
        """
        Sign data with modem's private key

        Args:
            data: Data to sign

        Returns:
            64-byte signature or None on error
        """
        resp = self._send_command(CMD_SIGN_DATA, data)
        if resp and resp[0] == RESP_SIGNATURE and len(resp[1]) == 64:
            return resp[1]
        return None

    def verify_signature(self, pubkey: bytes, signature: bytes, data: bytes) -> Optional[bool]:
        """
        Verify a signature

        Args:
            pubkey: 32-byte public key
            signature: 64-byte signature
            data: Original data

        Returns:
            True if valid, False if invalid, None on error
        """
        if len(pubkey) != 32 or len(signature) != 64:
            logger.error("Invalid pubkey or signature length")
            return None
        payload = pubkey + signature + data
        resp = self._send_command(CMD_VERIFY_SIGNATURE, payload)
        if resp and resp[0] == RESP_VERIFY and len(resp[1]) >= 1:
            return resp[1][0] == 0x01
        return None

    def encrypt_data(self, key: bytes, plaintext: bytes) -> Optional[tuple[bytes, bytes]]:
        """
        Encrypt data using a shared key

        Args:
            key: 32-byte encryption key
            plaintext: Data to encrypt

        Returns:
            Tuple of (mac, ciphertext) or None on error
        """
        if len(key) != 32:
            logger.error("Key must be 32 bytes")
            return None
        payload = key + plaintext
        resp = self._send_command(CMD_ENCRYPT_DATA, payload)
        if resp and resp[0] == RESP_ENCRYPTED and len(resp[1]) >= 2:
            mac = resp[1][:2]
            ciphertext = resp[1][2:]
            return (mac, ciphertext)
        return None

    def decrypt_data(self, key: bytes, mac: bytes, ciphertext: bytes) -> Optional[bytes]:
        """
        Decrypt data using a shared key

        Args:
            key: 32-byte decryption key
            mac: 2-byte MAC
            ciphertext: Encrypted data

        Returns:
            Plaintext or None on error (includes MAC failure)
        """
        if len(key) != 32 or len(mac) != 2:
            logger.error("Invalid key or MAC length")
            return None
        payload = key + mac + ciphertext
        resp = self._send_command(CMD_DECRYPT_DATA, payload)
        if resp and resp[0] == RESP_DECRYPTED:
            return resp[1]
        return None

    def key_exchange(self, remote_pubkey: bytes) -> Optional[bytes]:
        """
        Perform key exchange with remote public key

        Args:
            remote_pubkey: 32-byte remote public key

        Returns:
            32-byte shared secret or None on error
        """
        if len(remote_pubkey) != 32:
            logger.error("Remote public key must be 32 bytes")
            return None
        resp = self._send_command(CMD_KEY_EXCHANGE, remote_pubkey)
        if resp and resp[0] == RESP_SHARED_SECRET and len(resp[1]) == 32:
            return resp[1]
        return None

    def hash_data(self, data: bytes) -> Optional[bytes]:
        """
        Compute SHA-256 hash of data

        Args:
            data: Data to hash

        Returns:
            32-byte hash or None on error
        """
        resp = self._send_command(CMD_HASH, data)
        if resp and resp[0] == RESP_HASH and len(resp[1]) == 32:
            return resp[1]
        return None

    # LoRaRadio interface implementation

    def set_rx_callback(self, callback: RxCallback):
        """
        Set the RX callback function.

        The callback may be (data: bytes) or (data, rssi, snr). When invoked
        by this wrapper it is always called with (data, rssi, snr) so each
        packet gets correct per-packet metrics without race conditions.
        """
        self.on_frame_received = callback
        logger.debug("RX callback set")

    def begin(self):
        """Initialize the modem (LoRaRadio interface)"""
        success = self.connect()
        if not success:
            raise Exception("Failed to initialize KISS modem")

    async def send(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Send data via KISS modem (LoRaRadio interface)

        Args:
            data: Data to send

        Returns:
            Transmission metadata dict or None

        Raises:
            Exception: If send fails
        """
        success = self.send_frame(data)
        if not success:
            raise Exception("Failed to send frame via KISS modem")

        # Return metadata if available
        airtime = self.get_airtime(len(data))
        if airtime:
            return {"airtime_ms": airtime}
        return None

    async def wait_for_rx(self) -> bytes:
        """
        Wait for a packet to be received asynchronously (LoRaRadio interface)

        Returns:
            Received packet data
        """
        future = asyncio.Future()

        original_callback = self.on_frame_received

        def temp_callback(data: bytes, rssi: Optional[int] = None, snr: Optional[float] = None):
            if not future.done():
                future.set_result(data)
            if original_callback:
                try:
                    rssi_val = rssi if rssi is not None else -999
                    snr_val = snr if snr is not None else -999.0
                    _invoke_rx_callback(original_callback, data, rssi_val, snr_val)
                except Exception as e:
                    logger.error(f"Error in original callback: {e}")

        self.on_frame_received = temp_callback

        try:
            data = await future
            return data
        finally:
            self.on_frame_received = original_callback

    def sleep(self):
        """Put the modem into low-power mode (LoRaRadio interface)"""
        logger.debug("Sleep mode not directly supported for KISS modem")
        pass

    def get_last_rssi(self) -> int:
        """Return last received RSSI in dBm (LoRaRadio interface)"""
        return self.stats.get("last_rssi", -999)

    def get_last_snr(self) -> float:
        """Return last received SNR in dB (LoRaRadio interface)"""
        return self.stats.get("last_snr", -999.0)

    def get_stats(self) -> Dict[str, Any]:
        """Get interface statistics"""
        return self.stats.copy()

    # KISS frame encoding/decoding

    def _encode_kiss_frame(self, cmd: int, data: bytes) -> bytes:
        """
        Encode data into KISS frame format

        Args:
            cmd: Command byte
            data: Raw data to encode

        Returns:
            Encoded KISS frame
        """
        # Start with FEND and command
        frame = bytearray([KISS_FEND, cmd])

        # Escape and add data
        for byte in data:
            if byte == KISS_FEND:
                frame.extend([KISS_FESC, KISS_TFEND])
            elif byte == KISS_FESC:
                frame.extend([KISS_FESC, KISS_TFESC])
            else:
                frame.append(byte)

        # End with FEND
        frame.append(KISS_FEND)

        return bytes(frame)

    def _decode_kiss_byte(self, byte: int):
        """
        Process received byte for KISS frame decoding

        Args:
            byte: Received byte
        """
        if byte == KISS_FEND:
            if self.in_frame and len(self.rx_frame_buffer) > 0:
                # Complete frame received
                self._process_received_frame()
            # Start new frame
            self.rx_frame_buffer.clear()
            self.in_frame = True
            self.escaped = False

        elif byte == KISS_FESC:
            if self.in_frame:
                self.escaped = True

        elif self.escaped:
            if byte == KISS_TFEND:
                self.rx_frame_buffer.append(KISS_FEND)
            elif byte == KISS_TFESC:
                self.rx_frame_buffer.append(KISS_FESC)
            else:
                # Invalid escape sequence
                self.stats["frame_errors"] += 1
                logger.warning(f"Invalid KISS escape sequence: 0x{byte:02X}")
            self.escaped = False

        else:
            if self.in_frame:
                self.rx_frame_buffer.append(byte)

    def _dispatch_rx_callback(self, data: bytes, rssi: int, snr: float) -> None:
        """
        Dispatch RX callback, optionally via event loop for thread safety.

        If an event loop is set via set_event_loop(), the callback is scheduled
        onto that loop using call_soon_threadsafe(). Otherwise, the callback
        is invoked directly from the RX thread.

        Args:
            data: Received packet data
            rssi: RSSI in dBm
            snr: SNR in dB
        """
        if self.on_frame_received is None:
            return

        if self._event_loop is not None:
            # Schedule callback on event loop for thread-safe async
            try:
                self._event_loop.call_soon_threadsafe(
                    lambda: _invoke_rx_callback(self.on_frame_received, data, rssi, snr)
                )
            except RuntimeError as e:
                # Event loop may be closed
                logger.warning(f"Failed to schedule RX callback on event loop: {e}")
        else:
            # Direct invocation from RX thread
            _invoke_rx_callback(self.on_frame_received, data, rssi, snr)

    def _process_received_frame(self):
        """Process a complete received KISS frame"""
        if len(self.rx_frame_buffer) < 1:
            return

        # Extract command byte
        cmd = self.rx_frame_buffer[0]
        data = bytes(self.rx_frame_buffer[1:])

        self.stats["frames_received"] += 1
        self.stats["bytes_received"] += len(data)

        if cmd == CMD_DATA:
            # Data packet received - extract RSSI/SNR and payload
            if len(data) >= 2:
                # First byte is SNR * 4 (signed), second byte is RSSI (signed)
                snr_raw = data[0]
                rssi_raw = data[1]

                # Convert to signed values
                if snr_raw > 127:
                    snr_raw -= 256
                if rssi_raw > 127:
                    rssi_raw -= 256

                self.stats["last_snr"] = snr_raw / 4.0  # SNR in 0.25 dB steps
                self.stats["last_rssi"] = rssi_raw
                self.stats["rx_packets"] += 1

                # Extract packet payload (skip SNR and RSSI bytes)
                packet_data = data[2:]

                if self.on_frame_received and len(packet_data) > 0:
                    try:
                        # Pass per-packet rssi/snr to avoid race with get_last_rssi/get_last_snr
                        snr_db = snr_raw / 4.0  # SNR in 0.25 dB steps
                        self._dispatch_rx_callback(packet_data, rssi_raw, snr_db)
                    except Exception as e:
                        logger.error(f"Error in frame received callback: {e}")

        elif cmd == RESP_TX_DONE:
            # TX completion response
            if len(data) >= 1:
                self._tx_done_result = data[0] == 0x01
                self.stats["tx_packets"] += 1
            self._tx_done_event.set()

        elif cmd == RESP_ERROR:
            # Error response
            if len(data) >= 1:
                error_code = data[0]
                self.stats["errors"] += 1
                logger.warning(f"Modem error: 0x{error_code:02X}")
            # Signal response for command waiting
            with self._response_lock:
                self._pending_response = (cmd, data)
                self._response_event.set()

        else:
            # Response to a command
            with self._response_lock:
                self._pending_response = (cmd, data)
                self._response_event.set()

    def _rx_worker(self):
        """Background thread for receiving data"""
        while not self.stop_event.is_set() and self.is_connected:
            try:
                if self.serial_conn and self.serial_conn.in_waiting > 0:
                    data = self.serial_conn.read(self.serial_conn.in_waiting)

                    for byte in data:
                        self._decode_kiss_byte(byte)

                else:
                    threading.Event().wait(0.01)

            except Exception as e:
                if self.is_connected:
                    logger.error(f"RX worker error: {e}")
                break

    def _tx_worker(self):
        """Background thread for sending data"""
        while not self.stop_event.is_set() and self.is_connected:
            try:
                if self.tx_buffer:
                    frame = self.tx_buffer.popleft()

                    if self.serial_conn and self.serial_conn.is_open:
                        self.serial_conn.write(frame)
                        self.serial_conn.flush()

                        self.stats["frames_sent"] += 1
                        self.stats["bytes_sent"] += len(frame)
                    else:
                        logger.warning("Serial connection not open")
                else:
                    threading.Event().wait(0.01)

            except Exception as e:
                if self.is_connected:
                    logger.error(f"TX worker error: {e}")
                break

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.disconnect()
        except Exception:
            pass

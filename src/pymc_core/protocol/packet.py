from typing import ByteString, Optional

from .constants import (
    MAX_PATH_SIZE,
    MAX_SUPPORTED_PAYLOAD_VERSION,
    PH_ROUTE_MASK,
    PH_TYPE_MASK,
    PH_TYPE_SHIFT,
    PH_VER_MASK,
    PH_VER_SHIFT,
    PUB_KEY_SIZE,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_DIRECT,
    ROUTE_TYPE_TRANSPORT_FLOOD,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
)
from .packet_utils import PacketDataUtils, PacketHashingUtils, PacketValidationUtils

"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                          MESH PACKET STRUCTURE OVERVIEW                   ║
╠════════════════════╦══════════════════════════════════════════════════════╣
║ Field              ║ Description                                          ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Header (1 byte)    ║ Encodes route type (2 bits), payload type (4 bits),  ║
║                    ║ and version (2 bits).                                ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Transport Codes    ║ Two 16-bit codes (4 bytes total). Only present for   ║
║ (0 or 4 bytes)     ║ TRANSPORT_FLOOD and TRANSPORT_DIRECT route types.    ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Path Length (1 B)  ║ Number of path hops (0–15).                          ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Path (N bytes)     ║ List of node hashes (1 byte each), length = path_len ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Payload (N bytes)  ║ Actual encrypted or plain payload. Max: 254 bytes    ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Total Size         ║ <= 256 bytes (hard limit)                            ║
╚════════════════════╩══════════════════════════════════════════════════════╝

Header Layout (1 byte):
╔═══════════╦════════════╦════════════════════════════════╗
║ Bits      ║ Name       ║ Meaning                        ║
╠═══════════╬════════════╬════════════════════════════════╣
║ 0–1       ║ RouteType  ║ 00: TransportFlood,            ║
║           ║            ║ 01: Flood, 10: Direct,         ║
║           ║            ║ 11: TransportDirect            ║
╠═══════════╬════════════╬════════════════════════════════╣
║ 2–5       ║ PayloadType║ See PAYLOAD_TYPE_* constants   ║
╠═══════════╬════════════╬════════════════════════════════╣
║ 6–7       ║ Version    ║ Packet format version (0–3)    ║
╚═══════════╩════════════╩════════════════════════════════╝

Notes:
- `write_to()` and `read_from()` enforce the exact structure used in firmware.
- Transport codes are included only for route types 0x00 and 0x03.
- Payload size must be ≤ MAX_PACKET_PAYLOAD (typically 254).
- `calculate_packet_hash()` includes payload type + path_len (only for TRACE).
"""


class Packet:
    """
    Represents a mesh network packet with header, transport codes, path, and payload components.

    This class handles serialization and deserialization of packets in the mesh protocol,
    providing methods for packet validation, hashing, and data extraction. It maintains
    compatibility with C++ packet formats for cross-platform interoperability.

    Attributes:
        header (int): Single byte header containing packet type and flags.
        transport_codes (list): Two 16-bit transport codes for TRANSPORT route types.
        path_len (int): Length of the path component in bytes.
        path (bytearray): Variable-length path data for routing.
        payload (bytearray): Variable-length payload data.
        payload_len (int): Actual length of payload data.
        _rssi (int): Raw RSSI signal strength value from firmware.
        _snr (int): Raw SNR value from firmware.

    Example:
        ```python
        packet = Packet()
        packet.header = 0x01  # Flood routing
        packet.path = b"node1->node2"
        packet.path_len = len(packet.path)
        packet.payload = b"Hello World"
        packet.payload_len = len(packet.payload)
        data = packet.write_to()
        # data can be transmitted over the mesh network
        ```
    """

    """
    Python replica of mesh::Packet (compatible with C++ writeTo/readFrom).

    Provides:
    - Header parsing (route type, payload type/version)
    - Serialization (write_to) and deserialization (read_from)
    - Packet hashing (for ACKs, deduplication, validation)
    - Raw signal info (SNR, RSSI)
    """

    __slots__ = (
        "header",
        "path_len",
        "decrypted",
        "payload_len",
        "path",
        "payload",
        "transport_codes",
        "_snr",
        "_rssi",
        "_do_not_retransmit",
        "drop_reason",
        "_tx_metadata",
    )

    def __init__(self):
        """
        Initialize a new empty packet with default values.

        Sets up the packet structure with zero-initialized fields ready for
        population with actual packet data. All fields are initialized to
        safe default values to prevent undefined behavior.
        """
        self.header = 0x00
        self.path = bytearray()
        self.payload = bytearray()
        self.decrypted = {}
        self.path_len = 0
        self.payload_len = 0
        self.transport_codes = [0, 0]  # Array of two 16-bit transport codes
        self._snr = 0
        self._rssi = 0
        # Repeater flag to prevent retransmission and log drop reason
        self._do_not_retransmit = False
        self.drop_reason = None  # Optional: reason for dropping packet

    def get_route_type(self) -> int:
        """
        Extract the 2-bit route type from the packet header.

        Returns:
            int: Route type value (0-3) indicating routing method:
                - 0: Transport flood routing (with transport codes)
                - 1: Flood routing
                - 2: Direct routing
                - 3: Transport direct routing (with transport codes)
        """
        return self.header & PH_ROUTE_MASK

    def get_payload_type(self) -> int:
        """
        Extract the 4-bit payload type from the packet header.

        Returns:
            int: Payload type value indicating the type of data in the packet:
                - 0: Plain text message
                - 1: Encrypted message
                - 2: ACK packet
                - 3: Advertisement
                - 4: Login request/response
                - 5: Protocol control
                - 6-15: Reserved for future use
        """
        return (self.header >> PH_TYPE_SHIFT) & PH_TYPE_MASK

    def get_payload_ver(self) -> int:
        """
        Extract the 2-bit payload version from the packet header.

        Returns:
            int: Version number (0-3) indicating the packet format version.
                Higher versions may include additional features or format changes.
        """
        return (self.header >> PH_VER_SHIFT) & PH_VER_MASK

    def has_transport_codes(self) -> bool:
        """
        Check if this packet includes transport codes in its format.

        Returns:
            bool: True if the packet uses transport flood or transport direct
                routing, which includes 4 bytes of transport codes after the header.
        """
        route_type = self.get_route_type()
        return route_type == ROUTE_TYPE_TRANSPORT_FLOOD or route_type == ROUTE_TYPE_TRANSPORT_DIRECT

    def is_route_flood(self) -> bool:
        """
        Check if this packet uses flood routing (with or without transport codes).

        Returns:
            bool: True if the packet uses any form of flood routing.
        """
        route_type = self.get_route_type()
        return route_type == ROUTE_TYPE_TRANSPORT_FLOOD or route_type == ROUTE_TYPE_FLOOD

    def is_route_direct(self) -> bool:
        """
        Check if this packet uses direct routing (with or without transport codes).

        Returns:
            bool: True if the packet uses any form of direct routing.
        """
        route_type = self.get_route_type()
        return route_type == ROUTE_TYPE_TRANSPORT_DIRECT or route_type == ROUTE_TYPE_DIRECT

    def get_payload(self) -> bytes:
        """
        Get the packet payload as immutable bytes, truncated to declared length.

        Returns:
            bytes: The actual payload data, limited to payload_len bytes.
                Returns empty bytes if payload_len is 0 or negative.

        Note:
            This method ensures only the declared payload length is returned,
            preventing access to any extra data that might be in the buffer.
        """
        return bytes(self.payload[: self.payload_len])

    def get_payload_app_data(self) -> bytes:
        """
        Extract application-specific data from the payload, skipping protocol headers.

        Returns:
            bytes: Application data portion of the payload, excluding the protocol
                overhead (public key, timestamp, and signature). Returns empty bytes
                if the payload is too short to contain the full protocol header.

        Note:
            The protocol header consists of:
            - Public key (PUB_KEY_SIZE bytes)
            - Timestamp (TIMESTAMP_SIZE bytes)
            - Signature (SIGNATURE_SIZE bytes)
        """
        offset = PUB_KEY_SIZE + TIMESTAMP_SIZE + SIGNATURE_SIZE
        return self.get_payload()[offset:] if self.payload_len >= offset else b""

    def _validate_lengths(self) -> None:
        """
        Validate that internal length values match actual buffer lengths.

        Ensures data integrity by checking that declared lengths (path_len, payload_len)
        match the actual buffer sizes. This prevents buffer overflow and underflow issues.

        Raises:
            ValueError: If any declared length doesn't match the actual buffer length.
        """
        PacketValidationUtils.validate_buffer_lengths(
            self.path_len, len(self.path), self.payload_len, len(self.payload)
        )

    def _check_bounds(self, idx: int, required: int, data_len: int, error_msg: str) -> None:
        """
        Check if we have enough data remaining for the requested operation.

        Args:
            idx (int): Current position in the data buffer.
            required (int): Number of bytes required for the operation.
            data_len (int): Total length of the data buffer.
            error_msg (str): Error message to use if bounds check fails.

        Raises:
            ValueError: If there are insufficient bytes remaining in the buffer.
        """
        PacketValidationUtils.validate_packet_bounds(idx, required, data_len, error_msg)

    def write_to(self) -> bytes:
        """
        Serialize the packet to a byte sequence compatible with C++ Packet::writeTo().

        Creates a wire-format byte representation of the packet that can be transmitted
        over the mesh network. The format matches the C++ implementation exactly.

        Returns:
            bytes: Serialized packet data in the format:
                ``header(1) | [transport_codes(4)] | path_len(1) | path(N) | payload(M)``
                Transport codes are only included if has_transport_codes() is True.

        Raises:
            ValueError: If internal length values don't match actual buffer lengths,
                indicating data corruption or incorrect packet construction.
        """
        self._validate_lengths()

        out = bytearray([self.header])

        # Add transport codes if this packet type requires them
        if self.has_transport_codes():
            # Pack two 16-bit transport codes (4 bytes total) in little-endian format
            out.extend(self.transport_codes[0].to_bytes(2, "little"))
            out.extend(self.transport_codes[1].to_bytes(2, "little"))

        out.append(self.path_len)
        out += self.path
        out += self.payload[: self.payload_len]
        return bytes(out)

    def read_from(self, data: ByteString) -> bool:
        """
        Deserialize a C++ wire-format packet from bytes.

        Parses the binary packet data received over the network and populates
        the packet fields. The format must match the C++ Packet::readFrom() exactly.

        Args:
            data (ByteString): Raw packet data in wire format.

        Returns:
            bool: True if deserialization was successful.

        Raises:
            ValueError: If the packet format is invalid, truncated, or contains
                invalid values (e.g., path_len too large, invalid payload size).
        """
        idx, data_len = 0, len(data)
        self.header = data[idx]
        idx += 1

        # Validate packet version (must match C++ supported versions)
        version = self.get_payload_ver()
        if version > MAX_SUPPORTED_PAYLOAD_VERSION:
            raise ValueError(f"Unsupported packet version: {version}")

        # Read transport codes if present
        if self.has_transport_codes():
            self._check_bounds(idx, 4, data_len, "missing transport codes")
            # Unpack two 16-bit transport codes from little-endian format
            self.transport_codes[0] = int.from_bytes(data[idx : idx + 2], "little")
            self.transport_codes[1] = int.from_bytes(data[idx + 2 : idx + 4], "little")
            idx += 4
        else:
            self.transport_codes = [0, 0]

        self._check_bounds(idx, 1, data_len, "missing path_len")
        self.path_len = data[idx]
        idx += 1
        if self.path_len > MAX_PATH_SIZE:
            raise ValueError("path_len too large")

        self._check_bounds(idx, self.path_len, data_len, "truncated path")
        self.path = bytearray(data[idx : idx + self.path_len])
        idx += self.path_len

        self.payload = bytearray(data[idx:])
        self.payload_len = len(self.payload)
        PacketValidationUtils.validate_payload_size(self.payload_len)

        return True

    def calculate_packet_hash(self) -> bytes:
        """
        Compute SHA256-based hash for ACK, deduplication, and validation.

        Generates a cryptographic hash of the packet content for use in:
        - ACK packet generation and verification
        - Packet deduplication to prevent replay attacks
        - Message integrity validation

        Returns:
            bytes: First MAX_HASH_SIZE bytes of SHA256 digest computed over
                the payload type, path length, and payload data.

        Note:
            The hash includes payload type and path_len to ensure packets with
            different routing or content types produce different hashes.
        """
        return PacketHashingUtils.calculate_packet_hash(
            self.get_payload_type(), self.path_len, self.payload[: self.payload_len]
        )

    def get_packet_hash_hex(self, length: Optional[int] = None) -> str:
        """
        Return upper-case hex string representation of this packet's hash.

        Args:
            length (Optional[int], optional): Maximum length of the returned hex string.
                Defaults to None (full hash string).

        Returns:
            str: Upper-case hex string of the packet hash.
        """
        return PacketHashingUtils.calculate_packet_hash_string(
            payload_type=self.get_payload_type(),
            path_len=self.path_len,
            payload=self.payload[: self.payload_len],
            length=length,
        )

    def get_crc(self) -> int:
        """
        Calculate a 4-byte CRC from SHA256 digest for ACK confirmation.

        Generates a compact checksum derived from the packet's SHA256 hash,
        used specifically for ACK packet confirmation to ensure the ACK
        corresponds to the correct original packet.

        Returns:
            int: 32-bit CRC value extracted from the SHA256 digest,
                used for lightweight packet identification in ACKs.

        Note:
            This CRC is more compact than the full hash but still provides
            sufficient uniqueness for ACK correlation in the mesh network.
        """
        return PacketHashingUtils.calculate_crc(
            self.get_payload_type(), self.path_len, self.payload[: self.payload_len]
        )

    def get_raw_length(self) -> int:
        """
        Calculate the total byte length of the packet on the wire.

        Computes the exact size of the serialized packet as it would appear
        on the network, matching the C++ Packet::getRawLength() implementation.

        Returns:
            int: Total packet size in bytes, calculated as:
                header(1) + [transport_codes(4)] + path_len(1) + path(N) + payload(M)
                Transport codes are only included if has_transport_codes() is True.

        Note:
            This matches the wire format used by write_to() and expected by read_from().
        """
        base_length = 2 + self.path_len + self.payload_len  # header + path_len + path + payload
        return base_length + (4 if self.has_transport_codes() else 0)

    def get_snr(self) -> float:
        """
        Calculate the signal-to-noise ratio in decibels.

        Converts the raw SNR value from firmware into a standardized
        decibel representation for signal quality assessment.

        Returns:
            float: SNR value in dB, where higher values indicate better
                signal quality relative to background noise.
        """
        return PacketDataUtils.calculate_snr_db(self._snr)

    @property
    def rssi(self) -> int:
        """
        Get the raw RSSI (Received Signal Strength Indicator) value.

        Returns the signal strength measurement from the radio firmware
        in its native scale, typically used for relative signal comparisons.

        Returns:
            int: Raw RSSI value from firmware. Higher values indicate
                stronger received signals.
        """
        return self._rssi

    @property
    def snr(self) -> float:
        """
        Get the signal-to-noise ratio in decibels.

        Provides convenient access to the calculated SNR value in dB,
        automatically converting from the raw firmware value.

        Returns:
            float: SNR in decibels, where positive values indicate
                signal power above noise floor, negative values indicate
                signal below noise floor.
        """
        return self.get_snr()

    def mark_do_not_retransmit(self) -> None:
        """
        Mark this packet to prevent retransmission.

        Sets a flag indicating this packet should not be forwarded by repeaters.
        This is typically set when a packet has been successfully delivered to
        its intended destination to prevent unnecessary network traffic.

        Used by destination nodes after successfully decrypting and processing
        a message intended for them.
        """
        self._do_not_retransmit = True

    def is_marked_do_not_retransmit(self) -> bool:
        """
        Check if this packet is marked to prevent retransmission.

        Returns:
            bool: True if the packet should not be retransmitted/forwarded.
                This indicates the packet has reached its destination or should
                remain local to the receiving node.
        """
        return self._do_not_retransmit

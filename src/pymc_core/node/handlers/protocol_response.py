"""Protocol response handler for mesh network protocol requests.

Handles responses to protocol requests (like stats, config, etc.) that come
back as PATH packets with encrypted payloads.
"""

import asyncio
import struct
from typing import Any, Callable, Dict, Optional

from ...protocol import CryptoUtils, Identity, Packet
from ...protocol.constants import MAX_PATH_SIZE, PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_RESPONSE

# ---------------------------------------------------------------------------
# Built-in CayenneLPP decoder (no external dependency)
# Spec: https://docs.mydevices.com/docs/lorawan/cayenne-lpp
# Each record: channel(1) + type_id(1) + value(N)
# ---------------------------------------------------------------------------

_LPP_TYPES: Dict[int, tuple] = {
    # type_id: (name, value_size_bytes, divisor, signed)
    # --- Original LPPv1 types ---
    0x00: ("Digital Input", 1, 1, False),
    0x01: ("Digital Output", 1, 1, False),
    0x02: ("Analog Input", 2, 100, True),
    0x03: ("Analog Output", 2, 100, True),
    # --- Extended types (from CayenneLPP.h) ---
    0x64: ("Generic Sensor", 4, 1, False),   # LPP_GENERIC_SENSOR  = 100
    0x65: ("Illuminance", 2, 1, False),      # LPP_LUMINOSITY      = 101
    0x66: ("Presence", 1, 1, False),         # LPP_PRESENCE        = 102
    0x67: ("Temperature", 2, 10, True),      # LPP_TEMPERATURE     = 103
    0x68: ("Humidity", 1, 2, False),         # LPP_RELATIVE_HUMIDITY = 104
    0x71: ("Accelerometer", 6, 1000, True),  # LPP_ACCELEROMETER   = 113, 3×int16
    0x73: ("Barometer", 2, 10, False),       # LPP_BAROMETRIC_PRESSURE = 115
    0x74: ("Voltage", 2, 100, False),        # LPP_VOLTAGE         = 116, 0.01V
    0x75: ("Current", 2, 1000, False),       # LPP_CURRENT         = 117, 0.001A
    0x76: ("Frequency", 4, 1, False),        # LPP_FREQUENCY       = 118, 1Hz
    0x78: ("Percentage", 1, 1, False),       # LPP_PERCENTAGE      = 120, 1-100%
    0x79: ("Altitude", 2, 1, True),          # LPP_ALTITUDE        = 121, 1m signed
    0x7D: ("Concentration", 2, 1, False),    # LPP_CONCENTRATION   = 125, 1ppm
    0x80: ("Power", 2, 1, False),            # LPP_POWER           = 128, 1W
    0x82: ("Distance", 4, 1000, False),      # LPP_DISTANCE        = 130, 0.001m
    0x83: ("Energy", 4, 1000, False),        # LPP_ENERGY          = 131, 0.001kWh
    0x84: ("Direction", 2, 1, False),        # LPP_DIRECTION       = 132, 1deg
    0x85: ("Unix Time", 4, 1, False),        # LPP_UNIXTIME        = 133
    0x86: ("Gyroscope", 6, 100, True),       # LPP_GYROMETER       = 134, 3×int16
    0x87: ("Colour", 3, 1, False),           # LPP_COLOUR          = 135, RGB
    0x88: ("GPS", 9, 1, True),               # LPP_GPS             = 136, lat(3)+lon(3)+alt(3)
    0x8E: ("Switch", 1, 1, False),           # LPP_SWITCH          = 142, 0/1
}


def _decode_cayenne_lpp(data: bytes) -> list:
    """Decode CayenneLPP binary payload into a list of sensor dicts."""
    sensors: list = []
    idx = 0
    while idx + 2 <= len(data):
        channel = data[idx]
        type_id = data[idx + 1]
        idx += 2
        spec = _LPP_TYPES.get(type_id)
        if spec is None:
            break  # unknown type → stop (remaining bytes may be padding)
        name, size, divisor, signed = spec
        if idx + size > len(data):
            break
        raw = data[idx : idx + size]
        idx += size

        if type_id == 0x88:
            # GPS: lat(3, signed, /10000) + lon(3, signed, /10000) + alt(3, signed, /100)
            lat = int.from_bytes(raw[0:3], "big", signed=True) / 10000
            lon = int.from_bytes(raw[3:6], "big", signed=True) / 10000
            alt = int.from_bytes(raw[6:9], "big", signed=True) / 100
            sensors.append({"channel": channel, "type": name, "type_id": type_id,
                            "value": {"latitude": lat, "longitude": lon, "altitude": alt},
                            "raw_value": raw.hex()})
        elif size == 6 and type_id in (0x71, 0x86):
            # 3-axis: x(2) + y(2) + z(2), all signed
            x = int.from_bytes(raw[0:2], "big", signed=True) / divisor
            y = int.from_bytes(raw[2:4], "big", signed=True) / divisor
            z = int.from_bytes(raw[4:6], "big", signed=True) / divisor
            sensors.append({"channel": channel, "type": name, "type_id": type_id,
                            "value": {"x": x, "y": y, "z": z},
                            "raw_value": raw.hex()})
        elif type_id == 0x87:
            # Colour: R(1) + G(1) + B(1)
            sensors.append({"channel": channel, "type": name, "type_id": type_id,
                            "value": {"r": raw[0], "g": raw[1], "b": raw[2]},
                            "raw_value": raw.hex()})
        else:
            val = int.from_bytes(raw, "big", signed=signed)
            sensors.append({"channel": channel, "type": name, "type_id": type_id,
                            "value": val / divisor if divisor != 1 else val,
                            "raw_value": raw.hex()})
    return sensors


class ProtocolResponseHandler:
    """Handler for protocol responses that come back as encrypted PATH packets.

    This handler specifically deals with responses to protocol requests like:
    - Protocol 0x01: Get repeater stats
    - Protocol 0x02: Get configuration
    - etc.
    """

    def __init__(self, log_fn: Callable[[str], None], local_identity, contact_book):
        self._log = log_fn
        self._local_identity = local_identity
        self._contact_book = contact_book

        # Callbacks for protocol responses
        self._response_callbacks: Dict[int, Callable[[bool, str, Dict[str, Any]], None]] = {}
        # Optional: when set, decrypted payloads with tag+data (and optional path) are passed as binary response
        # Signature: (tag_bytes, response_data, path_info=None). path_info = (out_path, in_path, contact_pubkey).
        self._binary_response_callback: Optional[Callable[..., Any]] = None

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_PATH  # Protocol responses come as PATH packets

    def set_response_callback(
        self, contact_hash: int, callback: Callable[[bool, str, Dict[str, Any]], None]
    ) -> None:
        """Set callback for protocol responses from a specific contact."""
        self._response_callbacks[contact_hash] = callback

    def clear_response_callback(self, contact_hash: int) -> None:
        """Clear callback for protocol responses from a specific contact."""
        self._response_callbacks.pop(contact_hash, None)

    def set_binary_response_callback(self, callback: Callable[..., Any]) -> None:
        """Set callback for binary responses. Called with (tag_bytes, response_data, path_info=None).
        path_info when present is (out_path, in_path, contact_pubkey) for path-return format."""
        self._binary_response_callback = callback

    async def __call__(self, pkt: Packet) -> None:
        """Handle incoming PATH or RESPONSE packet that might be a protocol response."""
        try:
            # Check if this looks like an encrypted protocol response
            if len(pkt.payload) < 4:
                return  # Too short for protocol response

            # Both PATH and RESPONSE packets share the same structure:
            # dest_hash(1) + src_hash(1) + encrypted_data(N)
            src_hash = pkt.payload[1]

            # Proceed if we have a callback for this source or the binary (path-discovery) callback
            if src_hash not in self._response_callbacks and self._binary_response_callback is None:
                return

            # Try to decrypt the response
            success, decoded_text, parsed_data, raw_decrypted = await self._decrypt_protocol_response(
                pkt, src_hash
            )

            # If an explicit response callback is waiting for this source (e.g. telemetry,
            # stats, repeater command), deliver there first.  The binary/path-discovery
            # callback is a generic fallback for unsolicited binary responses.
            #
            # Guard: skip responses that are clearly NOT protocol responses (e.g. a
            # stale login response retransmission).  Protocol responses always decrypt
            # to a tag(4) + meaningful payload, so ≥20 bytes.  Login responses are only
            # ~12 bytes and parse as "binary" fallback.  Without this check a
            # retransmitted login response can consume the stats/telemetry waiter.
            if src_hash in self._response_callbacks:
                resp_type = parsed_data.get("type") if isinstance(parsed_data, dict) else None
                decrypted_len = len(raw_decrypted) if raw_decrypted else 0
                if not success or (resp_type == "binary" and decrypted_len < 20):
                    self._log(
                        f"[ProtocolResponse] Ignoring non-protocol response for 0x{src_hash:02X} "
                        f"(success={success}, type={resp_type}, decrypted_len={decrypted_len})"
                    )
                    return
                callback = self._response_callbacks[src_hash]
                if callback:
                    callback(success, decoded_text, parsed_data)
                return

            # If binary response callback is set, parse and invoke (plain tag+data or path-return format)
            if (
                success
                and self._binary_response_callback is not None
                and raw_decrypted is not None
                and len(raw_decrypted) >= 4
            ):
                path_info = None
                pkt_type = (pkt.header >> 2) & 0x0F

                if pkt_type == PAYLOAD_TYPE_PATH:
                    # PATH packet: decrypted is path_len(1)+path(N)+extra_type(1)+extra
                    # Extract inner response from path-return structure
                    path_len_byte = raw_decrypted[0]
                    inner_offset = 1 + path_len_byte + 1
                    if (
                        path_len_byte <= MAX_PATH_SIZE
                        and len(raw_decrypted) >= inner_offset + 4
                    ):
                        out_path = bytes(raw_decrypted[1 : 1 + path_len_byte])
                        extra_type = raw_decrypted[1 + path_len_byte] & 0x0F
                        extra = raw_decrypted[inner_offset:]
                        if extra_type == PAYLOAD_TYPE_RESPONSE and len(extra) >= 4:
                            tag_bytes = extra[:4]
                            response_data = extra[4:]
                            in_path = bytes(pkt.path) if pkt.path else b""
                            contact = self._find_contact_by_hash(src_hash)
                            if contact:
                                contact_pubkey = bytes.fromhex(contact.public_key)
                                path_info = (out_path, in_path, contact_pubkey)
                        else:
                            tag_bytes = raw_decrypted[:4]
                            response_data = raw_decrypted[4:]
                    else:
                        tag_bytes = raw_decrypted[:4]
                        response_data = raw_decrypted[4:]
                else:
                    # RESPONSE packet: decrypted is tag(4)+data directly
                    tag_bytes = raw_decrypted[:4]
                    response_data = raw_decrypted[4:]

                try:
                    cb_result = self._binary_response_callback(
                        tag_bytes, response_data, path_info
                    )
                    if asyncio.iscoroutine(cb_result):
                        await cb_result
                except Exception as e:
                    self._log(f"[ProtocolResponse] Binary response callback error: {e}")
                return

        except Exception as e:
            self._log(f"[ProtocolResponse] Error processing protocol response: {e}")

    async def _decrypt_protocol_response(
        self, pkt: Packet, src_hash: int
    ) -> tuple[bool, str, Dict[str, Any], Optional[bytes]]:
        """Decrypt and parse a protocol response packet. Returns (success, text, parsed_data, raw_decrypted).

        Handles both packet types by inspecting the actual packet header:
        - PAYLOAD_TYPE_RESPONSE (0x01): direct datagram → decrypted = tag(4)+data
        - PAYLOAD_TYPE_PATH (0x08): path return → decrypted = path_len(1)+path(N)+extra_type(1)+extra
        """
        try:
            # Find the contact by hash
            contact = self._find_contact_by_hash(src_hash)
            if not contact:
                return False, f"Unknown contact for hash 0x{src_hash:02X}", {}, None

            # Get encryption keys
            contact_pubkey = bytes.fromhex(contact.public_key)
            peer_id = Identity(contact_pubkey)
            shared_secret = peer_id.calc_shared_secret(self._local_identity.get_private_key())
            aes_key = shared_secret[:16]

            # Extract encrypted data (skip dest_hash(1) + src_hash(1))
            encrypted_data = pkt.payload[2:]

            # Decrypt the payload
            decrypted = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_data)

            # Determine the actual payload type from the incoming packet header.
            pkt_type = (pkt.header >> 2) & 0x0F

            # Extract the actual response data based on packet type.
            response_data = decrypted

            if pkt_type == PAYLOAD_TYPE_PATH:
                # Path-return format: path_len(1) + path(N) + extra_type(1) + extra_data
                # The actual protocol response is inside the 'extra' field.
                if len(decrypted) >= 2:  # need at least path_len + extra_type
                    path_len_byte = decrypted[0]
                    inner_offset = 1 + path_len_byte + 1  # path_len + path + extra_type
                    if (
                        path_len_byte <= MAX_PATH_SIZE
                        and len(decrypted) >= inner_offset
                    ):
                        extra_type = decrypted[1 + path_len_byte] & 0x0F
                        if extra_type == PAYLOAD_TYPE_RESPONSE and len(decrypted) > inner_offset:
                            response_data = decrypted[inner_offset:]
                        elif extra_type != PAYLOAD_TYPE_RESPONSE:
                            self._log(
                                f"[ProtocolResponse] PATH format: extra_type=0x{extra_type:02X}, "
                                f"not RESPONSE"
                            )

            # Parse based on content type
            success, text, parsed = self._parse_protocol_response(response_data)
            return success, text, parsed, decrypted

        except Exception as e:
            self._log(f"[ProtocolResponse] Decryption failed: {e}")
            return False, f"Decryption failed: {e}", {}, None

    def _parse_protocol_response(self, data: bytes) -> tuple[bool, str, Dict[str, Any]]:
        """Parse decrypted protocol response data.

        Parse order mirrors MeshCore firmware priority:
        1. Stats (RepeaterStats struct, ≥52 bytes)
        2. Text / status (UTF-8 printable after stripping tag + nulls)
        3. Telemetry (reflected_timestamp + valid CayenneLPP with ≥1 sensor)
        4. Binary fallback
        """
        try:
            # 1. Check if this looks like a stats response (protocol 0x01)
            #    RepeaterStats is 48-56 bytes + 4-byte tag.  Older firmware
            #    omits n_recv_errors (52 B struct → 56 total); PATH-wrapped
            #    responses may also lose trailing bytes to AES block alignment.
            if len(data) >= 56:
                stats_result = self._parse_stats_response(data)
                if stats_result:
                    # Include raw_bytes in the parsed dict so callers can
                    # forward the binary RepeaterStats to companion apps.
                    result_dict = stats_result["raw"]
                    result_dict["type"] = "stats"
                    result_dict["raw_bytes"] = stats_result["raw_bytes"]
                    self._log(
                        f"[ProtocolResponse] Parsed as STATS: batt={result_dict['batt_milli_volts']}mV, "
                        f"rssi={result_dict['last_rssi']}, snr={result_dict['last_snr']}, "
                        f"raw_bytes={len(result_dict['raw_bytes'])}B"
                    )
                    return True, stats_result["formatted"], result_dict

            # 2. Try parsing as text/status response.
            #    Status responses are tag(4) + UTF-8 text.  Strip the 4-byte
            #    tag that prefixes every response, then check for printable text.
            if len(data) > 4:
                try:
                    text_candidate = data[4:].rstrip(b"\x00").decode("utf-8")
                    if text_candidate.strip() and text_candidate.strip().isprintable():
                        return (
                            True,
                            text_candidate.strip(),
                            {"type": "text", "content": text_candidate.strip()},
                        )
                except UnicodeDecodeError:
                    pass

            # 3. Check if this looks like a telemetry response (protocol 0x03)
            #    Must decode at least one sensor from valid CayenneLPP after the tag.
            if len(data) >= 8:  # tag(4) + at least one LPP record (ch+type+val = 3+)
                telemetry_result = self._parse_telemetry_response(data)
                if telemetry_result and telemetry_result.get("sensor_count", 0) > 0:
                    return True, telemetry_result["formatted"], telemetry_result

            # 4. Fall back to hex representation
            hex_response = data.hex()
            return (
                True,
                f"Binary response: {hex_response}",
                {"type": "binary", "hex": hex_response},
            )

        except Exception as e:
            return False, f"Parse error: {e}", {}

    def _parse_stats_response(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse RepeaterStats struct response (protocol 0x01).

        RepeaterStats layout (from simple_repeater/MyMesh.h):
          uint16_t batt_milli_volts;        // offset 0
          uint16_t curr_tx_queue_len;       // offset 2
          int16_t  noise_floor;             // offset 4
          int16_t  last_rssi;               // offset 6
          uint32_t n_packets_recv;          // offset 8
          uint32_t n_packets_sent;          // offset 12
          uint32_t total_air_time_secs;     // offset 16
          uint32_t total_up_time_secs;      // offset 20
          uint32_t n_sent_flood;            // offset 24
          uint32_t n_sent_direct;           // offset 28
          uint32_t n_recv_flood;            // offset 32
          uint32_t n_recv_direct;           // offset 36
          uint16_t err_events;              // offset 40
          int16_t  last_snr;  // ×4         // offset 42
          uint16_t n_direct_dups;           // offset 44
          uint16_t n_flood_dups;            // offset 46
          uint32_t total_rx_air_time_secs;  // offset 48
          uint32_t n_recv_errors;           // offset 52
        Total: 56 bytes
        """
        try:
            # Skip 4-byte reflected timestamp/tag
            # memcpy(&reply_data[4], &stats, sizeof(stats))
            if len(data) < 56:  # 4 tag + 52 struct minimum (without n_recv_errors)
                return None

            stats_data = data[4:]  # Skip the 4-byte tag

            # Pad to 56 bytes so struct.unpack always succeeds.  Older firmware
            # or PATH-wrapped responses with AES block alignment may yield fewer
            # than 56 bytes; missing trailing fields default to zero.
            if len(stats_data) < 56:
                stats_data = stats_data + b"\x00" * (56 - len(stats_data))

            # Parse with correct field types matching C++ struct
            (
                batt_milli_volts,   # uint16  offset 0
                curr_tx_queue_len,  # uint16  offset 2
                noise_floor,        # int16   offset 4
                last_rssi,          # int16   offset 6
                n_packets_recv,     # uint32  offset 8
                n_packets_sent,     # uint32  offset 12
                total_air_time_secs,# uint32  offset 16
                total_up_time_secs, # uint32  offset 20
                n_sent_flood,       # uint32  offset 24
                n_sent_direct,      # uint32  offset 28
                n_recv_flood,       # uint32  offset 32
                n_recv_direct,      # uint32  offset 36
                err_events,         # uint16  offset 40
                last_snr_raw,       # int16   offset 42
                n_direct_dups,      # uint16  offset 44
                n_flood_dups,       # uint16  offset 46
                total_rx_air_time_secs,  # uint32  offset 48
                n_recv_errors,      # uint32  offset 52
            ) = struct.unpack("<HHhhIIIIIIIIHhHHII", stats_data[:56])

            raw_stats = {
                "batt_milli_volts": batt_milli_volts,
                "curr_tx_queue_len": curr_tx_queue_len,
                "noise_floor": noise_floor,
                "last_rssi": last_rssi,
                "n_packets_recv": n_packets_recv,
                "n_packets_sent": n_packets_sent,
                "total_air_time_secs": total_air_time_secs,
                "total_up_time_secs": total_up_time_secs,
                "n_sent_flood": n_sent_flood,
                "n_sent_direct": n_sent_direct,
                "n_recv_flood": n_recv_flood,
                "n_recv_direct": n_recv_direct,
                "err_events": err_events,
                "last_snr": last_snr_raw / 4.0,  # firmware stores SNR × 4
                "n_direct_dups": n_direct_dups,
                "n_flood_dups": n_flood_dups,
                "total_rx_air_time_secs": total_rx_air_time_secs,
                "n_recv_errors": n_recv_errors,
            }

            # Format as human-readable string
            formatted = self._format_stats(raw_stats)

            # Include raw bytes after the 4-byte tag so callers can forward
            # the binary RepeaterStats struct to companion apps verbatim.
            # Pad to 56 bytes if shorter (companion app expects full struct).
            raw_bytes_after_tag = bytes(stats_data[:56])

            return {
                "raw": raw_stats,
                "formatted": formatted,
                "type": "stats",
                "raw_bytes": raw_bytes_after_tag,
            }

        except Exception as e:
            self._log(f"[ProtocolResponse] Stats parsing failed: {e}")
            return None

    def _parse_telemetry_response(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse telemetry response data (protocol 0x03) according to MeshCore packet structure.

        Expected format:
        - reflected_timestamp (4 bytes, little-endian)
        - CayenneLPP data (remaining bytes)

        Returns None if no valid CayenneLPP sensors can be decoded, allowing
        the caller to fall back to other response types.
        """
        try:
            if len(data) < 8:
                # Need at least tag(4) + one minimal LPP record (ch+type+val = 3)
                return None

            # First 4 bytes: reflected timestamp / tag (little-endian)
            reflected_timestamp = struct.unpack("<I", data[:4])[0]

            # Remaining bytes: CayenneLPP data
            lpp_data = data[4:]

            if len(lpp_data) < 3:
                # Not enough for even one LPP record (channel + type + 1-byte value)
                return None

            # Sanity check: MeshCore telemetry always starts with
            # addVoltage(TELEM_CHANNEL_SELF=1, battery_volts) which produces
            # channel=1, type=0x74 (LPP_VOLTAGE).  Require this signature to
            # distinguish telemetry from other response types that happen to
            # decrypt to >= 8 bytes.
            if lpp_data[0] != 0x01 or lpp_data[1] != 0x74:
                return None

            sensors = _decode_cayenne_lpp(lpp_data)
            if not sensors:
                return None

            self._log(
                f"[ProtocolResponse] CayenneLPP decoded {len(sensors)} sensor(s) "
                f"from {len(lpp_data)} bytes: {lpp_data.hex()}"
            )
            return {
                "type": "telemetry",
                "formatted": (
                    f"Telemetry ({len(sensors)} sensors, "
                    f"ts:{reflected_timestamp})"
                ),
                "reflected_timestamp": reflected_timestamp,
                "sensor_count": len(sensors),
                "sensors": sensors,
                "raw_bytes": bytes(data[4:]),  # LPP data after tag for verbatim forwarding
            }

        except Exception as e:
            self._log(f"[ProtocolResponse] Telemetry parsing failed: {e}")
            return None

    def _format_stats(self, stats: Dict[str, Any]) -> str:
        """Format stats as human-readable string."""
        result = []

        # Battery voltage
        volts = stats["batt_milli_volts"] / 1000.0
        result.append(f"Batt: {volts:.2f}V")

        # TX Queue
        result.append(f"TxQ: {stats['curr_tx_queue_len']}")

        # Signal quality
        result.append(f"RSSI: {stats['last_rssi']}dBm")
        result.append(f"SNR: {stats['last_snr']:.1f}dB")
        result.append(f"NF: {stats['noise_floor']}dB")

        # Packet counts
        result.append(
            f"TX: {stats['n_packets_sent']} "
            f"(F:{stats['n_sent_flood']}/D:{stats['n_sent_direct']})"
        )
        result.append(
            f"RX: {stats['n_packets_recv']} "
            f"(F:{stats['n_recv_flood']}/D:{stats['n_recv_direct']})"
        )

        # Uptime formatting
        uptime = stats["total_up_time_secs"]
        if uptime < 3600:
            result.append(f"Up: {uptime}s")
        elif uptime < 86400:
            hours = uptime // 3600
            mins = (uptime % 3600) // 60
            result.append(f"Up: {hours}h{mins}m")
        else:
            days = uptime // 86400
            hours = (uptime % 86400) // 3600
            result.append(f"Up: {days}d{hours}h")

        # Air time
        result.append(f"TxAir: {stats['total_air_time_secs']}s")
        if stats.get("total_rx_air_time_secs"):
            result.append(f"RxAir: {stats['total_rx_air_time_secs']}s")

        # Error events (only if > 0)
        if stats["err_events"] > 0:
            result.append(f"Err: {stats['err_events']}")

        # RX errors (only if > 0)
        if stats.get("n_recv_errors", 0) > 0:
            result.append(f"RxErr: {stats['n_recv_errors']}")

        # Duplicates (only if > 0)
        if stats["n_direct_dups"] > 0 or stats["n_flood_dups"] > 0:
            result.append(f"Dups: D:{stats['n_direct_dups']}/F:{stats['n_flood_dups']}")

        return " | ".join(result)

    def _find_contact_by_hash(self, contact_hash: int):
        """Find contact by hash value."""
        if not self._contact_book:
            return None

        # Search through contacts to find one with matching hash
        for contact in self._contact_book.list_contacts():
            try:
                contact_pubkey = bytes.fromhex(contact.public_key)
                if contact_pubkey[0] == contact_hash:
                    return contact
            except (ValueError, IndexError):
                continue

        return None

"""Protocol response handler for mesh network protocol requests.

Handles responses to protocol requests (like stats, config, etc.) that come
back as PATH packets with encrypted payloads.
"""

import asyncio
import struct
from typing import Any, Callable, Dict, Optional

from ...hardware.signal_utils import snr_register_to_db
from ...protocol import CryptoUtils, Identity, Packet
from ...protocol.constants import MAX_PATH_SIZE, PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_RESPONSE


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
        """Handle incoming PATH packet that might be a protocol response."""
        try:
            # Check if this looks like an encrypted protocol response
            if len(pkt.payload) < 4:
                return  # Too short for protocol response

            # PATH packet structure:
            # dest_hash(1) + src_hash(1) + encrypted_data(N)
            src_hash = pkt.payload[1]

            # Proceed if we have a callback for this source or the binary (path-discovery) callback
            if src_hash not in self._response_callbacks and self._binary_response_callback is None:
                return

            self._log(
                "[ProtocolResponse] Processing potential protocol response "
                f"from 0x{src_hash:02X}"
            )

            # Try to decrypt the response
            success, decoded_text, parsed_data, raw_decrypted = await self._decrypt_protocol_response(
                pkt, src_hash
            )

            # If binary response callback is set, parse and invoke (plain tag+data or path-return format)
            if (
                success
                and self._binary_response_callback is not None
                and raw_decrypted is not None
                and len(raw_decrypted) >= 4
            ):
                path_info = None
                tag_bytes = raw_decrypted[:4]
                response_data = raw_decrypted[4:]
                # Path-return format (MeshCore createPathReturn): path_len(1), path(path_len), extra_type(1), extra
                path_len = raw_decrypted[0]
                if (
                    path_len <= MAX_PATH_SIZE
                    and len(raw_decrypted) >= 1 + path_len + 1 + 4
                ):
                    out_path = bytes(raw_decrypted[1 : 1 + path_len])
                    extra_type = raw_decrypted[1 + path_len]
                    extra = raw_decrypted[2 + path_len :]
                    if extra_type == PAYLOAD_TYPE_RESPONSE and len(extra) >= 4:
                        tag_bytes = extra[:4]
                        response_data = extra[4:]
                        in_path = bytes(pkt.path) if pkt.path else b""
                        contact = self._find_contact_by_hash(src_hash)
                        if contact:
                            contact_pubkey = bytes.fromhex(contact.public_key)
                            path_info = (out_path, in_path, contact_pubkey)
                try:
                    cb_result = self._binary_response_callback(
                        tag_bytes, response_data, path_info
                    )
                    if asyncio.iscoroutine(cb_result):
                        await cb_result
                except Exception as e:
                    self._log(f"[ProtocolResponse] Binary response callback error: {e}")
                return

            # Call the waiting callback
            callback = self._response_callbacks[src_hash]
            if callback:
                callback(success, decoded_text, parsed_data)

        except Exception as e:
            self._log(f"[ProtocolResponse] Error processing protocol response: {e}")

    async def _decrypt_protocol_response(
        self, pkt: Packet, src_hash: int
    ) -> tuple[bool, str, Dict[str, Any], Optional[bytes]]:
        """Decrypt and parse a protocol response packet. Returns (success, text, parsed_data, raw_decrypted)."""
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

            self._log(f"[ProtocolResponse] Successfully decrypted {len(decrypted)} bytes")

            # Parse based on content type
            success, text, parsed = self._parse_protocol_response(decrypted)
            return success, text, parsed, decrypted

        except Exception as e:
            self._log(f"[ProtocolResponse] Decryption failed: {e}")
            return False, f"Decryption failed: {e}", {}, None

    def _parse_protocol_response(self, data: bytes) -> tuple[bool, str, Dict[str, Any]]:
        """Parse decrypted protocol response data."""
        try:
            # Check if this looks like a stats response (protocol 0x01)
            if len(data) >= 48:
                # Try parsing as RepeaterStats struct
                stats_result = self._parse_stats_response(data)
                if stats_result:
                    return True, stats_result["formatted"], stats_result["raw"]

            # Check if this looks like a telemetry response (protocol 0x03)
            if len(data) >= 4:  # At minimum need some telemetry data
                telemetry_result = self._parse_telemetry_response(data)
                if telemetry_result:
                    return True, telemetry_result["formatted"], telemetry_result

            # Try parsing as text response
            try:
                text_response = data.rstrip(b"\x00").decode("utf-8")
                if text_response.strip():
                    return (
                        True,
                        text_response,
                        {"type": "text", "content": text_response},
                    )
            except UnicodeDecodeError:
                pass

            # Fall back to hex representation
            hex_response = data.hex()
            return (
                True,
                f"Binary response: {hex_response}",
                {"type": "binary", "hex": hex_response},
            )

        except Exception as e:
            return False, f"Parse error: {e}", {}

    def _parse_stats_response(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse RepeaterStats struct response (protocol 0x01)."""
        try:
            # Skip 4-byte header as per C++ code: memcpy(&reply_data[4], &stats, sizeof(stats))
            if len(data) < 52:  # 4 header + 48 struct = 52 minimum
                return None

            stats_data = data[4:]  # Skip the 4-byte header

            # Parse as all 16-bit values - this gives correct results
            parsed = struct.unpack("<24H", stats_data[:48])

            # Map to meaningful field names based on observed values
            raw_stats = {
                "batt_milli_volts": parsed[1],  # Battery voltage in mV
                "curr_tx_queue_len": parsed[2],  # Current TX queue length
                "last_rssi": self._convert_signed_16bit(parsed[3]),  # Last RSSI in dBm
                "n_packets_recv": parsed[5],  # Total packets received
                "n_packets_sent": parsed[7],  # Total packets sent
                "n_recv_flood": parsed[9],  # Flood packets received
                "total_up_time_secs": parsed[11],  # Uptime in seconds
                "total_air_time_secs": parsed[13],  # Air time in seconds
                "err_events": parsed[17],  # Error events count
                "last_snr": snr_register_to_db(parsed[19], bits=16),
                "n_flood_dups": parsed[22],  # Flood duplicate packets
                "n_direct_dups": parsed[23],  # Direct duplicate packets
            }

            # Format as human-readable string
            formatted = self._format_stats(raw_stats)

            return {"raw": raw_stats, "formatted": formatted, "type": "stats"}

        except Exception as e:
            self._log(f"[ProtocolResponse] Stats parsing failed: {e}")
            return None

    def _parse_telemetry_response(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse telemetry response data (protocol 0x03) according to MeshCore packet structure.

        Expected format:
        - reflected_timestamp (4 bytes, little-endian)
        - CayenneLPP data (remaining bytes)
        """
        try:
            if len(data) < 4:
                self._log(
                    "[ProtocolResponse] Telemetry data too short: "
                    f"{len(data)} bytes (need at least 4 for timestamp)"
                )
                return None

            self._log(
                "[ProtocolResponse] Parsing " f"{len(data)} bytes telemetry data: {data.hex()}"
            )

            # Parse according to MeshCore TelemetryResponseData structure
            # First 4 bytes: reflected timestamp (little-endian)
            reflected_timestamp = struct.unpack("<I", data[:4])[0]

            # Remaining bytes: CayenneLPP data
            lpp_data = data[4:]
            self._log(
                f"[ProtocolResponse] CayenneLPP data ({len(lpp_data)} bytes): {lpp_data.hex()}"
            )

            if len(lpp_data) == 0:
                self._log("[ProtocolResponse] No CayenneLPP data after timestamp")
                return {
                    "type": "telemetry",
                    "formatted": f"Empty telemetry (timestamp: {reflected_timestamp})",
                    "reflected_timestamp": reflected_timestamp,
                    "sensor_count": 0,
                    "sensors": [],
                    "original_hex": data.hex(),
                }

            # Remove trailing zeros that confuse the CayenneLPP library
            # Find the last non-zero byte
            last_nonzero = len(lpp_data) - 1
            while last_nonzero >= 0 and lpp_data[last_nonzero] == 0:
                last_nonzero -= 1

            if last_nonzero < len(lpp_data) - 1:
                lpp_data = lpp_data[: last_nonzero + 1]

            # Try using the cayenne_lpp_helpers function (now without trailing zeros) if available
            try:
                try:
                    from utils.cayenne_lpp_helpers import decode_cayenne_lpp_payload

                    helper_result = decode_cayenne_lpp_payload(lpp_data.hex())
                except ImportError:
                    # Utils not available in lightweight mode
                    helper_result = {"error": "cayenne_lpp_helpers not available"}

                if "error" not in helper_result and helper_result.get("sensor_count", 0) > 0:
                    self._log(
                        "[ProtocolResponse] CayenneLPP parsing succeeded: "
                        f"{helper_result['sensor_count']} sensors"
                    )

                    # Convert to our expected format
                    converted_sensors = []
                    for sensor in helper_result["sensors"]:
                        converted_sensor = {
                            "channel": sensor["channel"],
                            "type": sensor["type"],
                            "type_id": sensor["type_id"],
                            "value": sensor["value"],
                            "raw_value": sensor["raw_value"],
                        }
                        converted_sensors.append(converted_sensor)

                    return {
                        "type": "telemetry",
                        "formatted": (
                            f"Telemetry ({len(converted_sensors)} sensors, "
                            f"ts:{reflected_timestamp})"
                        ),
                        "reflected_timestamp": reflected_timestamp,
                        "sensor_count": len(converted_sensors),
                        "sensors": converted_sensors,
                    }
                else:
                    self._log(
                        "[ProtocolResponse] CayenneLPP parsing failed: "
                        f"{helper_result.get('error', 'no sensors found')}"
                    )

            except Exception as e:
                self._log(f"[ProtocolResponse] CayenneLPP parsing exception: {e}")

            # All parsing methods failed
            self._log("[ProtocolResponse] CayenneLPP parsing failed")
            return {
                "type": "telemetry",
                "formatted": (
                    f"Unknown telemetry LPP data ({len(lpp_data)} bytes, "
                    f"ts:{reflected_timestamp})"
                ),
                "reflected_timestamp": reflected_timestamp,
                "sensor_count": 0,
                "sensors": [],
            }

        except Exception as e:
            self._log(f"[ProtocolResponse] Telemetry parsing failed: {e}")
            return {
                "type": "telemetry",
                "length": len(data),
                "hex": data.hex(),
                "format": "error",
                "formatted": f"Telemetry parsing error: {e}",
                "error": str(e),
            }

    def _convert_signed_16bit(self, value: int) -> int:
        """Convert unsigned 16-bit to signed if needed."""
        return value - 65536 if value > 32767 else value

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

        # Packet counts
        result.append(f"RX: {stats['n_packets_recv']}")
        result.append(f"TX: {stats['n_packets_sent']}")
        result.append(f"Flood RX: {stats['n_recv_flood']}")

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
        result.append(f"Air: {stats['total_air_time_secs']}s")

        # Error events (only if > 0)
        if stats["err_events"] > 0:
            result.append(f"Err: {stats['err_events']}")

        # Duplicates (only if > 0)
        if stats["n_direct_dups"] > 0 or stats["n_flood_dups"] > 0:
            result.append(f"Dups: {stats['n_direct_dups']}/{stats['n_flood_dups']}")

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

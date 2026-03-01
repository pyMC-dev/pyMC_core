"""Protocol response handler for mesh network protocol requests.

Handles responses to protocol requests (like stats, config, etc.) that come
back as PATH packets with encrypted payloads.
"""

import asyncio
import struct
from typing import Any, Callable, Dict, Optional

from ...protocol import CryptoUtils, Identity, Packet
from ...protocol.constants import (
    MAX_PATH_SIZE,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RESPONSE,
    ROUTE_TYPE_DIRECT,
)
from ...protocol.crypto import CIPHER_BLOCK_SIZE, CIPHER_MAC_SIZE
from ...protocol.packet_builder import PacketBuilder

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
    0x64: ("Generic Sensor", 4, 1, False),  # LPP_GENERIC_SENSOR  = 100
    0x65: ("Illuminance", 2, 1, False),  # LPP_LUMINOSITY      = 101
    0x66: ("Presence", 1, 1, False),  # LPP_PRESENCE        = 102
    0x67: ("Temperature", 2, 10, True),  # LPP_TEMPERATURE     = 103
    0x68: ("Humidity", 1, 2, False),  # LPP_RELATIVE_HUMIDITY = 104
    0x71: ("Accelerometer", 6, 1000, True),  # LPP_ACCELEROMETER   = 113, 3×int16
    0x73: ("Barometer", 2, 10, False),  # LPP_BAROMETRIC_PRESSURE = 115
    0x74: ("Voltage", 2, 100, False),  # LPP_VOLTAGE         = 116, 0.01V
    0x75: ("Current", 2, 1000, True),  # LPP_CURRENT         = 117, 0.001A signed
    0x76: ("Frequency", 4, 1, False),  # LPP_FREQUENCY       = 118, 1Hz
    0x78: ("Percentage", 1, 1, False),  # LPP_PERCENTAGE      = 120, 1-100%
    0x79: ("Altitude", 2, 1, True),  # LPP_ALTITUDE        = 121, 1m signed
    0x7D: ("Concentration", 2, 1, False),  # LPP_CONCENTRATION   = 125, 1ppm
    0x80: ("Power", 2, 1, False),  # LPP_POWER           = 128, 1W
    0x82: ("Distance", 4, 1000, False),  # LPP_DISTANCE        = 130, 0.001m
    0x83: ("Energy", 4, 1000, False),  # LPP_ENERGY          = 131, 0.001kWh
    0x84: ("Direction", 2, 1, False),  # LPP_DIRECTION       = 132, 1deg
    0x85: ("Unix Time", 4, 1, False),  # LPP_UNIXTIME        = 133
    0x86: ("Gyroscope", 6, 100, True),  # LPP_GYROMETER       = 134, 3×int16
    0x87: ("Colour", 3, 1, False),  # LPP_COLOUR          = 135, RGB
    0x88: ("GPS", 9, 1, True),  # LPP_GPS             = 136, lat(3)+lon(3)+alt(3), mult 10000/100
    0x8E: ("Switch", 1, 1, False),  # LPP_SWITCH          = 142, 0/1
    # LPP_POLYLINE 240: variable size; min 8 bytes (size+delta+lon+lat). Skip min to continue.
    0xF0: ("Polyline", 8, 1, False),  # LPP_POLYLINE       = 240
}


def _decode_cayenne_lpp(data: bytes) -> list:
    """Decode CayenneLPP binary payload into a list of sensor dicts."""
    sensors: list = []
    idx = 0
    while idx + 2 <= len(data):
        channel = data[idx]
        type_id = data[idx + 1]
        # Channel 0 is never used by MeshCore firmware (channels start at
        # TELEM_CHANNEL_SELF=1).  A channel=0 byte is AES zero-padding — stop.
        if channel == 0:
            break
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
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": {"latitude": lat, "longitude": lon, "altitude": alt},
                    "raw_value": raw.hex(),
                }
            )
        elif size == 6 and type_id in (0x71, 0x86):
            # 3-axis: x(2) + y(2) + z(2), all signed
            x = int.from_bytes(raw[0:2], "big", signed=True) / divisor
            y = int.from_bytes(raw[2:4], "big", signed=True) / divisor
            z = int.from_bytes(raw[4:6], "big", signed=True) / divisor
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": {"x": x, "y": y, "z": z},
                    "raw_value": raw.hex(),
                }
            )
        elif type_id == 0x87:
            # Colour: R(1) + G(1) + B(1)
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": {"r": raw[0], "g": raw[1], "b": raw[2]},
                    "raw_value": raw.hex(),
                }
            )
        elif type_id == 0xF0:
            # Polyline: variable size; we only consume minimum 8 bytes (MeshCore skipData).
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": raw.hex(),
                    "raw_value": raw.hex(),
                }
            )
        else:
            val = int.from_bytes(raw, "big", signed=signed)
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": val / divisor if divisor != 1 else val,
                    "raw_value": raw.hex(),
                }
            )
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
        # Optional: decrypted payloads with tag+data (and optional path) passed as binary response.
        # Signature: (tag_bytes, response_data, path_info=None).
        self._binary_response_callback: Optional[Callable[..., Any]] = None
        # Reference to LoginResponseHandler for state-based login detection
        self._login_response_handler: Optional[Any] = None
        # Packet injector for sending reciprocal PATH packets (mirrors C++ Mesh.cpp:168-169)
        self._packet_injector: Optional[Callable] = None
        # Optional: notify when contact out_path is updated from decrypted PATH
        # (e.g. companion persist).
        self._contact_path_updated_callback: Optional[Callable[..., Any]] = None

    def set_contact_path_updated_callback(self, callback: Optional[Callable[..., Any]]) -> None:
        """Set callback when contact out_path is updated from a decrypted PATH packet.

        Signature: (contact_pubkey: bytes, path_len: int, path_bytes: bytes)
        -> None | Awaitable[None].
        Called after _update_contact_path when the contact was found and updated.
        """
        self._contact_path_updated_callback = callback

    def set_login_response_handler(self, handler: Any) -> None:
        """Set login handler ref for checking active login state."""
        self._login_response_handler = handler

    def set_packet_injector(self, injector: Optional[Callable]) -> None:
        """Set packet injector for sending reciprocal PATH packets.

        When the companion receives a flooded PATH from a remote repeater,
        the C++ firmware sends a reciprocal PATH back so the remote repeater
        learns the route to us (Mesh.cpp:168-169).  Without this, the remote
        repeater has no out_path for us and must fall back to plain FLOOD for
        responses — which intermediate repeaters may drop due to transport-code
        region filtering.
        """
        self._packet_injector = injector

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
        """Set callback for binary responses. (tag_bytes, response_data, path_info=None).
        path_info = (out_path, in_path, contact_pubkey) for path-return format."""
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
            pkt_type = (pkt.header >> 2) & 0x0F
            route_label = "FLOOD" if pkt.is_route_flood() else "DIRECT"
            if pkt_type == PAYLOAD_TYPE_RESPONSE:
                self._log(
                    f"[ProtocolResponse] Received RESPONSE (0x01) from 0x{src_hash:02X} "
                    f"({route_label}, {len(pkt.payload)}B)"
                )

            # Proceed if we have a callback for this source or the binary (path-discovery) callback
            if src_hash not in self._response_callbacks and self._binary_response_callback is None:
                return

            # Try to decrypt the response
            (
                success,
                decoded_text,
                parsed_data,
                raw_decrypted,
            ) = await self._decrypt_protocol_response(pkt, src_hash)

            # If an explicit response callback is waiting for this source (e.g. telemetry,
            # stats, repeater command), deliver there first.  The binary/path-discovery
            # callback is a generic fallback for unsolicited binary responses.
            #
            # Guard: only skip when this is a login response (13 bytes, response_code at [4]
            # 0x00/0x01). A broad "decrypted_len < 20" would drop valid PATH-wrapped stats
            # or other short responses and delay stats load after login.
            if src_hash in self._response_callbacks:
                if not success:
                    return
                if self._is_login_response(pkt, raw_decrypted):
                    # Login responses are handled by LoginResponseHandler; do not deliver to
                    # stats/telemetry waiter.
                    return
                callback = self._response_callbacks[src_hash]
                if callback:
                    if parsed_data.get("type") == "telemetry":
                        self._log(
                            f"[ProtocolResponse] Delivering telemetry to waiter "
                            f"(src=0x{src_hash:02X}, {parsed_data.get('sensor_count', 0)} sensors)"
                        )
                    callback(success, decoded_text, parsed_data)
                return

            # If binary response callback set, parse and invoke (tag+data or path-return)
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
                    if path_len_byte <= MAX_PATH_SIZE and len(raw_decrypted) >= inner_offset + 4:
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

                # Do not deliver login responses to the binary callback; they are
                # handled by LoginResponseHandler. Login response format is
                # tag(4) + response_code(1) + keep_alive(1) + is_admin(1) + ...
                # = 13 bytes total, with response_code 0x00 or 0x01.
                if len(response_data) == 9 and response_data[0] in (0x00, 0x01):
                    return

                try:
                    cb_result = self._binary_response_callback(tag_bytes, response_data, path_info)
                    if asyncio.iscoroutine(cb_result):
                        await cb_result
                except Exception as e:
                    self._log(f"[ProtocolResponse] Binary response callback error: {e}")
                return

        except Exception as e:
            self._log(f"[ProtocolResponse] Error processing protocol response: {e}")

    def _is_login_response(self, pkt: Packet, raw_decrypted: Optional[bytes]) -> bool:
        """True if a login is currently pending for the source contact.

        Mirrors the C++ companion firmware pattern: classify responses by
        pending-request state rather than payload content.  The previous
        content-based check (``inner[4] in (0x00, 0x01)``) falsely matched
        CayenneLPP telemetry whose first byte is channel 0x01.
        """
        if not self._login_response_handler:
            return False
        passwords = getattr(self._login_response_handler, "_active_login_passwords", {})
        if not passwords:
            return False
        if len(pkt.payload) < 2:
            return False
        src_hash = pkt.payload[1]
        return src_hash in passwords

    def _update_contact_path(
        self,
        contact_pubkey: bytes,
        src_hash: int,
        path_len_byte: int,
        decrypted: bytes,
    ) -> bool:
        """Update contact out_path from decrypted PATH data (firmware onContactPathRecv pattern).

        When a PATH packet is successfully decrypted, store the return path
        on the contact so that subsequent requests use sendDirect() instead
        of sendFlood().  This mirrors C++ ``BaseChatMesh::onContactPathRecv``.

        Returns True if the contact was found and updated, False otherwise.
        """
        try:
            if path_len_byte > MAX_PATH_SIZE:
                return False
            out_path_bytes = bytes(decrypted[1 : 1 + path_len_byte])
            contact_obj = self._contact_book.get_by_key(contact_pubkey)
            if contact_obj is not None:
                contact_obj.out_path_len = path_len_byte
                contact_obj.out_path = out_path_bytes
                self._contact_book.update(contact_obj)
                self._log(
                    f"[ProtocolResponse] Updated out_path for 0x{src_hash:02X}: "
                    f"path_len={path_len_byte}"
                )
                return True
            else:
                self._log(
                    f"[ProtocolResponse] Cannot update out_path for 0x{src_hash:02X}: "
                    f"contact not found by key"
                )
                return False
        except Exception as e:
            self._log(f"[ProtocolResponse] Failed to update out_path: {e}")
            return False

    async def _send_reciprocal_path(
        self,
        src_hash: int,
        shared_secret: bytes,
        pkt: Packet,
        decrypted: bytes,
        path_len_byte: int,
    ) -> None:
        """Send a reciprocal PATH back to the sender so it learns the route to us.

        Mirrors C++ firmware behaviour (Mesh.cpp lines 166-169):

            mesh::Packet* rpath = createPathReturn(
                &src_hash, secret, pkt->path, pkt->path_len, 0, NULL, 0);
            if (rpath) sendDirect(rpath, path, path_len, 500);

        - ``pkt.path`` is the flood accumulation path on the received PATH
          (the inbound route, e.g. [hash_X, hash_B]).  This is placed inside
          the reciprocal's encrypted payload so the remote repeater stores it
          as *its* ``out_path`` — the route from itself back to us.
        - The reciprocal is sent **DIRECT** using the inner ``out_path``
          extracted from the decrypted data (e.g. [hash_B, hash_X]), which
          routes through the mesh to reach the remote repeater.
        """
        if self._packet_injector is None:
            return
        try:
            our_hash = self._local_identity.get_public_key()[0]
            # The inbound flood path (pkt.path) tells the remote repeater
            # "to reach me, go through these intermediate hops".
            in_path = list(pkt.path) if pkt.path else []

            # Build the reciprocal PATH packet.  create_path_return produces a
            # FLOOD PATH by default; we convert it to DIRECT below.
            reciprocal = PacketBuilder.create_path_return(
                dest_hash=src_hash,
                src_hash=our_hash,
                secret=shared_secret,
                path=in_path,
                extra_type=0xFF,  # no extra payload (dummy, same as C++ NULL/0)
                extra=b"",
            )

            # Convert to DIRECT routing using the inner out_path (the route
            # from us to the remote repeater).
            out_path_bytes = bytes(decrypted[1 : 1 + path_len_byte])
            reciprocal.header = (reciprocal.header & ~0x03) | ROUTE_TYPE_DIRECT
            reciprocal.path = bytearray(out_path_bytes)
            reciprocal.path_len = len(out_path_bytes)

            # Await injection so the reciprocal PATH is serialized through the
            # radio TX pipeline before this method returns.  This ensures the
            # login callback doesn't fire until the reciprocal PATH is in flight,
            # preventing the app's first stats REQ from racing ahead of it.
            await self._packet_injector(reciprocal)

            self._log(
                f"[ProtocolResponse] Sending reciprocal PATH to 0x{src_hash:02X} "
                f"via DIRECT (out_path_len={path_len_byte}, in_path_len={len(in_path)})"
            )
        except Exception as e:
            self._log(f"[ProtocolResponse] Failed to send reciprocal PATH: {e}")

    async def _decrypt_protocol_response(
        self, pkt: Packet, src_hash: int
    ) -> tuple[bool, str, Dict[str, Any], Optional[bytes]]:
        """Decrypt and parse protocol response. Returns (success, text, parsed_data, raw_decrypted).

        Handles both packet types:
        - RESPONSE (0x01): direct → tag(4)+data
        - PATH (0x08): path_len+path(N)+extra_type+extra

        Both use same wire payload layout: dest_hash(1) + src_hash(1) + MAC(2) + ciphertext.
        """
        payload = pkt.get_payload()
        if len(payload) < 2 + 4:  # need dest+src + at least MAC(2)+min ciphertext
            return False, "Payload too short", {}, None
        encrypted_data = payload[2:]
        # MAC(2) + ciphertext. Ciphertext may be block-aligned or truncated (e.g. long PATH
        # packets lose one byte to header size; telemetry PATH 63 bytes). Allow MAC + 15 bytes
        # minimum so we can pad to one block and attempt decrypt.
        enc_len = len(encrypted_data)
        min_enc = CIPHER_MAC_SIZE + (CIPHER_BLOCK_SIZE - 1)  # 17: MAC(2) + 15 ciphertext
        if enc_len < min_enc:
            self._log(
                f"[ProtocolResponse] Payload too short for hash 0x{src_hash:02X}: "
                f"encrypted_data={enc_len}B (need MAC(2)+≥15 bytes ciphertext)"
            )
            return False, "Payload too short", {}, None
        pkt_type = (pkt.header >> 2) & 0x0F

        # Try every contact matching src_hash (same “try all hash matches” as TXT_MSG and PATH ACK).
        # Repeaters use the same ECDH shared secret as login (createPathReturn(..., secret, ...)).
        # Firmware: ed25519_key_exchange uses first 32B of priv (clamped) and (y+1)/(1-y) for peer
        # pub; we match via libsodium ed25519_pk_to_curve25519 + scalarmult.
        contacts_tried = list(self._contacts_by_hash(src_hash))
        for contact in contacts_tried:
            try:
                pk = contact.public_key
                contact_pubkey = pk if isinstance(pk, bytes) else bytes.fromhex(pk)
                if len(contact_pubkey) != 32:
                    continue
                peer_id = Identity(contact_pubkey)
                shared_secret = peer_id.calc_shared_secret(self._local_identity.get_private_key())
                aes_key = shared_secret[:16]
                decrypted = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_data)
            except Exception:
                continue

            # Determine the actual response data based on packet type.
            response_data = decrypted
            if pkt_type == PAYLOAD_TYPE_PATH:
                if len(decrypted) >= 2:
                    path_len_byte = decrypted[0]
                    inner_offset = 1 + path_len_byte + 1
                    if path_len_byte <= MAX_PATH_SIZE and len(decrypted) >= inner_offset:
                        extra_type = decrypted[1 + path_len_byte] & 0x0F
                        if extra_type == PAYLOAD_TYPE_RESPONSE and len(decrypted) > inner_offset:
                            response_data = decrypted[inner_offset:]
                        elif extra_type != PAYLOAD_TYPE_RESPONSE:
                            self._log(
                                f"[ProtocolResponse] PATH format: extra_type=0x{extra_type:02X}, "
                                f"not RESPONSE"
                            )

                    # Firmware pattern (onContactPathRecv): update contact out_path
                    # so subsequent requests use sendDirect() instead of sendFlood().
                    out_path_bytes = bytes(decrypted[1 : 1 + path_len_byte])
                    if self._update_contact_path(
                        contact_pubkey, src_hash, path_len_byte, decrypted
                    ):
                        if self._contact_path_updated_callback is not None:
                            cb_result = self._contact_path_updated_callback(
                                contact_pubkey, path_len_byte, out_path_bytes
                            )
                            if asyncio.iscoroutine(cb_result):
                                await cb_result

                    # Firmware pattern (Mesh.cpp:168-169): send reciprocal PATH back
                    # to the sender so it learns the route to us.  Without this, the
                    # remote repeater has no out_path for us and must fall back to
                    # plain FLOOD for responses — which intermediate repeaters may
                    # drop due to transport-code region filtering.
                    if pkt.is_route_flood():
                        await self._send_reciprocal_path(
                            src_hash,
                            shared_secret,
                            pkt,
                            decrypted,
                            path_len_byte,
                        )

            success, text, parsed = self._parse_protocol_response(response_data)
            return success, text, parsed, decrypted

        # Log once per packet: no contact or HMAC failed for every matching contact
        if not contacts_tried:
            self._log(
                f"[ProtocolResponse] No contact for hash 0x{src_hash:02X}, "
                "cannot decrypt PATH/RESPONSE"
            )
        else:
            self._log(
                f"[ProtocolResponse] HMAC failed for hash 0x{src_hash:02X} "
                f"(tried {len(contacts_tried)} contact(s). Repeater PATH uses same ECDH as login)"
            )
        return False, "Decryption failed: Invalid HMAC", {}, None

    def _parse_protocol_response(self, data: bytes) -> tuple[bool, str, Dict[str, Any]]:
        """Parse decrypted protocol response data.

        Parse order:
        0. Login response (13 bytes, response_code at [4] 0x00/0x01) → binary,
          for LoginResponseHandler.
        1. Telemetry (reflected_timestamp + valid CayenneLPP signature byte check)
        2. Stats (RepeaterStats struct, ≥52 bytes, only when not telemetry)
        3. Text / status (UTF-8 printable after stripping tag + nulls)
        4. Binary fallback

        Telemetry is checked first because CayenneLPP data can be ≥56 bytes for
        sensors with many readings, which would otherwise be misidentified as stats.
        The telemetry signature check (channel=1, type=0x74) is cheap and reliable.
        """
        try:
            # 0. Login responses are 13 bytes (tag(4) + response_code(1) + keep_alive(1) + ...).
            #    Do not parse as telemetry/stats; LoginResponseHandler will handle them.
            if len(data) == 13 and data[4] in (0x00, 0x01):
                return (
                    True,
                    "Binary response: " + data.hex(),
                    {"type": "binary", "hex": data.hex()},
                )

            # 1. Check if this looks like a telemetry response (protocol 0x03).
            #    MeshCore always starts telemetry with addVoltage(TELEM_CHANNEL_SELF=1, ...)
            #    which produces LPP channel=0x01, type=0x74 (LPP_VOLTAGE) as first record.
            #    This signature reliably distinguishes telemetry from stats/text responses.
            if len(data) >= 8:  # tag(4) + at least one LPP record (ch+type+val = 3+)
                telemetry_result = self._parse_telemetry_response(data)
                if telemetry_result and telemetry_result.get("sensor_count", 0) > 0:
                    return True, telemetry_result["formatted"], telemetry_result

            # 2. Check if this looks like a stats response (protocol 0x01).
            #    RepeaterStats is 48-56 bytes + 4-byte tag.  Older firmware
            #    omits n_recv_errors (52 B struct → 56 total); PATH-wrapped
            #    responses may also lose trailing bytes to AES block alignment.
            #    Only reached if telemetry signature check above failed.
            if len(data) >= 56:
                stats_result = self._parse_stats_response(data)
                if stats_result:
                    # Include raw_bytes in the parsed dict so callers can
                    # forward the binary RepeaterStats to companion apps.
                    result_dict = stats_result["raw"]
                    result_dict["type"] = "stats"
                    result_dict["raw_bytes"] = stats_result["raw_bytes"]
                    self._log(
                        f"[ProtocolResponse] STATS: batt={result_dict['batt_milli_volts']}mV, "
                        f"rssi={result_dict['last_rssi']}, snr={result_dict['last_snr']}, "
                        f"raw={len(result_dict['raw_bytes'])}B"
                    )
                    return True, stats_result["formatted"], result_dict

            # 3. Try parsing as text/status response.
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
                batt_milli_volts,  # uint16  offset 0
                curr_tx_queue_len,  # uint16  offset 2
                noise_floor,  # int16   offset 4
                last_rssi,  # int16   offset 6
                n_packets_recv,  # uint32  offset 8
                n_packets_sent,  # uint32  offset 12
                total_air_time_secs,  # uint32  offset 16
                total_up_time_secs,  # uint32  offset 20
                n_sent_flood,  # uint32  offset 24
                n_sent_direct,  # uint32  offset 28
                n_recv_flood,  # uint32  offset 32
                n_recv_direct,  # uint32  offset 36
                err_events,  # uint16  offset 40
                last_snr_raw,  # int16   offset 42
                n_direct_dups,  # uint16  offset 44
                n_flood_dups,  # uint16  offset 46
                total_rx_air_time_secs,  # uint32  offset 48
                n_recv_errors,  # uint32  offset 52
            ) = struct.unpack("<HHhhIIIIIIIIHhHHII", stats_data[:56])

            # Sanity-check key fields to avoid misidentifying non-stats data
            # (e.g. neighbor list binary data parsed as RepeaterStats produces
            # batt=22mV, rssi=-27844, which are obviously invalid).
            if batt_milli_volts > 10000:  # > 10V is unreasonable
                return None
            if last_rssi < -200 or last_rssi > 0:  # RSSI always negative, > -200 dBm
                return None

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
                "formatted": (f"Telemetry ({len(sensors)} sensors, " f"ts:{reflected_timestamp})"),
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
        """Find first contact by hash value."""
        for contact in self._contacts_by_hash(contact_hash):
            return contact
        return None

    def _contacts_by_hash(self, contact_hash: int):
        """Yield all contacts whose public_key first byte matches contact_hash."""
        if not self._contact_book:
            return
        for contact in self._contact_book.list_contacts():
            try:
                contact_pubkey = bytes.fromhex(contact.public_key)
                if contact_pubkey[0] == contact_hash:
                    yield contact
            except (ValueError, IndexError):
                continue

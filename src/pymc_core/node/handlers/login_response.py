import asyncio
import struct
from typing import Callable, Optional

from ...protocol import CryptoUtils, Identity, Packet
from ...protocol.constants import MAX_PATH_SIZE, PAYLOAD_TYPE_ANON_REQ, PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_RESPONSE
from .base import BaseHandler

# Response codes from C++ server
RESP_SERVER_LOGIN_OK = 0x80
# Alternative success code observed in practice
RESP_SERVER_LOGIN_SUCCESS_ALT = 0x00


class LoginResponseHandler(BaseHandler):
    """
    Handles PAYLOAD_TYPE_RESPONSE packets for login authentication responses.

    Expected response format from C++ server:
    - timestamp (4 bytes): Server response timestamp
    - response_code (1 byte): RESP_SERVER_LOGIN_OK (0x80) for success
    - keep_alive_interval (1 byte): Recommended keep-alive interval (secs / 16)
    - is_admin (1 byte): 1 if admin, 0 if guest
    - reserved (1 byte): Reserved for future use
    - random_blob (4 bytes): Random data for packet uniqueness

    """

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_RESPONSE

    def __init__(self, local_identity, contacts, log_fn, login_callback=None):
        self.local_identity = local_identity
        self.contacts = contacts
        self.log = log_fn
        self.login_callback = login_callback  # Callback to notify of login success/failure
        # Store login passwords persistently (not tied to contact objects)
        self._active_login_passwords = {}  # dest_hash -> password
        # Protocol response handler for forwarding telemetry responses
        self._protocol_response_handler = None

    def set_protocol_response_handler(self, protocol_response_handler):
        """Set protocol response handler for forwarding telemetry responses."""
        self._protocol_response_handler = protocol_response_handler

    def set_login_callback(self, callback: Callable[[bool, dict], None]):
        """Set callback to notify when login response is received.

        Args:
            callback: Function that accepts (success: bool, response_data: dict)
        """
        self.login_callback = callback

    def store_login_password(self, dest_hash: int, password: str):
        """Store password for response decryption by destination hash."""
        self._active_login_passwords[dest_hash] = password

    def clear_login_password(self, dest_hash: int):
        """Clear stored password for destination hash."""
        if dest_hash in self._active_login_passwords:
            del self._active_login_passwords[dest_hash]

    async def __call__(self, packet: Packet) -> None:
        """Handle RESPONSE or ANON_REQ packets for login authentication."""
        if len(packet.payload) < 4:
            return

        # Determine packet structure: ANON_REQ has our pubkey at bytes 1-33
        if (
            len(packet.payload) >= 34
            and packet.payload[1:33] == self.local_identity.get_public_key()
        ):
            # ANON_REQ format: dest_hash(1) + pubkey(32) + encrypted_data
            dest_hash = packet.payload[0]
            encrypted_start = 33
            lookup_hash = dest_hash  # For ANON_REQ, look up by destination hash
        else:
            # RESPONSE format: dest_hash(1) + src_hash(1) + encrypted_data
            dest_hash = packet.payload[0]
            src_hash = packet.payload[1]
            encrypted_start = 2
            lookup_hash = src_hash  # For RESPONSE, look up by source hash

            # Check if this response is for us
            our_hash = self.local_identity.get_public_key()[0]
            if dest_hash != our_hash and src_hash != our_hash:
                return

        # Find stored password and matching contact
        if lookup_hash not in self._active_login_passwords:
            # This might be a telemetry response, not a login response
            # Forward to protocol response handler if available
            if self._protocol_response_handler:
                # Create a fake PATH packet format that
                # ProtocolResponseHandler expects
                # PATH format: dest_hash(1) + src_hash(1) + encrypted_data
                # RESPONSE format is already: dest_hash(1) + src_hash(1) + encrypted_data
                # So we can directly forward the packet to the protocol response handler
                try:
                    await self._protocol_response_handler(packet)
                    return
                except Exception as e:
                    self.log(
                        "Error forwarding RESPONSE packet to " f"protocol response handler: {e}"
                    )
            return

        matched_contact = None

        for contact in self.contacts.contacts:
            try:
                contact_pubkey = bytes.fromhex(contact.public_key)
                if len(contact_pubkey) > 0 and contact_pubkey[0] == lookup_hash:
                    matched_contact = contact
                    break
            except Exception:
                continue

        if not matched_contact:
            return

        # Decrypt and process response
        response_data = await self._decrypt_response(packet, matched_contact, encrypted_start)
        if response_data:
            await self._process_login_response(response_data, matched_contact)
            self.clear_login_password(lookup_hash)
        elif self.login_callback:
            await self._safe_callback(False, {"error": "Failed to decrypt login response"})

    async def _decrypt_response(
        self, packet: Packet, contact, encrypted_start: int = 2
    ) -> Optional[dict]:
        """Decrypt the login response using the contact's password."""
        try:
            # Extract encrypted portion (skip the header part)
            encrypted_data = packet.payload[encrypted_start:]

            # Calculate X25519 ECDH shared secret
            contact_pubkey = bytes.fromhex(contact.public_key)
            contact_identity = Identity(contact_pubkey)
            shared_secret = contact_identity.calc_shared_secret(
                self.local_identity.get_private_key()
            )

            # Verify MAC and decrypt using X25519 shared secret
            aes_key = shared_secret[:16]
            plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_data)

            if not plaintext:
                return None

            # If this is a PATH packet, unwrap the path-return envelope to get
            # the inner response.  PATH format after decryption:
            #   path_len(1) + path(N) + extra_type(1) + extra_data(M)
            pkt_type = (packet.header >> 2) & 0x0F
            if pkt_type == PAYLOAD_TYPE_PATH and len(plaintext) >= 2:
                path_len_byte = plaintext[0]
                inner_offset = 1 + path_len_byte + 1  # skip path_len + path + extra_type
                if (
                    path_len_byte <= MAX_PATH_SIZE
                    and len(plaintext) >= inner_offset
                ):
                    extra_type = plaintext[1 + path_len_byte] & 0x0F
                    if extra_type == PAYLOAD_TYPE_RESPONSE and len(plaintext) > inner_offset:
                        plaintext = plaintext[inner_offset:]

            if len(plaintext) < 12:
                return None

            # Parse the C++ response format:
            # timestamp(4) + response_code(1) + keep_alive(1) + is_admin(1) +
            # reserved(1) + random(4)
            timestamp, response_code, keep_alive, is_admin, reserved = struct.unpack(
                "<IBBBB", plaintext[:8]
            )
            random_blob = plaintext[8:12]

            return {
                "timestamp": timestamp,
                "response_code": response_code,
                "keep_alive_interval": keep_alive,
                "is_admin": bool(is_admin),
                "reserved": reserved,
                "random_blob": random_blob,
                "contact": contact,
            }

        except Exception:
            return None

    async def _process_login_response(self, response_data: dict, contact):
        """Process the decrypted login response."""
        response_code = response_data["response_code"]
        success = response_code in (RESP_SERVER_LOGIN_OK, RESP_SERVER_LOGIN_SUCCESS_ALT)

        if success:
            self.log(f"Login successful to '{contact.name}' " f"(code: 0x{response_code:02X})")
            contact.last_login_success = response_data["timestamp"]
            contact.is_admin = response_data["is_admin"]
        else:
            self.log(f"Login failed to '{contact.name}' " f"(code: 0x{response_code:02X})")

        if self.login_callback:
            await self._safe_callback(success, response_data)

    async def _safe_callback(self, success: bool, data: dict):
        """Safely call the login callback without blocking."""
        try:
            if self.login_callback is not None:
                if asyncio.iscoroutinefunction(self.login_callback):
                    await self.login_callback(success, data)
                else:
                    self.login_callback(success, data)
        except Exception as e:
            self.log(f"Error in login callback: {e}")


class AnonReqResponseHandler(BaseHandler):
    """Handler for ANON_REQ packets that might be login responses."""

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ANON_REQ

    def __init__(self, local_identity, contacts, log_fn):
        self.local_identity = local_identity
        self.contacts = contacts
        self.log = log_fn
        self.login_response_handler = LoginResponseHandler(local_identity, contacts, log_fn)

    def set_login_callback(self, callback):
        self.login_response_handler.set_login_callback(callback)

    def store_login_password(self, dest_hash: int, password: str):
        self.login_response_handler.store_login_password(dest_hash, password)

    def clear_login_password(self, dest_hash: int):
        self.login_response_handler.clear_login_password(dest_hash)

    async def __call__(self, packet: Packet) -> None:
        """Check if this ANON_REQ is actually a login response."""
        if (
            len(packet.payload) >= 34
            and packet.payload[1:33] == self.local_identity.get_public_key()
        ):
            await self.login_response_handler(packet)

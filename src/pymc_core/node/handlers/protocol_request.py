"""
Protocol request handler for authenticated client requests.

Handles REQ packets and sends RESPONSE packets with requested data.
"""

import struct
from typing import Callable, Optional

from pymc_core.protocol import PacketBuilder
from pymc_core.protocol.constants import PAYLOAD_TYPE_REQ, PAYLOAD_TYPE_RESPONSE
from pymc_core.protocol.crypto import CryptoUtils

# Request type codes (matching C++ implementation)
REQ_TYPE_GET_STATUS = 0x01
REQ_TYPE_KEEP_ALIVE = 0x02
REQ_TYPE_GET_TELEMETRY_DATA = 0x03
REQ_TYPE_GET_ACCESS_LIST = 0x05
REQ_TYPE_GET_NEIGHBOURS = 0x06
REQ_TYPE_GET_OWNER_INFO = 0x07  # Variable-length: tag(4) + "version\nname\nowner"

# Response delay (matching C++ SERVER_RESPONSE_DELAY)
SERVER_RESPONSE_DELAY_MS = 500


class ProtocolRequestHandler:
    """
    Handler for protocol request packets (PAYLOAD_TYPE_REQ).

    Processes encrypted request packets from authenticated clients and sends
    appropriate RESPONSE packets. Request handling is delegated to callbacks
    for application-specific logic.
    """

    @staticmethod
    def payload_type():
        """Return the payload type this handler processes."""
        return PAYLOAD_TYPE_REQ

    def __init__(
        self,
        local_identity,
        contacts,
        get_client_fn: Optional[Callable] = None,
        request_handlers: Optional[dict] = None,
        log_fn: Optional[Callable] = None,
    ):
        """
        Initialize protocol request handler.

        Args:
            local_identity: LocalIdentity for this handler
            contacts: Contact manager or wrapper providing client lookup
            get_client_fn: Optional function to get client info by hash
            request_handlers: Dict mapping request type codes to handler functions
            log_fn: Optional logging function
        """
        self.local_identity = local_identity
        self.contacts = contacts
        self.get_client_fn = get_client_fn
        self.request_handlers = request_handlers or {}
        self.log = log_fn if log_fn else lambda msg: None

    async def __call__(self, packet):
        """
        Process a protocol request packet.

        Args:
            packet: Packet instance with REQ payload

        Returns:
            Packet: RESPONSE packet to send, or None
        """
        try:
            if len(packet.payload) < 2:
                return None

            dest_hash = packet.payload[0]
            src_hash = packet.payload[1]

            # Verify this packet is for us
            our_hash = self.local_identity.get_public_key()[0]
            if dest_hash != our_hash:
                return None

            self.log(f"Processing REQ from 0x{src_hash:02X}")

            # Get client info
            client = self._get_client(src_hash)
            if not client:
                self.log(f"REQ from unknown client 0x{src_hash:02X}")
                return None

            # Get shared secret
            shared_secret = self._get_shared_secret(client)
            if not shared_secret:
                self.log(f"No shared secret for client 0x{src_hash:02X}")
                return None

            # Decrypt request
            encrypted_data = packet.payload[2:]
            aes_key = shared_secret[:16]

            try:
                plaintext = CryptoUtils.mac_then_decrypt(
                    aes_key, shared_secret, bytes(encrypted_data)
                )
            except Exception as e:
                self.log(f"Failed to decrypt REQ: {e}")
                return None

            # Parse request
            if len(plaintext) < 5:
                self.log("REQ packet too short")
                return None

            timestamp = struct.unpack("<I", plaintext[0:4])[0]
            req_type = plaintext[4]
            req_data = plaintext[5:] if len(plaintext) > 5 else b""

            self.log(f"REQ type=0x{req_type:02X}, timestamp={timestamp}")

            # Handle request
            response_data = await self._handle_request(client, timestamp, req_type, req_data)

            if response_data:
                return self._build_response(packet, client, response_data, shared_secret)

            return None

        except Exception as e:
            self.log(f"Error processing REQ: {e}")
            return None

    def _get_client(self, src_hash: int):
        """Get client info by source hash."""
        if self.get_client_fn:
            return self.get_client_fn(src_hash)

        # Fallback: search in contacts
        if hasattr(self.contacts, "contacts"):
            for contact in self.contacts.contacts:
                if hasattr(contact, "public_key"):
                    pk = (
                        bytes.fromhex(contact.public_key)
                        if isinstance(contact.public_key, str)
                        else contact.public_key
                    )
                    if pk[0] == src_hash:
                        return contact

        return None

    def _get_shared_secret(self, client):
        """Get shared secret for client."""
        if hasattr(client, "shared_secret"):
            return client.shared_secret

        if hasattr(client, "public_key"):
            pk = (
                bytes.fromhex(client.public_key)
                if isinstance(client.public_key, str)
                else client.public_key
            )
            from pymc_core.protocol.identity import Identity

            identity = Identity(pk)
            return identity.calc_shared_secret(self.local_identity.get_private_key())

        return None

    async def _handle_request(self, client, timestamp: int, req_type: int, req_data: bytes):
        """
        Handle request and generate response.

        Args:
            client: Client info object
            timestamp: Request timestamp
            req_type: Request type code
            req_data: Request payload

        Returns:
            bytes: Response data (timestamp + payload) or None
        """
        # Build response with reflected timestamp
        response = bytearray(struct.pack("<I", timestamp))

        # Check if we have a handler for this request type
        if req_type in self.request_handlers:
            handler = self.request_handlers[req_type]
            payload = handler(client, timestamp, req_data)
            if payload is not None:
                response.extend(payload)
                return bytes(response)

        # Default handlers
        if req_type == REQ_TYPE_KEEP_ALIVE:
            return bytes(response)

        self.log(f"No handler for request type 0x{req_type:02X}")
        return None

    def _build_response(self, original_packet, client, response_data: bytes, shared_secret: bytes):
        """
        Build RESPONSE packet to send back to client.

        Args:
            original_packet: Original REQ packet
            client: Client info
            response_data: Response payload (includes timestamp)
            shared_secret: Encryption secret

        Returns:
            Packet: RESPONSE packet ready to send
        """
        try:
            # Get client identity
            from pymc_core.protocol.identity import Identity

            if hasattr(client, "id") and hasattr(client.id, "get_public_key"):
                client_identity = client.id
            else:
                pk = (
                    bytes.fromhex(client.public_key)
                    if isinstance(client.public_key, str)
                    else client.public_key
                )
                client_identity = Identity(pk)

            # Decide routing based on out_path_len if available
            route_type = "direct"
            if hasattr(client, "out_path_len") and client.out_path_len < 0:
                route_type = "flood"

            # Create RESPONSE datagram
            reply_packet = PacketBuilder.create_datagram(
                ptype=PAYLOAD_TYPE_RESPONSE,
                dest=client_identity,
                local_identity=self.local_identity,
                secret=shared_secret,
                plaintext=response_data,
                route_type=route_type,
            )

            # Add path for direct routing if available
            if hasattr(client, "out_path_len") and hasattr(client, "out_path"):
                if client.out_path_len >= 0 and len(client.out_path) > 0:
                    reply_packet.path = bytearray(client.out_path[: client.out_path_len])
                    reply_packet.path_len = client.out_path_len

            self.log(
                f"RESPONSE built for 0x{client_identity.get_public_key()[0]:02X} "
                f"via {route_type.upper()}"
            )

            return reply_packet

        except Exception as e:
            self.log(f"Error building RESPONSE: {e}")
            return None

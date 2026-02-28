import asyncio
from typing import Awaitable, Callable, Optional

from ...protocol import Packet
from ...protocol.constants import PAYLOAD_TYPE_ACK
from .base import BaseHandler


class AckHandler(BaseHandler):
    """
    ACK handler that processes all ACK variants:
    1. Discrete ACK packets (payload type 1)
    2. Bundled ACKs in PATH packets
    3. Encrypted ACK responses (20-byte PATH packets)
    """

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ACK

    def __init__(self, log_fn, dispatcher=None):
        self.log = log_fn
        self.dispatcher = dispatcher
        self._ack_received_callback: Optional[Callable[[int], Awaitable[None] | None]] = None

    def set_ack_received_callback(
        self, callback: Optional[Callable[[int], Awaitable[None] | None]]
    ):
        """Set callback to notify dispatcher when ACK is received."""
        self._ack_received_callback = callback

    def set_dispatcher(self, dispatcher):
        """Set dispatcher reference for contact lookup and waiting ACKs."""
        self.dispatcher = dispatcher

    async def __call__(self, packet: Packet) -> None:
        """Handle discrete ACK packets (payload type 1)."""
        ack_crc = await self.process_discrete_ack(packet)
        if ack_crc is not None:
            await self._notify_ack_received(ack_crc)

    async def process_discrete_ack(self, packet: Packet) -> Optional[int]:
        """Process a discrete ACK packet and return the CRC if valid."""
        self.log(f"Processing discrete ACK: payload_len={len(packet.payload)}")
        self.log(f"ACK payload (hex): {packet.payload.hex().upper()}")

        if len(packet.payload) != 4:
            self.log(f"Invalid ACK length: {len(packet.payload)} bytes (expected 4)")
            return None

        # Extract CRC checksum (4 bytes, little endian per protocol spec)
        crc = int.from_bytes(packet.payload, "little")
        self.log(f"Discrete ACK received: CRC={crc:08X}")
        return crc

    async def process_path_ack_variants(self, packet: Packet) -> Optional[int]:
        """
        Process PATH packets that may contain ACKs in different forms.
        Returns CRC if ACK found, None otherwise.
        """
        if not self.dispatcher:
            return None

        payload = packet.payload
        if len(payload) < 1:
            return None

        self.log(f"Processing PATH packet for ACKs: payload_len={len(payload)}")
        self.log(f"PATH payload (hex): {payload.hex().upper()}")

        # Check for encrypted ACK responses (20-byte PATH packets addressed to us)
        if (
            len(payload) == 20
            and self.dispatcher._waiting_acks
            and self.dispatcher.local_identity
            and self.dispatcher.contact_book
            and len(payload) >= 2
            and payload[0] == self.dispatcher.local_identity.get_public_key()[0]
        ):
            self.log("Checking 20-byte PATH packet for encrypted ACK response")
            ack_crc = await self._try_decrypt_encrypted_ack(payload)
            if ack_crc is not None:
                self.log(f"Found encrypted ACK response: CRC={ack_crc:08X}")
                return ack_crc

        # Check for bundled ACKs in returned path messages
        bundled_crc = await self._process_bundled_ack_in_path(payload)
        if bundled_crc is not None:
            self.log(f"Found bundled ACK: CRC={bundled_crc:08X}")
            return bundled_crc

        return None

    async def _try_decrypt_encrypted_ack(self, payload: bytes) -> Optional[int]:
        """Try to decrypt a 20-byte PATH packet as an encrypted ACK response."""
        try:
            # dest_hash = payload[0]  # Not currently used
            src_hash = payload[1]

            # Find contact for decryption
            contact = await self.dispatcher._find_contact_by_hash(src_hash)
            if not contact:
                return None

            from ...protocol import CryptoUtils, Identity

            peer_id = Identity(bytes.fromhex(contact.public_key))
            shared_secret = peer_id.calc_shared_secret(
                self.dispatcher.local_identity.get_private_key()
            )
            aes_key = shared_secret[:16]

            # Decrypt (skip dest_hash and src_hash)
            mac_and_ciphertext = payload[2:]
            decrypted = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, mac_and_ciphertext)

            if not decrypted or len(decrypted) < 4:
                return None

            # Look for expected CRC in decrypted data
            expected_crcs = set(self.dispatcher._waiting_acks.keys())
            for i in range(len(decrypted) - 3):
                crc_bytes = decrypted[i : i + 4]
                crc_le = int.from_bytes(crc_bytes, "little")
                # crc_be = int.from_bytes(crc_bytes, "big")

                if crc_le in expected_crcs:
                    return crc_le
                # if crc_be in expected_crcs:
                #     return crc_be

            return None

        except Exception as e:
            self.log(f"Error decrypting encrypted ACK: {e}")
            return None

    async def _process_bundled_ack_in_path(self, payload: bytes) -> Optional[int]:
        """Process bundled ACKs in returned path messages according to protocol spec."""
        if len(payload) < 1:
            return None

        path_length = payload[0]

        # Check if we have enough data for: path_length + path + extra_type + extra
        min_required = 1 + path_length + 1 + 4  # +4 for ACK CRC
        if len(payload) < min_required:
            return None

        # Extract extra section
        extra_start = 1 + path_length
        extra_type = payload[extra_start]
        extra_payload = payload[extra_start + 1 :]

        # Check if extra type is ACK
        if extra_type == PAYLOAD_TYPE_ACK:
            if len(extra_payload) >= 4:
                crc = int.from_bytes(extra_payload[:4], "little")
                return crc
            else:
                self.log(f"Bundled ACK too short: {len(extra_payload)} bytes")

        return None

    async def _notify_ack_received(self, crc: int):
        """Notify the dispatcher that an ACK was received."""
        if self._ack_received_callback:
            cb = self._ack_received_callback
            if asyncio.iscoroutinefunction(cb):
                await cb(crc)
            else:
                cb(crc)

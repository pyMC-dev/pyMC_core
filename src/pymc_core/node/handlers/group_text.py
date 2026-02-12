from typing import Optional

from ...protocol import Packet
from ...protocol.constants import PAYLOAD_TYPE_GRP_TXT
from ...protocol.crypto import CryptoUtils
from .base import BaseHandler


class GroupTextHandler(BaseHandler):
    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_GRP_TXT

    def __init__(
        self,
        local_identity,
        contacts,
        log_fn,
        send_packet_fn,
        channel_db=None,
        event_service=None,
        our_node_name=None,
    ):
        self.local_identity = local_identity
        self.contacts = contacts
        self.log = log_fn
        self.send_packet = send_packet_fn
        self.channel_db = channel_db  # Live database instead of static config
        self.event_service = event_service
        self.our_node_name = our_node_name  # Store our node name for echo detection

    def _get_channel_by_hash(self, channel_hash: int) -> Optional[dict]:
        """Find a channel by its hash (first byte of public key) from database."""
        if not self.channel_db:
            self.log("No channel database available")
            return None

        try:
            # Get all channels from database (live query)
            channels = self.channel_db.get_channels()
            for channel in channels:
                if "secret" in channel:
                    # Use consistent channel hash derivation
                    calculated_hash = self._derive_channel_hash(channel["secret"])
                    if calculated_hash == channel_hash:
                        return channel
            return None
        except Exception as e:
            self.log(f"Error querying channel database: {e}")
            return None

    def _derive_channel_hash(self, channel_secret: str) -> int:
        """Derive a consistent channel hash from the secret."""
        import hashlib

        # Convert hex secret to bytes, then derive key
        try:
            secret_bytes = bytes.fromhex(channel_secret)
        except ValueError:
            # If not hex, treat as UTF-8 string
            secret_bytes = channel_secret.encode("utf-8")

        # Simple SHA256 derivation (no salt) to match official spec
        channel_key = hashlib.sha256(secret_bytes).digest()

        # Return first byte as the channel hash
        return channel_key[0]

    def _derive_channel_keys(self, channel_secret: str) -> tuple:
        """Derive all necessary keys from channel secret."""
        import hashlib

        try:
            secret_bytes = bytes.fromhex(channel_secret)
        except ValueError:
            secret_bytes = channel_secret.encode("utf-8")

        # Simple SHA256 derivation to match official spec
        master_key = hashlib.sha256(secret_bytes).digest()

        # Split into different keys
        channel_hash = master_key[0]  # First byte for channel identification
        aes_key = master_key[:16]  # First 16 bytes for AES encryption
        hmac_key = master_key[16:32]  # Next 16 bytes for HMAC

        return channel_hash, aes_key, hmac_key

    def _decrypt_channel_message(
        self, channel_secret: str, mac: bytes, ciphertext: bytes
    ) -> Optional[bytes]:
        """Decrypt a channel message using the channel secret."""
        try:
            # Convert hex secret to bytes
            try:
                secret_bytes = bytes.fromhex(channel_secret)
            except ValueError:
                secret_bytes = channel_secret.encode("utf-8")

            # Ensure we have PUB_KEY_SIZE (32 bytes) for the secret
            if len(secret_bytes) < 32:
                # Pad with zeros if needed
                secret_bytes = secret_bytes + b"\x00" * (32 - len(secret_bytes))
            elif len(secret_bytes) > 32:
                # Truncate if too long
                secret_bytes = secret_bytes[:32]

            expected_mac = CryptoUtils._hmac_sha256(secret_bytes, ciphertext)[:2]

            if mac != expected_mac:
                raise ValueError("Invalid HMAC")

            plaintext = CryptoUtils._aes_decrypt(secret_bytes[:16], ciphertext)
            return plaintext

        except Exception as e:
            self.log(f"Channel message decryption failed: {e}")
            return None

    def _parse_plaintext_message(self, plaintext: bytes) -> Optional[dict]:
        """Parse the decrypted plaintext according to the spec."""
        if len(plaintext) < 5:  # timestamp(4) + flags(1) minimum
            return None

        try:
            timestamp = int.from_bytes(plaintext[:4], "little")
            flags = plaintext[4]
            message_content = plaintext[5:].decode("utf-8", errors="replace")

            # Parse message flags according to spec
            message_type = "unknown"
            if flags == 0x00:
                message_type = "plain_text"
            elif flags == 0x01:
                message_type = "cli_command"
            elif flags == 0x02:
                message_type = "signed_text"
                # For signed messages, first two bytes are sender prefix
                if len(plaintext) >= 7:
                    # sender_prefix = plaintext[5:7]  # Unused for now
                    message_content = plaintext[7:].decode("utf-8", errors="replace")

            return {
                "timestamp": timestamp,
                "flags": flags,
                "message_type": message_type,
                "content": message_content,
            }

        except Exception as e:
            self.log(f"Failed to parse plaintext message: {e}")
            return None

    def _extract_sender_from_message(self, message_content: str) -> tuple:
        """Extract sender name and message body from '<sender>: <message>' format."""
        if ": " in message_content:
            parts = message_content.split(": ", 1)
            if len(parts) == 2:
                return parts[0], parts[1]
        return "Unknown", message_content

    def _is_own_message(self, packet: Packet) -> bool:
        """Check if this packet originated from us by comparing sender name."""
        # Get decrypted data from the packet
        group_data = packet.decrypted.get("group_text_data", {})
        if "sender_name" not in group_data:
            return False

        sender_name = group_data["sender_name"]

        # Debug logging
        self.log(f"[Echo Check] Sender: '{sender_name}', Our node: '{self.our_node_name}'")

        # Check against our stored node name only
        if self.our_node_name and sender_name == self.our_node_name:
            self.log("[Echo Check] Match found - this is our own message")
            return True

        self.log("[Echo Check] No match - this is from another node")
        return False

    async def __call__(self, packet: Packet) -> None:
        """Handle incoming group text messages according to the specification."""
        try:
            payload = packet.get_payload()

            if len(payload) < 4:  # Minimum: channel_hash(1) + cipher_mac(2) + ciphertext(1+)
                self.log("Group text packet too short, ignoring")
                return

            channel_hash = payload[0]
            cipher_mac = payload[1:3]
            ciphertext = payload[3:]

            # Find the channel configuration
            channel = self._get_channel_by_hash(channel_hash)
            if not channel:
                self.log(f"Unknown channel hash: {channel_hash:02X}")
                return

            channel_name = channel.get("name", f"Channel-{channel_hash:02X}")
            self.log(f"Received group message for channel: {channel_name}")

            # Decrypt the message
            plaintext = self._decrypt_channel_message(channel["secret"], cipher_mac, ciphertext)
            if not plaintext:
                self.log("Failed to decrypt channel message")
                return

            # Parse the decrypted message
            parsed_message = self._parse_plaintext_message(plaintext)
            if not parsed_message:
                self.log("Failed to parse decrypted message")
                return

            # Extract sender and message from the content
            sender_name, message_body = self._extract_sender_from_message(parsed_message["content"])

            # Store the message content in the packet for echo detection
            # Use the existing decrypted dictionary to store our data
            packet.decrypted["group_text_data"] = {
                "text": message_body,
                "sender_name": sender_name,
                "channel_name": channel_name,
                "channel_hash": channel_hash,
                "message_type": parsed_message["message_type"],
                "timestamp": parsed_message["timestamp"],
                "flags": parsed_message["flags"],
                "full_content": parsed_message["content"],
            }

            # Check if this message is from ourselves using sender name (echo detection)
            is_own = self._is_own_message(packet)
            if is_own:
                self.log(f"Own echo detected (will publish for heard-count): {sender_name}: {message_body}")

            # Log the group message
            self.log(f"<<< Channel [{channel_name}] {sender_name}: {message_body} >>>")

            # Save to database and broadcast to websockets
            await self._save_and_broadcast_group_message(
                packet,
                sender_name,
                message_body,
                channel_name,
                parsed_message["timestamp"],
                is_outgoing=is_own,
            )

            # Note: Group messages are unverified according to spec, so no ACK needed

        except Exception as e:
            self.log(f"Error processing group text message: {e}")
            import traceback

            self.log(f"Traceback: {traceback.format_exc()}")

    async def _save_and_broadcast_group_message(
        self, packet, sender_name, message_body, channel_name, timestamp, is_outgoing: bool = False
    ):
        """Save the group message to database and broadcast via WebSocket."""
        try:
            # Create message ID for both database and WebSocket
            normalized_timestamp = (timestamp // 1000) * 1000
            content_hash = hash(f"{sender_name}_{message_body}_{normalized_timestamp}") & 0xFFFFFFFF
            message_id = f"grp_{normalized_timestamp}_{content_hash:08x}"

            # Publish channel message event if available
            if self.event_service:
                try:
                    from ..events import MeshEvents

                    channel_hash = f"{packet.get_payload()[0]:02X}"

                    # Extract path from packet (list of node hashes)
                    path = list(packet.path) if hasattr(packet, "path") and packet.path else None

                    # Use a custom message type for single channel message addition
                    message_data = {
                        "message_id": message_id,
                        "channel_name": channel_name,
                        "channel_hash": channel_hash,
                        "sender_name": sender_name,
                        "message_text": message_body,
                        "timestamp": timestamp,
                        "message_type": "group_text",
                        "flags": 0,
                        "full_content": packet.decrypted.get("group_text_data", {}).get(
                            "full_content"
                        ),
                        "is_outgoing": bool(is_outgoing),
                        "path": path,
                        "network_info": {
                            "header": f"0x{packet.header:02X}",
                            "payload_type": packet.get_payload_type(),
                            "payload_len": packet.payload_len,
                            "rssi": getattr(packet, "_rssi", None),
                            "snr": getattr(packet, "_snr", None),
                        },
                    }

                    # Publish channel message event
                    self.event_service.publish_sync(MeshEvents.NEW_CHANNEL_MESSAGE, message_data)
                    self.log("Published group message event")
                except Exception as publish_error:
                    self.log(f"Failed to publish group message event: {publish_error}")
            else:
                self.log(f"No event service available for group message: {channel_name}")

        except Exception as e:
            self.log(f"Error saving/broadcasting group message: {e}")
            import traceback

            self.log(f"Traceback: {traceback.format_exc()}")

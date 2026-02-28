import struct
import time
from typing import Any, Dict, Optional

from ...protocol import Identity, Packet, decode_appdata, parse_advert_payload
from ...protocol.constants import (
    MAX_ADVERT_DATA_SIZE,
    PAYLOAD_TYPE_ADVERT,
    PUB_KEY_SIZE,
    SIGNATURE_SIZE,
    describe_advert_flags,
)
from ...protocol.utils import determine_contact_type_from_flags, get_contact_type_name
from ..events import MeshEvents
from .base import BaseHandler


class AdvertHandler(BaseHandler):
    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ADVERT

    def __init__(self, log_fn, event_service=None):
        self.log = log_fn
        self.event_service = event_service

    def _verify_advert_signature(
        self, pubkey: bytes, timestamp: bytes, appdata: bytes, signature: bytes
    ) -> bool:
        """Verify the cryptographic signature of the advert packet."""
        try:
            if len(pubkey) != PUB_KEY_SIZE:
                self.log(
                    f"Invalid public key length: {len(pubkey)} bytes (expected {PUB_KEY_SIZE})"
                )
                return False

            if len(signature) != SIGNATURE_SIZE:
                self.log(
                    f"Invalid signature length: {len(signature)} bytes (expected {SIGNATURE_SIZE})"
                )
                return False

            peer_identity = Identity(pubkey)
        except ValueError as exc:
            self.log(f"Malformed public key in advert - invalid key format: {exc}")
            return False
        except Exception as exc:
            exc_type = type(exc).__name__
            self.log(
                f"Cryptographic error constructing identity from public key: " f"{exc_type}: {exc}"
            )
            return False

        signed_region = pubkey + timestamp + appdata
        if not peer_identity.verify(signed_region, signature):
            pubkey_prefix = pubkey[:8].hex()
            self.log(f"Signature verification failed for advert " f"(pubkey={pubkey_prefix}...)")
            return False
        return True

    async def __call__(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Process advert packet and return parsed data with signature verification."""
        try:
            payload = packet.get_payload()
            if not payload:
                return None
            try:
                parsed = parse_advert_payload(payload)
            except ValueError as e:
                self.log(f"Advert payload parse error: {e}")
                return None

            pubkey_bytes = bytes.fromhex(parsed["pubkey"])
            pubkey_hex = parsed["pubkey"]
            advert_timestamp = parsed["timestamp"]
            timestamp_bytes = struct.pack("<I", advert_timestamp)
            signature_bytes = bytes.fromhex(parsed["signature"])
            appdata = parsed["appdata"]
            if len(appdata) > MAX_ADVERT_DATA_SIZE:
                self.log(
                    f"Advert appdata too large ({len(appdata)} bytes), "
                    f"truncating to {MAX_ADVERT_DATA_SIZE}"
                )
                appdata = appdata[:MAX_ADVERT_DATA_SIZE]

            # Verify cryptographic signature
            if not self._verify_advert_signature(
                pubkey_bytes, timestamp_bytes, appdata, signature_bytes
            ):
                self.log(f"Rejecting advert with invalid signature (pubkey={pubkey_hex[:8]}...)")
                return None

            self.log(f"Processing advert for pubkey: {pubkey_hex[:16]}...")

            # Decode application data (protocol.utils.decode_appdata)
            decoded = decode_appdata(appdata)

            # Extract name from decoded data
            name = decoded.get("node_name") or decoded.get("name")
            if not name:
                self.log(f"Ignoring advert without name (pubkey={pubkey_hex[:8]}...)")
                return None

            # Extract location and flags
            lon = decoded.get("longitude") or decoded.get("lon") or 0.0
            lat = decoded.get("latitude") or decoded.get("lat") or 0.0
            flags_int = decoded.get("flags", 0)
            flags_description = describe_advert_flags(flags_int)
            contact_type_id = determine_contact_type_from_flags(flags_int)
            contact_type = get_contact_type_name(contact_type_id)

            # Clamp to current time if remote clock is ahead (avoid "future" last-advert in UI)
            now = int(time.time())
            if advert_timestamp > now:
                advert_timestamp = now

            # Build parsed advert data
            advert_data = {
                "public_key": pubkey_hex,
                "name": name,
                "longitude": lon,
                "latitude": lat,
                "flags": flags_int,
                "flags_description": flags_description,
                "contact_type_id": contact_type_id,
                "contact_type": contact_type,
                "advert_timestamp": advert_timestamp,
                "timestamp": int(time.time()),
                "snr": packet._snr if hasattr(packet, "_snr") else 0.0,
                "rssi": packet._rssi if hasattr(packet, "_rssi") else 0,
                "valid": True,
            }

            self.log(f"Parsed advert: {name} ({contact_type})")

            # Publish so companion/app receives node-discovered and advert_received callbacks
            if self.event_service:
                try:
                    event_data = {
                        "public_key": pubkey_hex,
                        "name": name,
                        "contact_type": contact_type_id,
                        "lat": lat,
                        "lon": lon,
                        "advert_timestamp": advert_timestamp,
                        "timestamp": int(time.time()),
                        "snr": advert_data["snr"],
                        "rssi": advert_data["rssi"],
                    }
                    self.event_service.publish_sync(MeshEvents.NODE_DISCOVERED, event_data)
                except Exception as e:
                    self.log(f"Failed to publish NODE_DISCOVERED event: {e}")

            return advert_data

        except Exception as e:
            self.log(f"Error parsing advert packet: {e}")
            return None

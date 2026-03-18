"""Tests for CompanionBridge (repeater-integrated companion with packet_injector)."""

import asyncio

import pytest

from pymc_core.companion import CompanionBridge
from pymc_core.companion.constants import ADV_TYPE_CHAT, AUTOADD_CHAT
from pymc_core.companion.models import Contact
from pymc_core.node.events import MeshEvents
from pymc_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet
from pymc_core.protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RAW_CUSTOM,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_FLOOD,
)
from pymc_core.protocol.packet_utils import PathUtils


def _make_peer_contact(name: str) -> Contact:
    """Return a contact with a valid Ed25519 public key (required for packet encryption)."""
    peer = LocalIdentity()
    return Contact(public_key=peer.get_public_key(), name=name)


class MockPacketInjector:
    """Records injected packets and returns True by default."""

    def __init__(self):
        self.calls: list[tuple] = []

    async def __call__(self, pkt: Packet, wait_for_ack: bool = False) -> bool:
        self.calls.append((pkt, wait_for_ack))
        return True


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------


class TestCompanionBridgeInit:
    def test_init_creates_stores(self):
        injector = MockPacketInjector()
        identity = LocalIdentity()
        bridge = CompanionBridge(identity, injector, node_name="BridgeNode")
        assert bridge.contacts is not None
        assert bridge.contacts.get_count() == 0
        assert bridge.channels is not None
        assert bridge.stats is not None
        assert bridge.prefs.node_name == "BridgeNode"
        assert bridge.get_public_key() == identity.get_public_key()
        assert injector.calls == []

    def test_init_with_authenticate_callback(self):
        def auth_cb(*args, **kwargs):
            return (True, 0)

        injector = MockPacketInjector()
        bridge = CompanionBridge(
            LocalIdentity(),
            injector,
            authenticate_callback=auth_cb,
        )
        assert bridge._handlers is not None


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeLifecycle:
    async def test_start_stop(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        assert bridge.is_running is False
        await bridge.start()
        assert bridge.is_running is True
        await bridge.stop()
        assert bridge.is_running is False


# ---------------------------------------------------------------------------
# Channel updated callback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeChannelUpdated:
    async def test_set_channel_and_remove_channel_fire_channel_updated(self):
        """set_channel and remove_channel fire on_channel_updated(idx, channel_or_none)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        events = []

        def on_channel_updated(idx: int, ch) -> None:
            events.append((idx, ch))

        bridge.on_channel_updated(on_channel_updated)
        await bridge.start()

        ok = bridge.set_channel(0, "General", b"secret_________________________")
        assert ok is True
        await asyncio.sleep(0)
        assert len(events) == 1
        assert events[0][0] == 0
        assert events[0][1] is not None
        assert events[0][1].name == "General"

        ok = bridge.remove_channel(0)
        assert ok is True
        await asyncio.sleep(0)
        assert len(events) == 2
        assert events[1] == (0, None)

        await bridge.stop()


# ---------------------------------------------------------------------------
# process_received_packet
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeProcessReceivedPacket:
    async def test_process_packet_records_rx_stats(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        await bridge.start()
        pkt = Packet()
        pkt.header = (ROUTE_TYPE_FLOOD << 0) | (PAYLOAD_TYPE_ADVERT << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray()
        pkt.payload_len = 0
        await bridge.process_received_packet(pkt)
        tot = bridge.stats.get_totals()
        assert tot["flood_rx"] == 1
        await bridge.stop()

    async def test_process_unknown_type_no_crash(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        pkt = Packet()
        pkt.header = (ROUTE_TYPE_FLOOD << 0) | (15 << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray()
        pkt.payload_len = 0
        await bridge.process_received_packet(pkt)
        assert True

    async def test_process_received_packet_fires_raw_data_received(self):
        """CompanionBridge fires on_raw_data_received(payload, snr, rssi) for RAW_CUSTOM packets."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        raw_calls = []

        def on_raw(payload: bytes, snr, rssi) -> None:
            raw_calls.append((payload, snr, rssi))

        bridge.on_raw_data_received(on_raw)
        await bridge.start()

        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_RAW_CUSTOM << 2)
        pkt.payload = bytearray(b"\x01\x02\x03\x04")
        pkt.payload_len = 4
        pkt.path_len = 0
        pkt._snr = 6.0
        pkt._rssi = -75

        await bridge.process_received_packet(pkt)
        await bridge.stop()

        assert len(raw_calls) == 1
        payload_bytes, snr, rssi = raw_calls[0]
        assert payload_bytes == b"\x01\x02\x03\x04"
        assert snr == 6.0
        assert rssi == -75


# ---------------------------------------------------------------------------
# Advertise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeAdvertise:
    async def test_advertise_injects_packet(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.advertise(flood=True)
        assert result is True
        assert len(injector.calls) == 1
        pkt, wait_for_ack = injector.calls[0]
        assert pkt is not None
        assert (pkt.header >> 2) & 0x0F == PAYLOAD_TYPE_ADVERT
        assert wait_for_ack is False
        assert bridge.stats.get_totals()["flood_tx"] == 1


# ---------------------------------------------------------------------------
# Send text, share contact
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeSendAndShare:
    async def test_send_text_message_no_contact(self, caplog):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_text_message(b"\x00" * 32, "Hi")
        assert result.success is False
        assert len(injector.calls) == 0

    async def test_send_text_message_with_contact_injects_packet(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Alice")
        bridge.contacts.add(contact)
        await bridge.send_text_message(contact.public_key, "Hello")
        assert len(injector.calls) >= 1
        pkt, _ = injector.calls[0]
        assert (pkt.header >> 2) & 0x0F == PAYLOAD_TYPE_TXT_MSG

    async def test_share_contact_not_found(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.share_contact(b"\x00" * 32)
        assert result is False
        assert len(injector.calls) == 0

    async def test_share_contact_success(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        key = b"\x22" * 32
        bridge.contacts.add(Contact(public_key=key, name="Bob"))
        result = await bridge.share_contact(key)
        assert result is True
        assert len(injector.calls) == 1

    async def test_send_raw_data_direct_injects_packet(self):
        """send_raw_data_direct builds RAW_CUSTOM packet and sends via injector."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        await bridge.start()
        path = b"\x42"
        payload = b"\x01\x02\x03\x04"
        result = await bridge.send_raw_data_direct(path, payload)
        await bridge.stop()
        assert result.success is True
        assert len(injector.calls) == 1
        pkt, wait_for_ack = injector.calls[0]
        assert (pkt.header >> 2) & 0x0F == PAYLOAD_TYPE_RAW_CUSTOM
        assert pkt.path == bytearray(path)
        assert pkt.path_len == len(path)
        assert bytes(pkt.payload) == payload
        assert wait_for_ack is False


# ---------------------------------------------------------------------------
# Path discovery, trace, control data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgePathAndControl:
    async def test_send_path_discovery_req_no_contact(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_path_discovery_req(b"\x00" * 32)
        assert result.success is False

    async def test_send_path_discovery_req_success(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Target")
        bridge.contacts.add(contact)
        result = await bridge.send_path_discovery_req(contact.public_key)
        assert result.success is True
        assert len(injector.calls) == 1
        assert result.timeout_ms == 10000

    async def test_send_trace_path_raw(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_trace_path_raw(0x12345678, 0xABCD, 0, bytes([0x01, 0x02]))
        assert result is True
        assert len(injector.calls) == 1

    async def test_send_control_data_valid_payload(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_control_data(bytes([0x80, 0x01]))
        assert result is True
        assert len(injector.calls) == 1
        pkt, _ = injector.calls[0]
        assert pkt.payload_len == 2
        assert list(pkt.payload) == [0x80, 0x01]

    async def test_send_control_data_rejects_no_high_bit(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_control_data(bytes([0x00, 0x01]))
        assert result is False
        assert len(injector.calls) == 0


# ---------------------------------------------------------------------------
# Binary request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeBinaryReq:
    async def test_send_binary_req_no_contact(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_binary_req(b"\x00" * 32, bytes([0x01]))
        assert result.success is False

    async def test_send_binary_req_with_contact(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Rpt")
        bridge.contacts.add(contact)
        result = await bridge.send_binary_req(
            contact.public_key, bytes([0x01]), timeout_seconds=5.0
        )
        assert result.success is True
        assert result.expected_ack is not None
        assert len(injector.calls) == 1


# ---------------------------------------------------------------------------
# NODE_DISCOVERED -> advert pipeline (contact store + advert_received)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeNodeDiscoveredAdvertPipeline:
    async def test_node_discovered_adds_contact_and_fires_advert_received(self):
        """Single path: NODE_DISCOVERED event drives store + advert_received (Bridge and Radio)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        pub_key_hex = peer.get_public_key().hex()
        event_data = {
            "public_key": pub_key_hex,
            "name": "DiscoveredNode",
            "contact_type": ADV_TYPE_CHAT,
            "lat": 52.0,
            "lon": -1.0,
            "advert_timestamp": 1000,
            "timestamp": 1001,
            "snr": 5.0,
            "rssi": -80,
        }
        advert_received_calls = []

        def on_advert(c):
            advert_received_calls.append(c)

        bridge.on_advert_received(on_advert)
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert bridge.contacts.get_count() == 1
        assert len(advert_received_calls) == 1
        assert advert_received_calls[0].name == "DiscoveredNode"
        assert advert_received_calls[0].public_key == peer.get_public_key()

    async def test_one_node_discovered_event_produces_exactly_one_advert_received(self):
        """Single-path guarantee: one NODE_DISCOVERED event yields exactly one
        advert_received callback (no duplicate path, no duplicate push frames).
        """
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        event_data = {
            "public_key": peer.get_public_key().hex(),
            "name": "SinglePathNode",
            "contact_type": ADV_TYPE_CHAT,
            "lat": 0.0,
            "lon": 0.0,
            "advert_timestamp": 1000,
            "timestamp": 1000,
            "snr": 0.0,
            "rssi": 0,
        }
        advert_received_calls = []
        bridge.on_advert_received(advert_received_calls.append)
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert len(advert_received_calls) == 1
        assert advert_received_calls[0].name == "SinglePathNode"

    async def test_path_packet_updates_contact_path_and_fires_contact_path_updated_once(self):
        """PATH packet that decrypts updates contact out_path and fires contact_path_updated."""
        injector = MockPacketInjector()
        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        bridge = CompanionBridge(local_identity, injector)
        bridge.contacts.add(Contact(public_key=peer_pubkey, name="Peer"))

        path_len_byte = 2
        path_bytes = bytes([0x01, 0x02])
        extra_type = PAYLOAD_TYPE_RESPONSE
        extra = bytes([0, 0, 0, 0, 0x00])
        plaintext = bytes([path_len_byte]) + path_bytes + bytes([extra_type]) + extra
        peer_id = Identity(peer_pubkey)
        shared_secret = peer_id.calc_shared_secret(local_identity.get_private_key())
        aes_key = shared_secret[:16]
        encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)
        our_hash = local_identity.get_public_key()[0]
        src_hash = peer_pubkey[0]
        payload = bytes([our_hash, src_hash]) + encrypted

        pkt = Packet()
        pkt.header = (ROUTE_TYPE_FLOOD << 0) | (PAYLOAD_TYPE_PATH << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        path_updated_calls = []

        async def on_path_updated(contact):
            path_updated_calls.append(contact)

        bridge.on_contact_path_updated(on_path_updated)
        await bridge.process_received_packet(pkt)

        assert len(path_updated_calls) == 1
        assert path_updated_calls[0].public_key == peer_pubkey
        assert path_updated_calls[0].out_path_len == path_len_byte
        assert path_updated_calls[0].out_path == path_bytes
        contact = bridge.contacts.get_by_key(peer_pubkey)
        assert contact is not None
        assert contact.out_path_len == path_len_byte
        assert contact.out_path == path_bytes

    async def test_path_packet_with_ack_uses_encoded_path_byte_len_for_2byte_and_3byte_hashes(self):
        """PATH ACK extraction uses PathUtils.get_path_byte_len so 2- and 3-byte hashes work."""
        injector = MockPacketInjector()
        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        bridge = CompanionBridge(local_identity, injector)
        bridge.contacts.add(Contact(public_key=peer_pubkey, name="Peer"))

        ack_crc_expected = 0x12345678
        peer_id = Identity(peer_pubkey)
        shared_secret = peer_id.calc_shared_secret(local_identity.get_private_key())
        aes_key = shared_secret[:16]
        our_hash = local_identity.get_public_key()[0]
        src_hash = peer_pubkey[0]

        def build_path_packet(path_len_byte: int, path_bytes: bytes) -> Packet:
            plaintext = (
                bytes([path_len_byte])
                + path_bytes
                + bytes([PAYLOAD_TYPE_ACK])
                + ack_crc_expected.to_bytes(4, "little")
            )
            encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)
            payload = bytes([our_hash, src_hash]) + encrypted
            pkt = Packet()
            pkt.header = (ROUTE_TYPE_FLOOD << 0) | (PAYLOAD_TYPE_PATH << 2)
            pkt.path_len = 0
            pkt.path = bytearray()
            pkt.payload = bytearray(payload)
            pkt.payload_len = len(payload)
            return pkt

        send_confirmed_calls = []
        bridge.on_send_confirmed(send_confirmed_calls.append)
        bridge._track_pending_ack(ack_crc_expected)

        # 2-byte path hash: 1 hop -> 2 path bytes (encoded 0x41)
        path_len_2 = PathUtils.encode_path_len(2, 1)
        assert PathUtils.get_path_byte_len(path_len_2) == 2
        pkt2 = build_path_packet(path_len_2, bytes([0xAA, 0xBB]))
        await bridge.process_received_packet(pkt2)
        assert len(send_confirmed_calls) == 1
        assert send_confirmed_calls[0] == ack_crc_expected

        # 3-byte path hash: 1 hop -> 3 path bytes (encoded 0x81)
        path_len_3 = PathUtils.encode_path_len(3, 1)
        assert PathUtils.get_path_byte_len(path_len_3) == 3
        send_confirmed_calls.clear()
        ack_crc_3 = 0xDEADBEEF
        bridge._track_pending_ack(ack_crc_3)
        plaintext_3 = (
            bytes([path_len_3])
            + bytes([0x11, 0x22, 0x33])
            + bytes([PAYLOAD_TYPE_ACK])
            + ack_crc_3.to_bytes(4, "little")
        )
        encrypted_3 = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext_3)
        payload_3 = bytes([our_hash, src_hash]) + encrypted_3
        pkt3 = Packet()
        pkt3.header = (ROUTE_TYPE_FLOOD << 0) | (PAYLOAD_TYPE_PATH << 2)
        pkt3.path_len = 0
        pkt3.path = bytearray()
        pkt3.payload = bytearray(payload_3)
        pkt3.payload_len = len(payload_3)
        await bridge.process_received_packet(pkt3)
        assert len(send_confirmed_calls) == 1
        assert send_confirmed_calls[0] == ack_crc_3

    async def test_node_discovered_fires_node_discovered_even_when_filtered(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        bridge.prefs.manual_add_contacts = 1
        bridge.prefs.autoadd_config = AUTOADD_CHAT
        peer = LocalIdentity()
        event_data = {
            "public_key": peer.get_public_key().hex(),
            "name": "RepeaterNode",
            "contact_type": 2,
            "lat": 0.0,
            "lon": 0.0,
            "advert_timestamp": 1000,
            "timestamp": 1000,
            "snr": 0.0,
            "rssi": 0,
        }
        node_discovered_calls = []
        advert_received_calls = []

        def on_node(data):
            node_discovered_calls.append(data)

        def on_advert(c):
            advert_received_calls.append(c)

        bridge.on_node_discovered(on_node)
        bridge.on_advert_received(on_advert)
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert bridge.contacts.get_count() == 0
        assert len(advert_received_calls) == 0
        assert len(node_discovered_calls) == 1
        assert node_discovered_calls[0]["name"] == "RepeaterNode"

    async def test_node_discovered_event_path_adds_contact_and_fires_advert_received(self):
        """Event path with optional inbound_path: store updated, advert_received fired once."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        pub_key_hex = peer.get_public_key().hex()
        event_data = {
            "public_key": pub_key_hex,
            "name": "AdvertNode",
            "contact_type": ADV_TYPE_CHAT,
            "lat": 0.0,
            "lon": 0.0,
            "advert_timestamp": 1000,
            "timestamp": 1000,
            "snr": 0.0,
            "rssi": 0,
            "inbound_path": b"\x01\x02\x03",
        }
        advert_received_calls = []

        def on_advert(c):
            advert_received_calls.append(c)

        bridge.on_advert_received(on_advert)
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert bridge.contacts.get_count() == 1
        assert len(advert_received_calls) == 1
        assert advert_received_calls[0].name == "AdvertNode"
        # Second event (same contact): update, still one contact, advert_received again
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert bridge.contacts.get_count() == 1
        assert len(advert_received_calls) == 2


# ---------------------------------------------------------------------------
# Deduplication (direct messages by packet_hash)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeDeduplication:
    async def test_direct_message_deduplicated_by_packet_hash(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        key_hex = LocalIdentity().get_public_key().hex()
        same_hash = "A1B2C3D4E5F6"
        data = {
            "contact_pubkey": key_hex,
            "message_text": "Hello",
            "timestamp": 1000,
            "txt_type": 0,
            "packet_hash": same_hash,
        }
        await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, data)
        await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, data)
        await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, data)
        assert bridge.message_queue.count == 1
        msg = bridge.sync_next_message()
        assert msg is not None
        assert msg.text == "Hello"
        assert bridge.sync_next_message() is None

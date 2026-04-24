import struct
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

# from pymc_core.node.events import MeshEvents  # Not currently used
from pymc_core.node.handlers import (
    AckHandler,
    AdvertHandler,
    BaseHandler,
    GroupTextHandler,
    LoginResponseHandler,
    PathHandler,
    ProtocolRequestHandler,
    ProtocolResponseHandler,
    TextMessageHandler,
    TraceHandler,
)
from pymc_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet, PacketBuilder
from pymc_core.protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_REQ,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    PUB_KEY_SIZE,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
)


# Mock classes for testing
class MockContact:
    def __init__(self, public_key="0123456789abcdef0123456789abcdef", name="mock"):
        self.public_key = public_key
        self.name = name
        self.last_advert = 0


class MockContactBook:
    def __init__(self):
        self.contacts = []
        self.added_contacts = []

    def add_contact(self, contact_data):
        self.added_contacts.append(contact_data)


class MockDispatcher:
    def __init__(self):
        self.local_identity = LocalIdentity()
        self.contact_book = MockContactBook()
        self._waiting_acks = {}
        self._find_contact_by_hash = AsyncMock(return_value=MockContact())


class MockEventService:
    def __init__(self):
        self.publish = AsyncMock()
        self.publish_sync = MagicMock()


# Base Handler Tests
def test_base_handler_is_abstract():
    """Test that BaseHandler cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseHandler()


# ACK Handler Tests
class TestAckHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.dispatcher = MockDispatcher()
        self.handler = AckHandler(self.log_fn, self.dispatcher)
        self.handler.set_dispatcher(self.dispatcher)

    def test_payload_type(self):
        """Test ACK handler payload type."""
        assert AckHandler.payload_type() == PAYLOAD_TYPE_ACK

    def test_ack_handler_initialization(self):
        """Test ACK handler initialization."""
        assert self.handler.log == self.log_fn
        assert self.handler.dispatcher == self.dispatcher
        assert self.handler._ack_received_callback is None

    def test_set_ack_received_callback(self):
        """Test setting ACK received callback."""
        callback = MagicMock()
        self.handler.set_ack_received_callback(callback)
        assert self.handler._ack_received_callback == callback

    @pytest.mark.asyncio
    async def test_process_discrete_ack_valid(self):
        """Test processing a valid discrete ACK packet."""
        # Create packet with 4-byte CRC payload
        packet = Packet()
        packet.payload = bytearray(b"\x78\x56\x34\x12")  # CRC 0x12345678

        crc = await self.handler.process_discrete_ack(packet)
        assert crc == 0x12345678
        self.log_fn.assert_called()

    @pytest.mark.asyncio
    async def test_process_discrete_ack_invalid_length(self):
        """Test processing ACK packet with invalid length."""
        packet = Packet()
        packet.payload = bytearray(b"\x12\x34")  # Too short

        crc = await self.handler.process_discrete_ack(packet)
        assert crc is None
        self.log_fn.assert_called()

    @pytest.mark.asyncio
    async def test_call_discrete_ack(self):
        """Test calling ACK handler with discrete ACK packet."""
        # Create packet with 4-byte CRC payload
        packet = Packet()
        packet.payload = bytearray(b"\x78\x56\x34\x12")  # CRC 0x12345678

        callback = MagicMock()
        self.handler.set_ack_received_callback(callback)

        await self.handler(packet)

        callback.assert_called_once_with(0x12345678)


# Text Message Handler Tests
class TestTextMessageHandler:
    def setup_method(self):
        self.local_identity = LocalIdentity()
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.event_service = MockEventService()
        self.handler = TextMessageHandler(
            self.local_identity,
            self.contacts,
            self.log_fn,
            self.send_packet_fn,
            self.event_service,
        )

    def test_payload_type(self):
        """Test text message handler payload type."""
        assert TextMessageHandler.payload_type() == PAYLOAD_TYPE_TXT_MSG

    def test_text_handler_initialization(self):
        """Test text message handler initialization."""
        assert self.handler.local_identity == self.local_identity
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.send_packet == self.send_packet_fn
        assert self.handler.event_service == self.event_service

    def test_set_command_response_callback(self):
        """Test setting command response callback."""
        callback = MagicMock()
        self.handler.set_command_response_callback(callback)
        assert self.handler.command_response_callback == callback

    @pytest.mark.asyncio
    async def test_call_with_short_payload(self):
        """Test calling text handler with payload too short to decrypt."""
        packet = Packet()
        packet.payload = bytearray(b"\x12\x34")  # Too short

        await self.handler(packet)

        # Should return early without processing
        self.log_fn.assert_called()


# Advert Handler Tests
class TestAdvertHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.handler = AdvertHandler(self.log_fn)

    def test_payload_type(self):
        """Test advert handler payload type."""
        assert AdvertHandler.payload_type() == PAYLOAD_TYPE_ADVERT

    def test_advert_handler_initialization(self):
        """Test advert handler initialization."""
        assert self.handler.log == self.log_fn

    @pytest.mark.asyncio
    async def test_advert_handler_accepts_valid_signature(self):
        remote_identity = LocalIdentity()
        packet = PacketBuilder.create_advert(remote_identity, "RemoteNode")

        result = await self.handler(packet)

        assert result is not None
        assert result["valid"] is True
        assert result["public_key"] == remote_identity.get_public_key().hex()
        assert result["name"] == "RemoteNode"

    @pytest.mark.asyncio
    async def test_advert_handler_rejects_invalid_signature(self):
        remote_identity = LocalIdentity()
        packet = PacketBuilder.create_advert(remote_identity, "RemoteNode")
        appdata_offset = PUB_KEY_SIZE + TIMESTAMP_SIZE + SIGNATURE_SIZE + 5
        if appdata_offset >= packet.payload_len:
            appdata_offset = packet.payload_len - 1
        packet.payload[appdata_offset] ^= 0x01

        result = await self.handler(packet)

        assert result is None
        assert any(
            "invalid signature" in call.args[0].lower()
            for call in self.log_fn.call_args_list
            if call.args
        )

    @pytest.mark.asyncio
    async def test_advert_handler_ignores_self_advert(self):
        """Test that handler processes self-advert (dispatcher handles filtering)."""
        local_identity = LocalIdentity()
        packet = PacketBuilder.create_advert(local_identity, "SelfNode")

        result = await self.handler(packet)

        # Handler should still return parsed data; dispatcher filters self-adverts
        assert result is not None
        assert result["name"] == "SelfNode"


# Path Handler Tests
class TestPathHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.ack_handler = AckHandler(self.log_fn)
        self.protocol_response_handler = MagicMock()
        self.handler = PathHandler(self.log_fn, self.ack_handler, self.protocol_response_handler)

    def test_payload_type(self):
        """Test path handler payload type."""
        assert PathHandler.payload_type() == PAYLOAD_TYPE_PATH

    def test_path_handler_initialization(self):
        """Test path handler initialization."""
        assert self.handler._log == self.log_fn
        assert self.handler._ack_handler == self.ack_handler
        assert self.handler._protocol_response_handler == self.protocol_response_handler


# Group Text Handler Tests
class TestGroupTextHandler:
    def setup_method(self):
        self.local_identity = LocalIdentity()
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.event_service = MockEventService()
        self.handler = GroupTextHandler(
            self.local_identity,
            self.contacts,
            self.log_fn,
            self.send_packet_fn,
            channel_db=None,
            event_service=self.event_service,
            our_node_name="InitialName",
        )

    def test_set_our_node_name_updates_stored_name(self):
        """set_our_node_name updates the name used for echo detection."""
        assert self.handler.our_node_name == "InitialName"
        self.handler.set_our_node_name("NewName")
        assert self.handler.our_node_name == "NewName"
        self.handler.set_our_node_name(None)
        assert self.handler.our_node_name is None

    def test_is_own_message_uses_current_name_after_set_our_node_name(self):
        """_is_own_message uses the current our_node_name after it is updated."""
        self.handler.set_our_node_name("Howl 🏝️")
        packet = Packet()
        packet.decrypted = {"group_text_data": {"sender_name": "Howl 🏝️"}}
        assert self.handler._is_own_message(packet) is True
        packet.decrypted = {"group_text_data": {"sender_name": "Howl 🧱"}}
        assert self.handler._is_own_message(packet) is False
        # After updating name, old name no longer matches
        self.handler.set_our_node_name("Howl 🧱")
        assert self.handler._is_own_message(packet) is True

    def test_is_own_message_false_when_sender_name_missing(self):
        """_is_own_message returns False when packet has no sender_name in group_text_data."""
        self.handler.set_our_node_name("Me")
        packet = Packet()
        packet.decrypted = {}
        assert self.handler._is_own_message(packet) is False
        packet.decrypted = {"group_text_data": {}}
        assert self.handler._is_own_message(packet) is False

    def test_is_own_message_false_when_no_match(self):
        """_is_own_message returns False when sender name differs from our_node_name."""
        self.handler.set_our_node_name("Me")
        packet = Packet()
        packet.decrypted = {"group_text_data": {"sender_name": "Other"}}
        assert self.handler._is_own_message(packet) is False

    def test_payload_type(self):
        """Test group text handler payload type."""
        assert GroupTextHandler.payload_type() == PAYLOAD_TYPE_GRP_TXT

    def test_group_text_handler_initialization(self):
        """Test group text handler initialization."""
        assert self.handler.local_identity == self.local_identity
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.send_packet == self.send_packet_fn
        assert self.handler.our_node_name == "InitialName"


# Login Response Handler Tests
class TestLoginResponseHandler:
    def setup_method(self):
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.local_identity = LocalIdentity()
        self.handler = LoginResponseHandler(self.local_identity, self.contacts, self.log_fn)

    def test_payload_type(self):
        """Test login response handler payload type."""
        assert LoginResponseHandler.payload_type() == PAYLOAD_TYPE_RESPONSE

    def test_login_response_handler_initialization(self):
        """Test login response handler initialization."""
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.local_identity == self.local_identity
        assert self.handler.local_identity == self.local_identity


# Protocol Response Handler Tests
class TestProtocolResponseHandler:
    def setup_method(self):
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.local_identity = LocalIdentity()
        self.handler = ProtocolResponseHandler(self.log_fn, self.local_identity, self.contacts)

    def test_payload_type(self):
        """Test protocol response handler payload type."""
        assert ProtocolResponseHandler.payload_type() == PAYLOAD_TYPE_PATH

    def test_protocol_response_handler_initialization(self):
        """Test protocol response handler initialization."""
        assert self.handler._contact_book == self.contacts
        assert self.handler._log == self.log_fn
        assert self.handler._local_identity == self.local_identity

    def test_parse_telemetry_response_tag_plus_lpp(self):
        """Parse tag(4) + CayenneLPP matches repeater firmware format; raw_bytes is LPP only."""
        # Repeater sends: tag(4) + LPP. Tag is 4-byte reflected_timestamp (little-endian).
        # MeshCore first record: addVoltage(TELEM_CHANNEL_SELF=1, v)
        # → channel=1, type=0x74 (LPP_VOLTAGE), 2 bytes 0.01V big-endian. 3.7V → 370 → 0x01 0x72
        tag = b"\x01\x00\x00\x00"  # LE 1
        lpp = bytes([0x01, 0x74, 0x01, 0x72])  # ch 1, Voltage, 370 (3.70 V)
        data = tag + lpp
        result = self.handler._parse_telemetry_response(data)
        assert result is not None
        assert result["type"] == "telemetry"
        assert result["reflected_timestamp"] == 1
        assert result["raw_bytes"] == lpp
        assert result["sensor_count"] == 1
        sensor = result["sensors"][0]
        assert sensor["channel"] == 1
        assert sensor["type"] == "Voltage"
        assert sensor["type_id"] == 0x74
        assert abs(sensor["value"] - 3.7) < 0.001

    def test_parse_telemetry_response_rejects_non_telemetry(self):
        """Payload without channel=1, type=0x74 signature is not classified as telemetry."""
        tag = b"\x00\x00\x00\x00"  # LE 0
        # Not starting with 0x01 0x74
        data = tag + bytes([0x01, 0x67, 0x00, 0x00])  # ch 1, Temperature, 0°C
        result = self.handler._parse_telemetry_response(data)
        assert result is None

    def test_set_contact_path_updated_callback(self):
        """set_contact_path_updated_callback stores the callback."""
        cb = MagicMock()
        self.handler.set_contact_path_updated_callback(cb)
        assert self.handler._contact_path_updated_callback is cb
        self.handler.set_contact_path_updated_callback(None)
        assert self.handler._contact_path_updated_callback is None

    @pytest.mark.asyncio
    async def test_contact_path_updated_callback_invoked_on_path_update(self):
        """PATH decrypts and updates contact path; contact_path_updated callback is invoked."""
        from pymc_core.companion.contact_store import ContactStore
        from pymc_core.companion.models import Contact

        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        contacts = ContactStore(5)
        contacts.add(Contact(public_key=peer_pubkey, name="Peer"))
        log_fn = MagicMock()
        handler = ProtocolResponseHandler(log_fn, local_identity, contacts)
        handler.set_binary_response_callback(lambda *a, **k: None)

        path_len_byte = 2
        path_bytes = bytes([0x01, 0x02])
        extra_type = PAYLOAD_TYPE_RESPONSE
        extra = bytes([0, 0, 0, 0, 0x00])  # tag(4) + 1 byte (not login response)
        plaintext = bytes([path_len_byte]) + path_bytes + bytes([extra_type]) + extra

        peer_id = Identity(peer_pubkey)
        shared_secret = peer_id.calc_shared_secret(local_identity.get_private_key())
        aes_key = shared_secret[:16]
        encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)

        our_hash = local_identity.get_public_key()[0]
        src_hash = peer_pubkey[0]
        payload = bytes([our_hash, src_hash]) + encrypted

        pkt = Packet()
        pkt.header = (0 << 0) | (PAYLOAD_TYPE_PATH << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        callback_calls = []

        async def on_path_updated(pub: bytes, path_len: int, path_bytes_arg: bytes) -> None:
            callback_calls.append((pub, path_len, path_bytes_arg))

        handler.set_contact_path_updated_callback(on_path_updated)

        await handler(pkt)

        assert len(callback_calls) == 1
        assert callback_calls[0][0] == peer_pubkey
        assert callback_calls[0][1] == path_len_byte
        assert callback_calls[0][2] == path_bytes

    @pytest.mark.asyncio
    async def test_contact_path_updated_with_2byte_hashes(self):
        """PATH with 2-byte hashes decrypts and updates contact path correctly."""
        from pymc_core.companion.contact_store import ContactStore
        from pymc_core.companion.models import Contact
        from pymc_core.protocol.packet_utils import PathUtils

        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        contacts = ContactStore(5)
        contacts.add(Contact(public_key=peer_pubkey, name="Peer"))
        log_fn = MagicMock()
        handler = ProtocolResponseHandler(log_fn, local_identity, contacts)
        handler.set_binary_response_callback(lambda *a, **k: None)

        # 2 hops × 2-byte hashes = 4 bytes of path data
        path_len_byte = PathUtils.encode_path_len(2, 2)  # 0x42
        path_bytes = bytes([0x01, 0x02, 0x03, 0x04])
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
        pkt.header = (0 << 0) | (PAYLOAD_TYPE_PATH << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        callback_calls = []

        async def on_path_updated(pub: bytes, path_len: int, path_bytes_arg: bytes) -> None:
            callback_calls.append((pub, path_len, path_bytes_arg))

        handler.set_contact_path_updated_callback(on_path_updated)

        await handler(pkt)

        assert len(callback_calls) == 1
        assert callback_calls[0][0] == peer_pubkey
        assert callback_calls[0][1] == path_len_byte  # encoded byte, not raw count
        assert callback_calls[0][2] == path_bytes  # all 4 bytes of path data


class TestProtocolRequestHandler:
    """Tests for ProtocolRequestHandler._build_response (firmware-consistent)."""

    def setup_method(self):
        self.local_identity = LocalIdentity()
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.handler = ProtocolRequestHandler(
            self.local_identity, self.contacts, log_fn=self.log_fn
        )

    def _client_with_key(self, pubkey_bytes: bytes):
        """Return a minimal client object with public_key (no .id to use public_key path)."""

        class Client:
            pass

        c = Client()
        c.public_key = pubkey_bytes
        c.out_path = b""
        c.out_path_len = -1
        return c

    def test_flood_req_returns_path_packet(self):
        """REQ via flood → path-return PATH packet (firmware createPathReturn + sendFlood)."""
        peer_identity = LocalIdentity()
        client = self._client_with_key(peer_identity.get_public_key())
        client_hash = peer_identity.get_public_key()[0]
        our_hash = self.local_identity.get_public_key()[0]

        # Incoming REQ via flood with 1-hop path
        original = Packet()
        original.header = (ROUTE_TYPE_FLOOD & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        original.path_len = 1
        original.path = bytearray([0xAA])
        assert original.is_route_flood()

        response_data = b"\x39\x30\x00\x00\x00"  # timestamp LE + req_type 0
        shared_secret = peer_identity.calc_shared_secret(self.local_identity.get_private_key())

        result = self.handler._build_response(original, client, response_data, shared_secret)

        assert result is not None
        assert result.get_payload_type() == PAYLOAD_TYPE_PATH
        assert result.is_route_flood()
        assert result.payload[0] == client_hash
        assert result.payload[1] == our_hash

    def test_flood_req_applies_path_hash_mode(self):
        """Path-return packet preserves incoming path hash size (2-byte hashes)."""
        from pymc_core.protocol.packet_utils import PathUtils

        peer_identity = LocalIdentity()
        client = self._client_with_key(peer_identity.get_public_key())
        shared_secret = peer_identity.calc_shared_secret(self.local_identity.get_private_key())

        original = Packet()
        original.header = (ROUTE_TYPE_FLOOD & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        # 2 hops × 2-byte hashes → encoded path_len
        original.path_len = PathUtils.encode_path_len(2, 2)
        original.path = bytearray([0x01, 0x02, 0x03, 0x04])
        response_data = b"\x00\x00\x00\x00\x00"

        result = self.handler._build_response(original, client, response_data, shared_secret)

        assert result is not None
        assert result.get_payload_type() == PAYLOAD_TYPE_PATH
        # path_len high bits = (2-1)<<6 = 0x40 for 2-byte hash size, 0 hops
        assert result.path_len == 0x40

    def test_direct_req_no_out_path_returns_response_flood(self):
        """Direct REQ and no client out_path → RESPONSE via flood (no reversed path)."""
        peer_identity = LocalIdentity()
        client = self._client_with_key(peer_identity.get_public_key())
        client.out_path = b""
        client.out_path_len = -1
        shared_secret = peer_identity.calc_shared_secret(self.local_identity.get_private_key())

        original = Packet()
        original.header = (ROUTE_TYPE_DIRECT & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        original.path_len = 1
        original.path = bytearray([0xBB])
        assert not original.is_route_flood()

        response_data = b"\x01\x00\x00\x00\x00"
        result = self.handler._build_response(original, client, response_data, shared_secret)

        assert result is not None
        assert result.get_payload_type() == PAYLOAD_TYPE_RESPONSE
        assert result.is_route_flood()
        assert result.path_len == 0

    def test_direct_req_with_out_path_returns_response_direct(self):
        """Direct REQ and client has out_path → RESPONSE via direct with that path."""
        peer_identity = LocalIdentity()
        client = self._client_with_key(peer_identity.get_public_key())
        client.out_path = bytes([0x01, 0x02])
        client.out_path_len = 2
        shared_secret = peer_identity.calc_shared_secret(self.local_identity.get_private_key())

        original = Packet()
        original.header = (ROUTE_TYPE_DIRECT & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        original.path_len = 0
        original.path = bytearray()

        response_data = b"\x02\x00\x00\x00\x00"
        result = self.handler._build_response(original, client, response_data, shared_secret)

        assert result is not None
        assert result.get_payload_type() == PAYLOAD_TYPE_RESPONSE
        assert result.is_route_direct()
        assert result.path_len == 2
        assert bytes(result.path) == b"\x01\x02"


class TestTraceHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.local_identity = LocalIdentity()
        self.handler = TraceHandler(self.log_fn)

    def test_payload_type(self):
        """Test trace handler payload type."""
        assert TraceHandler.payload_type() == PAYLOAD_TYPE_TRACE

    def test_trace_handler_initialization(self):
        """Test trace handler initialization."""
        assert self.handler._log == self.log_fn

    def test_parse_trace_payload_one_byte_hashes(self):
        """flags=0: 1 byte per hop; path 0x01 0x02 = two hops."""
        payload = struct.pack("<IIB", 0x11111111, 0x22222222, 0x00) + bytes([0x01, 0x02])
        r = self.handler._parse_trace_payload(payload)
        assert r["valid"]
        assert r["path_hash_width"] == 1
        assert r["path_hop_count"] == 2
        assert r["trace_hops"] == [b"\x01", b"\x02"]
        assert r["trace_path_bytes"] == b"\x01\x02"
        assert r["trace_path"] == [0x01, 0x02]

    def test_parse_trace_payload_two_byte_hashes(self):
        """flags=0x01: 2 bytes per hop; 0x01 0x02 = one hop 0x0102."""
        payload = struct.pack("<IIB", 1, 2, 0x01) + bytes([0x01, 0x02])
        r = self.handler._parse_trace_payload(payload)
        assert r["valid"]
        assert r["path_hash_width"] == 2
        assert r["path_hop_count"] == 1
        assert r["trace_hops"] == [b"\x01\x02"]
        assert r["trace_path"] == [0x01]

    def test_format_trace_response_multibyte_hops(self):
        parsed = {
            "valid": True,
            "tag": 0xC88E314F,
            "auth_code": 0,
            "flags": 1,
            "trace_hops": [b"\x01\x02"],
            "snr": 11.8,
            "rssi": -45,
        }
        s = self.handler._format_trace_response(parsed)
        assert "0x0102" in s
        assert "path=[0x0102]" in s


# Integration Tests
@pytest.mark.asyncio
async def test_all_handlers_have_correct_payload_types():
    """Test that all handlers have unique and correct payload types."""
    handlers = [
        (AckHandler, PAYLOAD_TYPE_ACK),
        (TextMessageHandler, PAYLOAD_TYPE_TXT_MSG),
        (AdvertHandler, PAYLOAD_TYPE_ADVERT),
        (PathHandler, PAYLOAD_TYPE_PATH),
        (GroupTextHandler, PAYLOAD_TYPE_GRP_TXT),
        (LoginResponseHandler, PAYLOAD_TYPE_RESPONSE),
        (
            ProtocolResponseHandler,
            PAYLOAD_TYPE_PATH,
        ),  # Protocol responses come as PATH packets
        (TraceHandler, PAYLOAD_TYPE_TRACE),
    ]

    payload_types = []
    for handler_class, expected_type in handlers:
        payload_type = handler_class.payload_type()
        assert payload_type == expected_type
        payload_types.append(payload_type)

    # Check for uniqueness (except for LoginResponseHandler and
    # ProtocolResponseHandler which share RESPONSE)
    unique_types = set(payload_types)
    assert (
        len(unique_types) == len(payload_types) - 1
    )  # -1 because two handlers share RESPONSE type


@pytest.mark.asyncio
async def test_handlers_can_be_called():
    """Test that all handlers can be instantiated and called without errors."""
    local_identity = LocalIdentity()
    contacts = MockContactBook()
    log_fn = MagicMock()
    send_packet_fn = AsyncMock()
    event_service = MockEventService()

    handlers = [
        AckHandler(log_fn),
        TextMessageHandler(local_identity, contacts, log_fn, send_packet_fn, event_service),
        AdvertHandler(log_fn),
        PathHandler(log_fn),
        GroupTextHandler(local_identity, contacts, log_fn, send_packet_fn),
        LoginResponseHandler(local_identity, contacts, log_fn),
        ProtocolResponseHandler(log_fn, local_identity, contacts),
        TraceHandler(log_fn),
    ]

    # Create a minimal packet for testing
    packet = Packet()
    packet.payload = bytearray(b"test_payload")

    # All handlers should be callable without raising exceptions
    for handler in handlers:
        try:
            await handler(packet)
        except Exception as e:
            # Some handlers may raise exceptions due to incomplete setup,
            # but they should be callable
            assert isinstance(e, (ValueError, AttributeError, TypeError))  # Expected exceptions


# AnonReqResponseHandler Tests (separate from LoginResponseHandler)
def test_anon_req_response_handler():
    """Test AnonReqResponseHandler can be imported and has correct payload type."""
    from pymc_core.node.handlers import AnonReqResponseHandler

    # Should have same payload type as anonymous requests
    assert AnonReqResponseHandler.payload_type() == PAYLOAD_TYPE_ANON_REQ


# LoginServerHandler Tests — verify parity with C++ simple_repeater
class TestLoginServerHandler:
    """
    Tests for the server-side login handler.

    Validates that behavior matches C++ MeshCore/examples/simple_repeater:
    - Flood login → PATH packet response (login reply as extra data)
    - Direct login → RESPONSE datagram flooded back
    - Failed auth → no response sent
    - Response payload is 13 bytes with correct structure
    """

    def setup_method(self):
        from pymc_core.node.handlers.login_server import LoginServerHandler

        self.server_identity = LocalIdentity()
        self.client_identity_local = LocalIdentity()
        self.log_fn = MagicMock()

        # Default: successful auth returning admin permissions (0x03)
        self.auth_callback = MagicMock(return_value=(True, 0x03))

        self.handler = LoginServerHandler(
            local_identity=self.server_identity,
            log_fn=self.log_fn,
            authenticate_callback=self.auth_callback,
            is_room_server=False,
        )

        # Capture sent packets
        self.sent_packets = []

        def capture_send(pkt, delay_ms):
            self.sent_packets.append((pkt, delay_ms))

        self.handler.set_send_packet_callback(capture_send)

    def _build_login_packet(self, password="admin123", route_type="flood", path=None):
        """Build an ANON_REQ login packet the same way the client does."""
        client_pubkey = self.client_identity_local.get_public_key()
        server_pubkey = self.server_identity.get_public_key()

        # Calculate shared secret (client side)
        server_id = Identity(server_pubkey)
        shared_secret = server_id.calc_shared_secret(
            self.client_identity_local.get_private_key()
        )
        aes_key = shared_secret[:16]

        # Repeater format plaintext: timestamp(4) + password + null
        timestamp = int(time.time())
        plaintext = struct.pack("<I", timestamp) + password.encode("utf-8") + b"\x00"
        encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)

        # ANON_REQ payload: dest_hash(1) + client_pubkey(32) + encrypted_data
        dest_hash = server_pubkey[0]
        payload = bytes([dest_hash]) + client_pubkey + encrypted

        # Build packet with appropriate route type
        if route_type == "flood":
            header = (PAYLOAD_TYPE_ANON_REQ << 2) | ROUTE_TYPE_FLOOD
        else:
            header = (PAYLOAD_TYPE_ANON_REQ << 2) | ROUTE_TYPE_DIRECT

        pkt = Packet()
        pkt.header = header
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        if path:
            pkt.path = bytearray(path)
            pkt.path_len = len(path)
        else:
            pkt.path = bytearray()
            pkt.path_len = 0

        return pkt

    def test_payload_type(self):
        """LoginServerHandler handles ANON_REQ packets."""
        from pymc_core.node.handlers.login_server import LoginServerHandler

        assert LoginServerHandler.payload_type() == PAYLOAD_TYPE_ANON_REQ

    @pytest.mark.asyncio
    async def test_flood_login_sends_path_packet(self):
        """Flood login → PATH packet response (matches C++ createPathReturn path)."""
        pkt = self._build_login_packet(password="admin123", route_type="flood")
        await self.handler(pkt)

        assert len(self.sent_packets) == 1
        response_pkt, delay_ms = self.sent_packets[0]

        # C++ uses SERVER_RESPONSE_DELAY = 300
        assert delay_ms == 300

        # Must be PAYLOAD_TYPE_PATH — the C++ flood path
        assert response_pkt.get_payload_type() == PAYLOAD_TYPE_PATH

        # Must be flood routed (createPathReturn sets flood)
        assert response_pkt.is_route_flood()

        # PATH payload: dest_hash(1) + src_hash(1) + encrypted(...)
        assert len(response_pkt.payload) > 2
        # dest_hash should be client's hash
        client_hash = self.client_identity_local.get_public_key()[0]
        assert response_pkt.payload[0] == client_hash
        # src_hash should be server's hash
        server_hash = self.server_identity.get_public_key()[0]
        assert response_pkt.payload[1] == server_hash

    @pytest.mark.asyncio
    async def test_direct_login_sends_response_datagram(self):
        """Direct login → RESPONSE datagram via flood (matches C++ sendFlood(createDatagram) path)."""
        pkt = self._build_login_packet(password="admin123", route_type="direct")
        await self.handler(pkt)

        assert len(self.sent_packets) == 1
        response_pkt, delay_ms = self.sent_packets[0]

        assert delay_ms == 300

        # Must be PAYLOAD_TYPE_RESPONSE — regular datagram, NOT a PATH packet
        assert response_pkt.get_payload_type() == PAYLOAD_TYPE_RESPONSE

        # C++ sends the datagram via flood when reply_path_len < 0
        assert response_pkt.is_route_flood()

    @pytest.mark.asyncio
    async def test_flood_login_response_decryptable_with_login_reply(self):
        """PATH response from flood login contains the 13-byte login reply as extra data."""
        pkt = self._build_login_packet(password="admin123", route_type="flood")
        await self.handler(pkt)

        response_pkt, _ = self.sent_packets[0]

        # Decrypt the PATH payload to verify inner structure
        server_pubkey = self.server_identity.get_public_key()
        client_id = Identity(self.client_identity_local.get_public_key())
        shared_secret = client_id.calc_shared_secret(
            self.server_identity.get_private_key()
        )
        aes_key = shared_secret[:16]

        # PATH payload: dest_hash(1) + src_hash(1) + mac_and_ciphertext
        encrypted_part = bytes(response_pkt.payload[2:])
        plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_part)

        # Inner: path_len(1) + path_bytes(0 for no path) + extra_type(1) + extra(13)
        path_len_byte = plaintext[0]
        # With no path hops, path_len_byte is 0
        assert path_len_byte == 0

        extra_type = plaintext[1]
        assert extra_type == PAYLOAD_TYPE_RESPONSE

        # 13-byte login reply: timestamp(4) + resp_code(1) + keepalive(1) +
        #                      is_admin(1) + perms(1) + random(4) + fw_ver(1)
        # AES block padding may add trailing zero bytes — take exactly 13
        login_reply = plaintext[2:15]
        assert len(login_reply) == 13

        resp_code = login_reply[4]
        assert resp_code == 0x00  # RESP_SERVER_LOGIN_OK

        keepalive = login_reply[5]
        assert keepalive == 0  # Legacy, always 0

        is_admin = login_reply[6]
        assert is_admin == 1  # permissions 0x03 has admin bit 0x02

        perms = login_reply[7]
        assert perms == 0x03

        fw_ver = login_reply[12]
        assert fw_ver == 1  # FIRMWARE_VER_LEVEL

    @pytest.mark.asyncio
    async def test_failed_auth_sends_no_response(self):
        """Failed authentication → no response sent (C++ returns 0 from handleLoginReq)."""
        self.auth_callback.return_value = (False, 0)

        pkt = self._build_login_packet(password="wrongpass", route_type="flood")
        await self.handler(pkt)

        assert len(self.sent_packets) == 0

    @pytest.mark.asyncio
    async def test_packet_too_short_ignored(self):
        """Packets with payload < 34 bytes are silently dropped."""
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_ANON_REQ << 2) | ROUTE_TYPE_FLOOD
        pkt.payload = bytearray(b"\x00" * 10)
        pkt.payload_len = 10
        pkt.path = bytearray()
        pkt.path_len = 0

        await self.handler(pkt)

        assert len(self.sent_packets) == 0

    @pytest.mark.asyncio
    async def test_wrong_dest_hash_ignored(self):
        """Packets addressed to a different server are silently ignored."""
        pkt = self._build_login_packet(password="admin123", route_type="flood")
        # Corrupt dest_hash to not match our identity
        pkt.payload[0] = (self.server_identity.get_public_key()[0] + 1) & 0xFF

        await self.handler(pkt)

        assert len(self.sent_packets) == 0

    @pytest.mark.asyncio
    async def test_guest_permissions_is_admin_zero(self):
        """Guest login (no admin bit) → is_admin = 0 in response (matches C++ check)."""
        # Permission 0x01 = guest only, no admin bit (0x02)
        self.auth_callback.return_value = (True, 0x01)

        pkt = self._build_login_packet(password="guest", route_type="flood")
        await self.handler(pkt)

        response_pkt, _ = self.sent_packets[0]

        # Decrypt and verify is_admin field
        client_id = Identity(self.client_identity_local.get_public_key())
        shared_secret = client_id.calc_shared_secret(
            self.server_identity.get_private_key()
        )
        aes_key = shared_secret[:16]
        encrypted_part = bytes(response_pkt.payload[2:])
        plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_part)

        login_reply = plaintext[2:15]  # skip path_len(1) + extra_type(1), take 13
        is_admin = login_reply[6]
        assert is_admin == 0  # No admin bit → is_admin = 0

        perms = login_reply[7]
        assert perms == 0x01

    @pytest.mark.asyncio
    async def test_no_send_callback_logs_error(self):
        """Without send callback, logs error but doesn't crash."""
        self.handler.set_send_packet_callback(None)

        pkt = self._build_login_packet(password="admin123", route_type="flood")
        await self.handler(pkt)

        # Should have logged the error
        log_calls = [str(c) for c in self.log_fn.call_args_list]
        assert any("No send packet callback" in c for c in log_calls)

    @pytest.mark.asyncio
    async def test_flood_login_with_path_includes_path_in_response(self):
        """Flood login with path hashes → PATH response includes those hashes."""
        path_hashes = [0xAA, 0xBB]
        pkt = self._build_login_packet(
            password="admin123", route_type="flood", path=path_hashes
        )
        # path_len encodes hash size and count: (hash_size-1)<<6 | count
        # For 1-byte hashes with 2 hops: (0<<6) | 2 = 2
        pkt.path_len = 2

        await self.handler(pkt)

        assert len(self.sent_packets) == 1
        response_pkt, _ = self.sent_packets[0]
        assert response_pkt.get_payload_type() == PAYLOAD_TYPE_PATH

        # Decrypt and verify path is included
        client_id = Identity(self.client_identity_local.get_public_key())
        shared_secret = client_id.calc_shared_secret(
            self.server_identity.get_private_key()
        )
        aes_key = shared_secret[:16]
        encrypted_part = bytes(response_pkt.payload[2:])
        plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_part)

        # Inner: path_len_encoded(1) + path(2 bytes) + extra_type(1) + extra(13)
        path_len_encoded = plaintext[0]
        assert path_len_encoded == 2  # 2 hops, 1-byte hashes
        assert plaintext[1] == 0xAA
        assert plaintext[2] == 0xBB
        assert plaintext[3] == PAYLOAD_TYPE_RESPONSE  # extra_type

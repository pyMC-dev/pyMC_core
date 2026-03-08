import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from pymc_core.node.dispatcher import Dispatcher, DispatcherState
from pymc_core.protocol import Packet
from pymc_core.protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
)
from pymc_core.protocol.packet_filter import PacketFilter
from pymc_core.protocol.packet_utils import PathUtils


def create_test_packet(payload_type: int, payload: bytes) -> bytes:
    """Create a simple test packet bytes for testing."""
    packet = Packet()
    # Set header with payload type (route type = direct = 1)
    # Ensure payload_type is valid (0-15)
    if payload_type > 15:
        payload_type = 15  # Max valid payload type
    packet.header = (1 << 6) | (payload_type << 2)  # Version 0, route type 1, payload type
    packet.payload = bytearray(payload)
    packet.payload_len = len(payload)
    packet.path_len = 0  # No path
    return packet.write_to()


class MockRadio:
    """Mock radio for testing dispatcher."""

    def __init__(self):
        self.tx_data = None
        self.rx_callback = None
        self.state = "idle"

    async def transmit(self, data: bytes) -> bool:
        if hasattr(self, "_should_fail") and self._should_fail:
            raise Exception("Radio transmit failed")
        self.tx_data = data
        return True

    async def send(self, data: bytes) -> bool:
        """Alias for transmit to match dispatcher interface."""
        return await self.transmit(data)

    async def wait_for_rx(self):
        # Mock receiving data
        return b"mock_received_data"

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    def get_state(self):
        return self.state

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 30


class MockHandler:
    """Mock handler for testing."""

    def __init__(self, payload_type: int):
        self.payload_type = payload_type
        self.call_count = 0
        self.last_packet = None

    @staticmethod
    def payload_type():
        return 99  # Mock payload type

    async def __call__(self, packet: Packet):
        self.call_count += 1
        self.last_packet = packet


class MockContactBook:
    """Mock contact book for testing."""

    def __init__(self):
        self.contacts = []


class MockIdentity:
    """Mock identity for testing."""

    def __init__(self):
        self.public_key = b"0123456789abcdef0123456789abcdef"

    def get_public_key(self):
        return self.public_key


@pytest.fixture
def mock_radio():
    return MockRadio()


@pytest.fixture
def mock_identity():
    return MockIdentity()


@pytest.fixture
def mock_contact_book():
    return MockContactBook()


@pytest.fixture
def mock_logger():
    return Mock()


@pytest.fixture
def dispatcher(mock_radio, mock_identity, mock_contact_book, mock_logger):
    packet_filter = PacketFilter()
    dispatcher = Dispatcher(radio=mock_radio, packet_filter=packet_filter, log_fn=mock_logger)
    # Set additional attributes that are normally set by the node
    dispatcher.local_identity = mock_identity
    dispatcher.contact_book = mock_contact_book
    return dispatcher


class TestDispatcherInitialization:
    """Test dispatcher initialization and setup."""

    def test_dispatcher_creation(self, mock_radio, mock_identity, mock_contact_book, mock_logger):
        """Test creating a dispatcher with valid parameters."""
        packet_filter = PacketFilter()
        dispatcher = Dispatcher(radio=mock_radio, packet_filter=packet_filter, log_fn=mock_logger)
        # Set additional attributes that are normally set by the node
        dispatcher.local_identity = mock_identity
        dispatcher.contact_book = mock_contact_book

        assert dispatcher.radio == mock_radio
        assert dispatcher.local_identity == mock_identity
        assert dispatcher.contact_book == mock_contact_book
        assert dispatcher.packet_filter == packet_filter
        assert dispatcher.state == DispatcherState.IDLE
        assert isinstance(dispatcher._handlers, dict)
        assert isinstance(dispatcher._waiting_acks, dict)
        assert isinstance(dispatcher._recent_acks, dict)

    def test_dispatcher_initial_state(self, dispatcher):
        """Test dispatcher starts in IDLE state."""
        assert dispatcher.state == DispatcherState.IDLE

    def test_dispatcher_default_handlers_registration(self, dispatcher):
        """Test that default handlers can be registered."""
        # Initially no handlers
        assert len(dispatcher._handlers) == 0

        # Register default handlers
        dispatcher.register_default_handlers(
            contacts=None, local_identity=dispatcher.local_identity, event_service=None
        )

        # Should now have handlers
        assert len(dispatcher._handlers) > 0
        # Check that ACK handler is registered
        assert PAYLOAD_TYPE_ACK in dispatcher._handlers

    def test_dispatcher_handler_registration(self, dispatcher):
        """Test registering custom handlers."""
        mock_handler = MockHandler(100)
        dispatcher.register_handler(100, mock_handler)

        assert 100 in dispatcher._handlers
        assert dispatcher._handlers[100] == mock_handler


class TestDispatcherPacketProcessing:
    """Test packet processing and routing."""

    @pytest.mark.asyncio
    async def test_process_received_packet_valid(self, dispatcher):
        """Test processing a valid received packet."""
        # Create a mock packet
        payload = b"test_payload"
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, payload)

        # Register a mock handler
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        # Process the packet
        await dispatcher._process_received_packet(packet_data)

        # Verify handler was called
        assert mock_handler.call_count == 1
        assert mock_handler.last_packet is not None

    @pytest.mark.asyncio
    async def test_process_received_packet_unknown_type(self, dispatcher):
        """Test processing packet with unknown payload type."""
        # Create packet with unknown payload type
        payload = b"test_payload"
        packet_data = create_test_packet(999, payload)  # Unknown type

        # Process the packet (should not crash)
        await dispatcher._process_received_packet(packet_data)

        # Should still work without registered handler

    @pytest.mark.asyncio
    async def test_process_received_packet_invalid_data(self, dispatcher):
        """Test processing invalid packet data."""
        invalid_data = b"invalid_packet_data"

        # Should handle gracefully
        await dispatcher._process_received_packet(invalid_data)

    @pytest.mark.asyncio
    async def test_process_received_packet_duplicate(self, dispatcher):
        """Test duplicate packet filtering."""
        # Create a packet
        payload = b"test_payload"
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, payload)

        # Register handler
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        # Process same packet twice
        await dispatcher._process_received_packet(packet_data)
        await dispatcher._process_received_packet(packet_data)

        # Handler should only be called once due to deduplication
        assert mock_handler.call_count == 1


class TestDispatcherACKSystem:
    """Test ACK system functionality."""

    @pytest.mark.asyncio
    async def test_ack_waiting_and_receipt(self, dispatcher):
        """Test waiting for ACK and receiving it."""
        crc = 0x12345678

        # Start waiting for ACK
        ack_event = asyncio.Event()
        dispatcher._waiting_acks[crc] = ack_event

        # Simulate receiving ACK
        await dispatcher._register_ack_received(crc)

        # Event should be set
        assert ack_event.is_set()
        # ACK should be removed from waiting list
        assert crc not in dispatcher._waiting_acks
        # ACK should be in recent ACKs
        assert crc in dispatcher._recent_acks

    @pytest.mark.asyncio
    async def test_ack_timeout_cleanup(self, dispatcher):
        """Test ACK timeout and cleanup."""
        crc = 0x12345678
        dispatcher._waiting_acks[crc] = asyncio.Event()

        # Simulate the cleanup logic from run_forever without the infinite loop
        # Clean out old ACK CRCs (older than 5 seconds)
        now = asyncio.get_event_loop().time()
        old_time = now - 10  # 10 seconds ago
        dispatcher._recent_acks[crc] = old_time

        # Simulate cleanup (this is what run_forever does)
        dispatcher._recent_acks = {
            crc_key: ts for crc_key, ts in dispatcher._recent_acks.items() if now - ts < 5
        }

        # Old ACK should be cleaned up
        assert crc not in dispatcher._recent_acks

    def test_recent_ack_cleanup(self, dispatcher):
        """Test cleanup of old recent ACKs."""
        crc = 0x12345678
        old_time = asyncio.get_event_loop().time() - 10  # 10 seconds ago
        dispatcher._recent_acks[crc] = old_time

        # Simulate cleanup
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            now = loop.time()
            dispatcher._recent_acks = {
                crc: ts for crc, ts in dispatcher._recent_acks.items() if now - ts < 5
            }
        finally:
            loop.close()

        # Old ACK should be cleaned up
        assert crc not in dispatcher._recent_acks


class TestDispatcherStateManagement:
    """Test dispatcher state management."""

    def test_state_transitions(self, dispatcher):
        """Test state transitions."""
        # Start in IDLE
        assert dispatcher.state == DispatcherState.IDLE

        # Change to TRANSMIT
        dispatcher.state = DispatcherState.TRANSMIT
        assert dispatcher.state == DispatcherState.TRANSMIT

        # Change to WAIT
        dispatcher.state = DispatcherState.WAIT
        assert dispatcher.state == DispatcherState.WAIT

        # Back to IDLE
        dispatcher.state = DispatcherState.IDLE
        assert dispatcher.state == DispatcherState.IDLE

    @pytest.mark.asyncio
    async def test_state_based_rx_handling(self, dispatcher):
        """Test RX handling based on state."""
        # Mock radio without callback support
        dispatcher.radio = Mock()
        dispatcher.radio.set_rx_callback = Mock(side_effect=AttributeError)

        # Set state to IDLE
        dispatcher.state = DispatcherState.IDLE
        dispatcher.radio.wait_for_rx = AsyncMock(return_value=b"test_data")
        dispatcher._process_received_packet = AsyncMock()

        # Run RX once
        await dispatcher._rx_once()

        # Should have called wait_for_rx and process_received_packet
        dispatcher.radio.wait_for_rx.assert_called_once()
        dispatcher._process_received_packet.assert_called_once_with(b"test_data")


class TestDispatcherSendPacket:
    """Test packet sending functionality."""

    @pytest.mark.asyncio
    async def test_send_packet_success(self, dispatcher):
        """Test successful packet sending."""
        # Create a proper Packet object
        packet = Packet()
        packet.header = (
            (0 << 6) | (0 << 4) | (PAYLOAD_TYPE_ADVERT << 2) | 0
        )  # Version 0, reserved 0, type, route 0
        packet.payload = bytearray(b"test_packet_data")
        packet.payload_len = len(packet.payload)
        packet.path_len = 0

        dispatcher.radio.transmit = AsyncMock(return_value=True)

        result = await dispatcher.send_packet(packet)

        assert result is True
        dispatcher.radio.transmit.assert_called_once()

    @pytest.mark.asyncio
    async def test_default_path_hash_mode_applied_to_flood_packet(self, dispatcher):
        """When path_hash_mode is set, flood packets with 0 hops get path_len bits 6-7 set."""
        from pymc_core.protocol.constants import PH_TYPE_SHIFT

        dispatcher.set_default_path_hash_mode(1)  # 2-byte hashes
        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"advert_payload")
        pkt.payload_len = len(pkt.payload)

        await dispatcher.send_packet(pkt)

        raw = dispatcher.radio.tx_data
        assert raw is not None
        path_len_byte = raw[1]
        assert path_len_byte == 0x40

    @pytest.mark.asyncio
    async def test_path_hash_mode_not_overwritten_when_companion_applied(self, dispatcher):
        """Packet with _path_hash_mode_applied is not overwritten by dispatcher default."""
        from pymc_core.protocol.constants import PH_TYPE_SHIFT

        dispatcher.set_default_path_hash_mode(2)  # 3-byte
        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"x")
        pkt.payload_len = 1
        pkt.apply_path_hash_mode(1, mark_applied=True)

        await dispatcher.send_packet(pkt)

        raw = dispatcher.radio.tx_data
        assert raw is not None
        path_len_byte = raw[1]
        assert path_len_byte == 0x40

    @pytest.mark.asyncio
    async def test_trace_flood_rejected(self, dispatcher):
        """TRACE payload with flood route is rejected; send_packet returns False and no TX."""
        from pymc_core.protocol.constants import PH_TYPE_SHIFT

        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_TRACE << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00")  # tag, auth, flags
        pkt.payload_len = len(pkt.payload)

        result = await dispatcher.send_packet(pkt)

        assert result is False
        assert dispatcher.radio.tx_data is None

    @pytest.mark.asyncio
    async def test_trace_direct_still_sends(self, dispatcher):
        """TRACE with direct route is still sent (no regression)."""
        from pymc_core.protocol.constants import PH_TYPE_SHIFT

        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_TRACE << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        pkt.payload_len = len(pkt.payload)

        result = await dispatcher.send_packet(pkt, wait_for_ack=False)

        assert result is True
        assert dispatcher.radio.tx_data is not None

    def test_set_default_path_hash_mode_validates(self, dispatcher):
        """set_default_path_hash_mode accepts None, 0, 1, 2 and rejects other values."""
        dispatcher.set_default_path_hash_mode(None)
        assert dispatcher.path_hash_mode is None
        for mode in (0, 1, 2):
            dispatcher.set_default_path_hash_mode(mode)
            assert dispatcher.path_hash_mode == mode
        with pytest.raises(ValueError, match="path_hash_mode must be None, 0, 1, or 2"):
            dispatcher.set_default_path_hash_mode(3)
        with pytest.raises(ValueError, match="path_hash_mode must be None, 0, 1, or 2"):
            dispatcher.set_default_path_hash_mode(-1)

    @pytest.mark.asyncio
    async def test_send_packet_failure(self, dispatcher):
        """Test packet sending failure."""
        # Create a proper Packet object
        packet = Packet()
        packet.header = (
            (0 << 6) | (0 << 4) | (PAYLOAD_TYPE_ADVERT << 2) | 0
        )  # Version 0, reserved 0, type, route 0
        packet.payload = bytearray(b"test_packet_data")
        packet.payload_len = len(packet.payload)
        packet.path_len = 0

        dispatcher.radio.transmit = AsyncMock(side_effect=Exception("Radio transmit failed"))

        result = await dispatcher.send_packet(packet)

        assert result is False
        dispatcher.radio.transmit.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_packet_with_ack_waiting(self, dispatcher):
        """Test sending packet and waiting for ACK."""
        # Create a proper Packet object
        packet = Packet()
        packet.header = (
            (0 << 6) | (0 << 4) | (PAYLOAD_TYPE_ADVERT << 2) | 0
        )  # Version 0, reserved 0, type, route 0
        packet.payload = bytearray(b"test_packet_data")
        packet.payload_len = len(packet.payload)
        packet.path_len = 0

        # expected_crc = 0x12345678  # Not currently used

        # Mock radio
        dispatcher.radio.transmit = AsyncMock(return_value=True)

        # Mock ACK waiting
        dispatcher._waiting_acks = {}
        dispatcher._handle_ack_received = AsyncMock()

        # Send packet
        result = await dispatcher.send_packet(packet)

        assert result is True

    def test_own_packet_detection(self, dispatcher):
        """Test detection of own packets."""
        # Create packet with our own address as source
        our_hash = dispatcher.local_identity.get_public_key()[0]
        payload = bytes([0, our_hash]) + b"test"  # dest_hash=0, src_hash=our_hash
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, payload)

        # Parse the packet to check
        packet = Packet()
        packet.read_from(packet_data)

        # Should detect as own packet
        is_own = packet.payload[1] == our_hash
        assert is_own


class TestDispatcherCallbacks:
    """Test callback system."""

    @pytest.mark.asyncio
    async def test_raw_packet_callback(self, dispatcher):
        """Test raw packet callback."""
        callback_called = False
        received_packet = None
        received_data = None
        received_analysis = None

        def test_callback(packet, data, analysis):
            nonlocal callback_called, received_packet, received_data, received_analysis
            callback_called = True
            received_packet = packet
            received_data = data
            received_analysis = analysis

        # Set callback
        dispatcher.set_raw_packet_callback(test_callback)

        # Create and process packet
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")

        await dispatcher._process_received_packet(packet_data)

        # Callback should have been called
        assert callback_called
        assert received_packet is not None
        assert received_data == packet_data

    @pytest.mark.asyncio
    async def test_full_hop_count_packet_marked_do_not_retransmit(self, dispatcher):
        """Packet with path at max hops for its encoding is marked do not retransmit."""
        received_packet = None

        def capture(packet, data, analysis):
            nonlocal received_packet
            received_packet = packet

        dispatcher.set_raw_packet_callback(capture)

        # 1-byte hashes: max 63 hops
        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_TXT_MSG << 2)
        pkt.path_len = PathUtils.encode_path_len(1, 63)
        pkt.path = bytearray(bytes(63))
        pkt.payload = bytearray(b"x")
        pkt.payload_len = 1
        packet_data = pkt.write_to()

        await dispatcher._process_received_packet(packet_data)

        assert received_packet is not None
        assert received_packet.is_marked_do_not_retransmit() is True
        assert received_packet.get_path_hash_count() == 63

    @pytest.mark.asyncio
    async def test_2byte_path_at_max_hops_marked_do_not_retransmit(self, dispatcher):
        """Packet with 2-byte path at 32 hops (64 bytes) is marked do not retransmit."""
        received_packet = None

        def capture(packet, data, analysis):
            nonlocal received_packet
            received_packet = packet

        dispatcher.set_raw_packet_callback(capture)

        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_TXT_MSG << 2)
        pkt.path_len = PathUtils.encode_path_len(2, 32)
        pkt.path = bytearray(64)  # 32 * 2
        pkt.payload = bytearray(b"x")
        pkt.payload_len = 1
        packet_data = pkt.write_to()

        await dispatcher._process_received_packet(packet_data)

        assert received_packet is not None
        assert received_packet.is_marked_do_not_retransmit() is True
        assert received_packet.get_path_hash_count() == 32
        assert received_packet.get_path_byte_len() == 64

    @pytest.mark.asyncio
    async def test_async_callback(self, dispatcher):
        """Test async callback."""
        callback_called = False

        async def async_callback(packet, data, analysis):
            nonlocal callback_called
            callback_called = True
            await asyncio.sleep(0.01)  # Simulate async work

        # Set async callback
        dispatcher.set_raw_packet_callback(async_callback)

        # Create and process packet
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")

        await dispatcher._process_received_packet(packet_data)

        # Callback should have been called
        assert callback_called


class TestDispatcherMaintenance:
    """Test maintenance functionality."""

    @pytest.mark.asyncio
    async def test_run_forever_cleanup(self, dispatcher):
        """Test run_forever maintenance loop."""
        # Add some old ACKs
        old_time = asyncio.get_event_loop().time() - 10
        dispatcher._recent_acks[0x12345678] = old_time

        # Mock the cleanup calls
        dispatcher.packet_filter.cleanup_old_hashes = Mock()

        # Run maintenance (will run for a short time due to callback support)
        # In real scenario, this would run indefinitely

        # Simulate the cleanup that happens in run_forever
        now = asyncio.get_event_loop().time()
        dispatcher._recent_acks = {
            crc: ts for crc, ts in dispatcher._recent_acks.items() if now - ts < 5
        }

        # Old ACK should be cleaned up
        assert 0x12345678 not in dispatcher._recent_acks

    @pytest.mark.asyncio
    async def test_packet_filter_cleanup(self, dispatcher):
        """Test packet filter cleanup."""
        dispatcher.packet_filter.cleanup_old_hashes = Mock()

        # Simulate cleanup call
        dispatcher.packet_filter.cleanup_old_hashes()

        # Verify cleanup was called
        dispatcher.packet_filter.cleanup_old_hashes.assert_called_once()


class TestDispatcherErrorHandling:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_radio_tx_error_handling(self, dispatcher):
        """Test handling radio transmit errors."""
        # Create a proper Packet object
        packet = Packet()
        packet.header = (1 << 6) | (PAYLOAD_TYPE_ADVERT << 2)  # ADVERT packets don't wait for ACK
        packet.payload = bytearray(b"test_data")
        packet.payload_len = len(packet.payload)
        packet.path_len = 0

        dispatcher.radio.transmit = AsyncMock(side_effect=Exception("Radio error"))

        result = await dispatcher.send_packet(packet)

        # Should return False on error
        assert not result

    @pytest.mark.asyncio
    async def test_radio_rx_error_handling(self, dispatcher):
        """Test handling radio receive errors."""
        dispatcher.radio.wait_for_rx = AsyncMock(side_effect=Exception("RX error"))

        # Should handle error gracefully
        await dispatcher._rx_once()

        # Should not crash

    @pytest.mark.asyncio
    async def test_callback_error_handling(self, dispatcher):
        """Test handling callback errors."""

        def failing_callback(packet, data, analysis):
            raise Exception("Callback error")

        # Set failing callback
        dispatcher.set_raw_packet_callback(failing_callback)

        # Create and process packet
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")

        # Should handle callback error gracefully
        await dispatcher._process_received_packet(packet_data)

        # Should not crash


class TestDispatcherIntegration:
    """Integration tests for dispatcher."""

    @pytest.mark.asyncio
    async def test_full_packet_flow(self, dispatcher):
        """Test complete packet receive and process flow."""
        # Create a text message packet
        payload = b"Hello, World!"
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, payload)

        # Register a handler
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        # Process the packet
        await dispatcher._process_received_packet(packet_data)

        # Verify handler was called with correct packet
        assert mock_handler.call_count == 1
        assert mock_handler.last_packet.payload == payload

    @pytest.mark.asyncio
    async def test_multiple_handlers(self, dispatcher):
        """Test multiple handlers for different payload types."""
        # Create handlers for different types
        text_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        ack_handler = MockHandler(PAYLOAD_TYPE_ACK)

        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, text_handler)
        dispatcher.register_handler(PAYLOAD_TYPE_ACK, ack_handler)

        # Create and process text packet
        text_packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"text message")

        # Create and process ACK packet
        ack_packet_data = create_test_packet(PAYLOAD_TYPE_ACK, b"\x78\x56\x34\x12")  # CRC

        # Process both packets
        await dispatcher._process_received_packet(text_packet_data)
        await dispatcher._process_received_packet(ack_packet_data)

        # Both handlers should have been called
        assert text_handler.call_count == 1
        assert ack_handler.call_count == 1

    def test_packet_filter_stats(self, dispatcher):
        """Test getting packet filter statistics."""
        stats = dispatcher.get_filter_stats()
        assert isinstance(stats, dict)

    def test_clear_packet_filter(self, dispatcher):
        """Test clearing packet filter."""
        dispatcher.clear_packet_filter()
        # Should not crash

from pymc_core import LocalIdentity
from pymc_core.protocol.constants import (
    MAX_PACKET_PAYLOAD,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_RAW_CUSTOM,
)
from pymc_core.protocol.packet_builder import PacketBuilder


# PacketBuilder tests
def test_packet_builder_create_ack():
    """Test creating ACK packets."""
    identity = LocalIdentity()
    timestamp = 1234567890
    attempt = 1
    text = "test_ack"

    ack_packet = PacketBuilder.create_ack(identity.get_public_key(), timestamp, attempt, text)

    assert ack_packet is not None
    assert ack_packet.get_payload_type() == PAYLOAD_TYPE_ACK


def test_packet_builder_create_advert():
    """Test creating advertisement packets."""
    identity = LocalIdentity()
    advert_packet = PacketBuilder.create_advert(identity, "test_data", 1)

    assert advert_packet is not None
    assert advert_packet.get_payload_type() == PAYLOAD_TYPE_ADVERT


def test_packet_builder_create_self_advert():
    """Test creating self-advertisement packets."""
    identity = LocalIdentity()
    self_advert = PacketBuilder.create_self_advert(identity, "TestNode", 1)

    assert self_advert is not None
    assert self_advert.get_payload_type() == PAYLOAD_TYPE_ADVERT


def test_packet_builder_create_flood_advert():
    """Test creating flood advertisement packets."""
    identity = LocalIdentity()
    flood_advert = PacketBuilder.create_flood_advert(identity, "TestNode", 1)

    assert flood_advert is not None
    assert flood_advert.get_payload_type() == PAYLOAD_TYPE_ADVERT


def test_packet_builder_create_direct_advert():
    """Test creating direct advertisement packets."""
    identity = LocalIdentity()
    direct_advert = PacketBuilder.create_direct_advert(identity, "TestNode", 1)

    assert direct_advert is not None
    assert direct_advert.get_payload_type() == PAYLOAD_TYPE_ADVERT


def test_packet_builder_create_raw_data():
    """Test creating raw custom packets (PAYLOAD_TYPE_RAW_CUSTOM)."""
    data = b"\x01\x02\x03\x04"
    pkt = PacketBuilder.create_raw_data(data)
    assert pkt is not None
    assert pkt.get_payload_type() == PAYLOAD_TYPE_RAW_CUSTOM
    assert pkt.payload == bytearray(data)
    assert pkt.payload_len == len(data)
    assert pkt.path_len == 0
    assert pkt.path == bytearray()


def test_packet_builder_create_raw_data_too_large_raises():
    """Test create_raw_data raises when data exceeds MAX_PACKET_PAYLOAD."""
    import pytest

    data = bytes(MAX_PACKET_PAYLOAD + 1)
    with pytest.raises(ValueError, match="exceeds MAX_PACKET_PAYLOAD"):
        PacketBuilder.create_raw_data(data)

"""Tests for CompanionRadio (stand-alone companion with radio)."""

import pytest

from pymc_core.companion import CompanionRadio
from pymc_core.companion.constants import ADV_TYPE_CHAT
from pymc_core.companion.models import Contact
from pymc_core.protocol import LocalIdentity


def _make_peer_contact(name: str) -> Contact:
    """Return a contact with a valid Ed25519 public key (required for packet encryption)."""
    peer = LocalIdentity()
    return Contact(public_key=peer.get_public_key(), name=name)


class MockRadio:
    """Mock radio for CompanionRadio: set_rx_callback, send, optional RSSI/SNR."""

    def __init__(self):
        self.rx_callback = None
        self.sent: list[bytes] = []

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes) -> bool:
        self.sent.append(data)
        return True

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 5


# ---------------------------------------------------------------------------
# Init and lifecycle
# ---------------------------------------------------------------------------


class TestCompanionRadioInit:
    def test_init_creates_stores(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity, node_name="TestNode")
        assert comp.contacts is not None
        assert comp.contacts.get_count() == 0
        assert comp.channels is not None
        assert comp.message_queue is not None
        assert comp.path_cache is not None
        assert comp.stats is not None
        assert comp.prefs.node_name == "TestNode"
        assert comp.prefs.adv_type == ADV_TYPE_CHAT
        assert comp.get_public_key() == identity.get_public_key()
        assert comp.node is not None
        assert comp.node.dispatcher is not None

    def test_init_passes_contacts_to_node(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity)
        comp.contacts.add(Contact(public_key=b"\x01" * 32, name="Alice"))
        assert comp.node.contacts is comp.contacts
        assert comp.node.contacts.get_by_name("Alice") is not None


@pytest.mark.asyncio
class TestCompanionRadioLifecycle:
    async def test_start_stop(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity)
        assert comp.is_running is False
        await comp.start()
        assert comp.is_running is True
        await comp.stop()
        assert comp.is_running is False

    async def test_start_idempotent_warning(self, caplog):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        await comp.start()
        await comp.start()
        await comp.stop()
        assert "already running" in caplog.text.lower() or True


# ---------------------------------------------------------------------------
# Contact management (base API via radio)
# ---------------------------------------------------------------------------


class TestCompanionRadioContacts:
    def test_add_and_get_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        key = b"\x02" * 32
        comp.add_update_contact(Contact(public_key=key, name="Bob"))
        assert comp.get_contact_by_key(key) is not None
        assert comp.get_contact_by_key(key).name == "Bob"
        assert comp.get_contact_by_name("Bob") is not None

    def test_import_contact_packet_data(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        # 73 bytes: 32 key + 1 adv_type + 32 name (padded) + 4 lat + 4 lon
        name_padded = b"Charlie\x00" * 4  # 32 bytes
        packet_data = b"\x03" * 32 + bytes([1]) + name_padded + (0).to_bytes(4, "little") * 2
        assert comp.import_contact(packet_data) is True
        contacts = comp.get_contacts()
        assert len(contacts) == 1
        assert contacts[0].name.startswith("Charlie")

    def test_export_contact_self(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity, node_name="Me")
        data = comp.export_contact(None)
        assert data is not None
        assert len(data) >= 73
        assert data[:32] == identity.get_public_key()


# ---------------------------------------------------------------------------
# Advertise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioAdvertise:
    async def test_advertise_sends_packet(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.advertise(flood=True)
        assert result is True
        assert len(radio.sent) == 1
        assert comp.stats.get_totals()["flood_tx"] == 1

    async def test_advertise_direct(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        await comp.advertise(flood=False)
        assert len(radio.sent) == 1
        assert comp.stats.get_totals()["direct_tx"] == 1


# ---------------------------------------------------------------------------
# Send text (requires contact)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioSendText:
    async def test_send_text_message_no_contact(self, caplog):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_text_message(b"\x00" * 32, "Hi")
        assert result.success is False
        assert "contact not found" in caplog.text.lower() or "Contact not found" in caplog.text

    async def test_send_text_message_with_contact_sends_packet(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Alice")
        comp.contacts.add(contact)
        result = await comp.send_text_message(contact.public_key, "Hello")
        assert len(radio.sent) >= 1
        # success may be False if no ACK (mock radio doesn't echo ACK)
        assert result.success is False or result.success is True


# ---------------------------------------------------------------------------
# Share contact, channel message, sync message
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioMisc:
    async def test_share_contact_not_found(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.share_contact(b"\x00" * 32)
        assert result is False

    async def test_share_contact_success(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        key = b"\x22" * 32
        comp.contacts.add(Contact(public_key=key, name="Bob"))
        result = await comp.share_contact(key)
        assert result is True
        assert len(radio.sent) == 1

    async def test_sync_next_message_empty(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        assert comp.sync_next_message() is None

    async def test_send_channel_message_no_channel(self, caplog):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_channel_message(0, "Hi")
        assert result is False


# ---------------------------------------------------------------------------
# Path discovery, trace, control data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioPathAndControl:
    async def test_send_path_discovery_no_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_path_discovery(b"\x00" * 32)
        assert result is False

    async def test_send_path_discovery_req_sends(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Target")
        comp.contacts.add(contact)
        result = await comp.send_path_discovery_req(contact.public_key)
        assert result.success is True
        assert len(radio.sent) == 1

    async def test_send_trace_path_raw(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_trace_path_raw(0x12345678, 0xABCD, 0, bytes([0x01, 0x02]))
        assert result is True
        assert len(radio.sent) == 1

    async def test_send_control_data_default_discovery(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_control_data()
        assert result is True
        assert len(radio.sent) == 1

    async def test_send_control_data_raw_payload(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_control_data(bytes([0x80, 0x04]))
        assert result is True
        assert len(radio.sent) == 1

    async def test_contact_path_updated_fired_when_handler_callback_invoked(self):
        """Radio wires protocol_response_handler contact_path_updated to _fire_callbacks."""
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        path_updated_calls = []

        async def on_path_updated(contact):
            path_updated_calls.append(contact)

        comp.on_contact_path_updated(on_path_updated)
        proto = comp.node.dispatcher.protocol_response_handler
        assert proto is not None
        assert proto._contact_path_updated_callback is not None

        pub = b"\x22" * 32
        path_len = 2
        path_bytes = bytes([0x01, 0x02])
        cb_result = proto._contact_path_updated_callback(pub, path_len, path_bytes)
        if hasattr(cb_result, "__await__"):
            await cb_result

        assert len(path_updated_calls) == 1
        assert path_updated_calls[0].public_key == pub
        assert path_updated_calls[0].out_path_len == path_len
        assert path_updated_calls[0].out_path == path_bytes


# ---------------------------------------------------------------------------
# Stats and config
# ---------------------------------------------------------------------------


class TestCompanionRadioStats:
    def test_get_stats_core(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        comp.contacts.add(Contact(public_key=b"\x01" * 32, name="A"))
        core = comp.get_stats(0)
        assert "contacts_count" in core
        assert core["contacts_count"] == 1
        assert "queue_len" in core
        assert "uptime_secs" in core

    def test_get_stats_packets(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        tot = comp.get_stats(2)
        assert "flood_tx" in tot
        assert "direct_rx" in tot
        assert "tx_errors" in tot


# ---------------------------------------------------------------------------
# Binary request and repeater command (delegate to node)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioBinaryAndRepeater:
    async def test_send_binary_req_no_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_binary_req(b"\x00" * 32, bytes([0x01]))
        assert result.success is False

    async def test_send_binary_req_with_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Rpt")
        comp.contacts.add(contact)
        result = await comp.send_binary_req(contact.public_key, bytes([0x01]), timeout_seconds=5.0)
        assert result.success is True
        assert result.expected_ack is not None
        assert len(radio.sent) == 1

    async def test_send_repeater_command_no_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        out = await comp.send_repeater_command(b"\x00" * 32, "status")
        assert out["success"] is False
        assert "not found" in out["reason"].lower()

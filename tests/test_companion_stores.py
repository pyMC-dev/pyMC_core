"""Tests for companion stores and models: ContactStore, ChannelStore, MessageQueue, PathCache."""

from pymc_core.companion import ChannelStore, ContactStore, MessageQueue, PathCache, StatsCollector
from pymc_core.companion.models import (
    AdvertPath,
    Channel,
    Contact,
    NodePrefs,
    QueuedMessage,
    SentResult,
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestContact:
    def test_contact_defaults(self):
        key = b"\x00" * 32
        c = Contact(public_key=key, name="alice")
        assert c.public_key == key
        assert c.name == "alice"
        assert c.adv_type == 0
        assert c.out_path_len == -1
        assert c.out_path == b""
        assert c.gps_lat == 0.0
        assert c.gps_lon == 0.0

    def test_contact_with_path(self):
        c = Contact(
            public_key=b"\x01" * 32,
            name="bob",
            out_path_len=3,
            out_path=bytes([0xAA, 0xBB, 0xCC]),
        )
        assert c.out_path_len == 3
        assert c.out_path == bytes([0xAA, 0xBB, 0xCC])


class TestSentResult:
    def test_sent_result_minimal(self):
        r = SentResult(success=False)
        assert r.success is False
        assert r.is_flood is False
        assert r.expected_ack is None
        assert r.timeout_ms is None

    def test_sent_result_full(self):
        r = SentResult(success=True, is_flood=True, expected_ack=0x1234, timeout_ms=5000)
        assert r.success is True
        assert r.is_flood is True
        assert r.expected_ack == 0x1234
        assert r.timeout_ms == 5000


class TestNodePrefs:
    def test_node_prefs_defaults(self):
        p = NodePrefs()
        assert p.node_name == "pyMC"
        assert p.adv_type == 1
        assert p.tx_power_dbm == 20
        assert p.frequency_hz == 915000000

    def test_node_prefs_custom(self):
        p = NodePrefs(node_name="TestNode", adv_type=2)
        assert p.node_name == "TestNode"
        assert p.adv_type == 2


class TestQueuedMessage:
    def test_queued_message_direct(self):
        key = b"\x02" * 32
        msg = QueuedMessage(sender_key=key, text="Hello", timestamp=1000)
        assert msg.sender_key == key
        assert msg.text == "Hello"
        assert msg.timestamp == 1000
        assert msg.is_channel is False
        assert msg.channel_idx == 0

    def test_queued_message_channel(self):
        msg = QueuedMessage(
            sender_key=b"",
            text="Sender: Hi",
            is_channel=True,
            channel_idx=2,
        )
        assert msg.is_channel is True
        assert msg.channel_idx == 2


class TestAdvertPath:
    def test_advert_path(self):
        prefix = b"\x03" * 7
        ap = AdvertPath(
            public_key_prefix=prefix,
            name="sensor1",
            path_len=2,
            path=bytes([1, 2]),
            recv_timestamp=12345,
        )
        assert ap.public_key_prefix == prefix
        assert ap.name == "sensor1"
        assert ap.path_len == 2
        assert ap.path == bytes([1, 2])
        assert ap.recv_timestamp == 12345


# ---------------------------------------------------------------------------
# ContactStore
# ---------------------------------------------------------------------------


class TestContactStore:
    def test_empty_store(self):
        store = ContactStore(max_contacts=10)
        assert store.get_count() == 0
        assert store.get_all() == []
        assert store.get_by_key(b"\x00" * 32) is None
        assert store.get_by_name("nobody") is None
        assert store.is_full() is False
        assert store.contacts == []
        assert store.list_contacts() == []

    def test_add_and_get_by_key(self):
        store = ContactStore(max_contacts=5)
        key = b"\x11" * 32
        contact = Contact(public_key=key, name="Alice")
        assert store.add(contact) is True
        assert store.get_count() == 1
        assert store.get_by_key(key) is contact
        assert store.get_by_key(b"\x22" * 32) is None

    def test_add_and_get_by_name(self):
        store = ContactStore(max_contacts=5)
        key = b"\x11" * 32
        contact = Contact(public_key=key, name="Bob")
        store.add(contact)
        proxy = store.get_by_name("Bob")
        assert proxy is not None
        assert proxy.name == "Bob"
        assert proxy.public_key == key.hex()
        assert store.get_by_name("Charlie") is None

    def test_update_existing(self):
        store = ContactStore(max_contacts=5)
        key = b"\x11" * 32
        store.add(Contact(public_key=key, name="Alice"))
        updated = Contact(public_key=key, name="AliceUpdated", gps_lat=1.0)
        assert store.update(updated) is True
        c = store.get_by_key(key)
        assert c.name == "AliceUpdated"
        assert c.gps_lat == 1.0

    def test_remove(self):
        store = ContactStore(max_contacts=5)
        key = b"\x11" * 32
        store.add(Contact(public_key=key, name="Alice"))
        assert store.remove(key) is True
        assert store.get_count() == 0
        assert store.get_by_key(key) is None
        assert store.remove(key) is False

    def test_max_contacts(self):
        store = ContactStore(max_contacts=2)
        store.add(Contact(public_key=b"\x01" * 32, name="A"))
        store.add(Contact(public_key=b"\x02" * 32, name="B"))
        assert store.add(Contact(public_key=b"\x03" * 32, name="C")) is False
        assert store.get_count() == 2
        assert store.is_full() is True

    def test_get_all_since(self):
        store = ContactStore(max_contacts=10)
        store.add(Contact(public_key=b"\x01" * 32, name="A", lastmod=100))
        store.add(Contact(public_key=b"\x02" * 32, name="B", lastmod=200))
        store.add(Contact(public_key=b"\x03" * 32, name="C", lastmod=150))
        all_c = store.get_all()
        assert len(all_c) == 3
        since_150 = store.get_all(since=150)
        assert len(since_150) == 2

    def test_clear(self):
        store = ContactStore(max_contacts=5)
        store.add(Contact(public_key=b"\x01" * 32, name="A"))
        store.clear()
        assert store.get_count() == 0
        assert store.get_by_name("A") is None

    def test_load_from(self):
        store = ContactStore(max_contacts=10)
        contacts = [Contact(public_key=bytes([i] * 32), name=f"C{i}") for i in range(3)]
        store.load_from(contacts)
        assert store.get_count() == 3
        assert store.get_by_name("C1").name == "C1"

    def test_load_from_dicts(self):
        store = ContactStore(max_contacts=10)
        store.load_from_dicts(
            [
                {"public_key": "a1" * 32, "name": "DictAlice"},
                {"public_key": "b2" * 32, "name": "DictBob"},
            ]
        )
        assert store.get_count() == 2
        assert store.get_by_name("DictAlice") is not None
        assert store.get_by_name("DictBob") is not None

    def test_to_dicts(self):
        store = ContactStore(max_contacts=5)
        store.add(Contact(public_key=b"\xaa" * 32, name="Export", adv_type=1))
        dicts = store.to_dicts()
        assert len(dicts) == 1
        assert dicts[0]["name"] == "Export"
        assert dicts[0]["public_key"] == "aa" * 32
        assert dicts[0]["adv_type"] == 1

    def test_get_by_key_prefix(self):
        store = ContactStore(max_contacts=5)
        key = b"\x11\x22\x33" + b"\x00" * 29
        store.add(Contact(public_key=key, name="Prefix"))
        assert store.get_by_key_prefix(b"\x11\x22") is not None
        assert store.get_by_key_prefix(b"\x11\x22\x33").name == "Prefix"
        assert store.get_by_key_prefix(b"\xff\xff") is None


# ---------------------------------------------------------------------------
# ChannelStore
# ---------------------------------------------------------------------------


class TestChannelStore:
    def test_empty_channels(self):
        store = ChannelStore(max_channels=8)
        assert store.get_count() == 0
        assert store.get(0) is None
        assert store.get_channels() == []
        assert store.find_by_name("any") is None

    def test_set_and_get(self):
        store = ChannelStore(max_channels=8)
        ch = Channel(name="general", secret=b"\x11" * 16)
        assert store.set(0, ch) is True
        assert store.get(0) is ch
        assert store.get_count() == 1
        assert store.get_channels() == [{"name": "general", "secret": "11" * 16}]

    def test_find_by_name(self):
        store = ChannelStore(max_channels=8)
        store.set(0, Channel(name="alpha", secret=b"\x00" * 16))
        store.set(1, Channel(name="beta", secret=b"\x01" * 16))
        assert store.find_by_name("alpha") == 0
        assert store.find_by_name("beta") == 1
        assert store.find_by_name("gamma") is None

    def test_remove(self):
        store = ChannelStore(max_channels=8)
        store.set(0, Channel(name="x", secret=b"\x00" * 16))
        assert store.remove(0) is True
        assert store.get(0) is None
        assert store.remove(0) is False
        assert store.remove(99) is False

    def test_clear(self):
        store = ChannelStore(max_channels=8)
        store.set(0, Channel(name="a", secret=b"\x00" * 16))
        store.clear()
        assert store.get_count() == 0
        assert store.get(0) is None

    def test_out_of_range(self):
        store = ChannelStore(max_channels=4)
        ch = Channel(name="x", secret=b"\x00" * 16)
        assert store.set(-1, ch) is False
        assert store.set(4, ch) is False
        assert store.get(4) is None


# ---------------------------------------------------------------------------
# MessageQueue
# ---------------------------------------------------------------------------


class TestMessageQueue:
    def test_empty_queue(self):
        q = MessageQueue(max_size=5)
        assert q.count == 0
        assert q.is_empty() is True
        assert q.is_full() is False
        assert q.pop() is None
        assert q.peek() is None

    def test_push_and_pop(self):
        q = MessageQueue(max_size=5)
        msg = QueuedMessage(sender_key=b"\x00" * 32, text="Hi")
        q.push(msg)
        assert q.count == 1
        assert q.peek() is msg
        assert q.pop() is msg
        assert q.count == 0
        assert q.pop() is None

    def test_maxlen_drops_oldest(self):
        q = MessageQueue(max_size=2)
        q.push(QueuedMessage(sender_key=b"\x01" * 32, text="1"))
        q.push(QueuedMessage(sender_key=b"\x02" * 32, text="2"))
        q.push(QueuedMessage(sender_key=b"\x03" * 32, text="3"))
        assert q.count == 2
        first = q.pop()
        assert first.text == "2"
        assert q.pop().text == "3"

    def test_clear(self):
        q = MessageQueue(max_size=5)
        q.push(QueuedMessage(sender_key=b"\x00" * 32, text="x"))
        q.clear()
        assert q.count == 0
        assert q.pop() is None


# ---------------------------------------------------------------------------
# PathCache
# ---------------------------------------------------------------------------


class TestPathCache:
    def test_empty_cache(self):
        cache = PathCache(max_entries=8)
        assert cache.get_all() == []
        assert cache.get_by_prefix(b"\x00" * 7) is None

    def test_update_and_get(self):
        cache = PathCache(max_entries=8)
        ap = AdvertPath(
            public_key_prefix=b"\x01" * 7,
            name="n1",
            path_len=2,
            path=bytes([1, 2]),
            recv_timestamp=100,
        )
        cache.update(ap)
        assert len(cache.get_all()) == 1
        found = cache.get_by_prefix(b"\x01" * 5)
        assert found is not None
        assert found.name == "n1"
        assert found.path == bytes([1, 2])

    def test_update_replaces_same_prefix(self):
        cache = PathCache(max_entries=8)
        prefix = b"\x02" * 7
        cache.update(AdvertPath(public_key_prefix=prefix, name="v1", path=bytes([1])))
        cache.update(AdvertPath(public_key_prefix=prefix, name="v2", path=bytes([2, 2])))
        assert len(cache.get_all()) == 1
        assert cache.get_by_prefix(prefix).name == "v2"
        assert cache.get_by_prefix(prefix).path == bytes([2, 2])

    def test_eviction_when_full(self):
        cache = PathCache(max_entries=2)
        cache.update(AdvertPath(public_key_prefix=b"\x01" * 7, name="1", path=b""))
        cache.update(AdvertPath(public_key_prefix=b"\x02" * 7, name="2", path=b""))
        cache.update(AdvertPath(public_key_prefix=b"\x03" * 7, name="3", path=b""))
        assert len(cache.get_all()) == 2
        assert cache.get_by_prefix(b"\x01" * 7) is None
        assert cache.get_by_prefix(b"\x02" * 7) is not None
        assert cache.get_by_prefix(b"\x03" * 7) is not None

    def test_clear(self):
        cache = PathCache(max_entries=8)
        cache.update(AdvertPath(public_key_prefix=b"\x01" * 7, name="x", path=b""))
        cache.clear()
        assert cache.get_all() == []
        assert cache.get_by_prefix(b"\x01" * 7) is None


# ---------------------------------------------------------------------------
# StatsCollector
# ---------------------------------------------------------------------------


class TestStatsCollector:
    def test_initial_state(self):
        s = StatsCollector()
        assert s.packets.flood_tx == 0
        assert s.packets.direct_rx == 0
        assert s.packets.tx_errors == 0
        assert s.get_uptime_secs() >= 0

    def test_record_tx_rx(self):
        s = StatsCollector()
        s.record_tx(is_flood=True)
        s.record_tx(is_flood=True)
        s.record_tx(is_flood=False)
        s.record_rx(is_flood=False)
        s.record_rx(is_flood=True)
        assert s.packets.flood_tx == 2
        assert s.packets.direct_tx == 1
        assert s.packets.direct_rx == 1
        assert s.packets.flood_rx == 1

    def test_record_tx_error(self):
        s = StatsCollector()
        s.record_tx_error()
        s.record_tx_error()
        assert s.packets.tx_errors == 2

    def test_get_totals(self):
        s = StatsCollector()
        s.record_tx(is_flood=True)
        s.record_rx(is_flood=False)
        tot = s.get_totals()
        assert tot["flood_tx"] == 1
        assert tot["direct_rx"] == 1
        assert tot["total_tx"] == 1
        assert tot["total_rx"] == 1
        assert "uptime_secs" in tot

    def test_reset(self):
        s = StatsCollector()
        s.record_tx(is_flood=True)
        s.record_tx_error()
        s.reset()
        assert s.packets.flood_tx == 0
        assert s.packets.tx_errors == 0

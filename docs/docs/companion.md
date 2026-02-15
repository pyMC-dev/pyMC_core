# Companion Module

The companion module provides a high-level Python interface to the MeshCore companion radio protocol. It manages contacts, messaging, channels, advertisements, path routing, telemetry, cryptographic signing, and device configuration on top of pyMC_core's `MeshNode`.

Two implementations are provided:

| Class | Owns Radio | Use Case |
|---|---|---|
| `CompanionRadio` | Yes | Standalone companion — wraps a hardware radio and `MeshNode` |
| `CompanionBridge` | No | Repeater-integrated companion — shares an existing dispatcher via a packet injector callback |

Both inherit from `CompanionBase` (an abstract base class), which holds all shared stores, event handling, device configuration logic, and unified TX methods (advertising, binary requests, path discovery, offline queue sync). Subclasses implement transport via the abstract `_send_packet` method.

---

## Architecture

```
CompanionBase (ABC)
├── ContactStore          (in-memory contacts, max 1000)
├── ChannelStore          (group channels, max 40)
├── MessageQueue          (offline FIFO, max 512)
├── PathCache             (recent advert paths, max 16)
├── StatsCollector        (TX/RX counters, uptime)
├── NodePrefs             (radio params, name, location)
│
│   Unified methods (use abstract _send_packet):
│   advertise, share_contact, send_binary_req,
│   send_path_discovery_req, send_trace_path_raw,
│   sync_next_message
│
├─► CompanionRadio        (owns MeshNode + hardware radio)
└─► CompanionBridge       (packet_injector callback, no radio)
```

---

## Installation

```bash
pip install pymc_core            # core only
pip install pymc_core[hardware]  # SX1262 direct radio support
pip install pymc_core[all]       # everything
```

---

## CompanionRadio

`CompanionRadio` is a standalone companion that owns a hardware radio and a `MeshNode`. It is the typical entry point for building a chat application, sensor gateway, or automation tool that participates in a MeshCore network.

### Quick Start

```python
import asyncio
from pymc_core import LocalIdentity
from pymc_core.companion import (
    CompanionRadio,
    ADV_TYPE_CHAT,
    STATS_TYPE_PACKETS,
)

async def main():
    # --- Setup ---
    from pymc_core.hardware import KissModemWrapper

    radio = KissModemWrapper("/dev/ttyUSB0")
    radio.connect()

    identity = LocalIdentity()  # generates a new Ed25519 keypair
    companion = CompanionRadio(
        radio=radio,
        identity=identity,
        node_name="myNode",
        adv_type=ADV_TYPE_CHAT,
    )

    # --- Register callbacks before starting ---
    companion.on_message_received(on_msg)
    companion.on_advert_received(on_advert)
    companion.on_channel_message_received(on_chan_msg)
    companion.on_send_confirmed(on_ack)

    await companion.start()

    # --- Advertise presence ---
    await companion.advertise(flood=True)

    # --- Send a direct message ---
    dest = bytes.fromhex("ab" * 32)  # 32-byte public key
    result = await companion.send_text_message(dest, "Hello mesh!")
    print(f"Sent: success={result.success}, flood={result.is_flood}")

    # --- Keep running ---
    try:
        while True:
            await asyncio.sleep(1)
    finally:
        await companion.stop()


# --- Callbacks ---
def on_msg(sender_key, text, timestamp, txt_type):
    print(f"DM from {sender_key[:8].hex()}: {text}")

def on_advert(contact):
    print(f"Discovered: {contact.name} (type={contact.adv_type})")

def on_chan_msg(channel_name, sender_name, text, timestamp, path_len, channel_idx):
    print(f"[{channel_name}] {sender_name}: {text}")

def on_ack(ack_crc):
    print(f"ACK confirmed: {ack_crc:#x}")


asyncio.run(main())
```

### Constructor

```python
CompanionRadio(
    radio,                              # hardware radio wrapper
    identity: LocalIdentity,            # Ed25519 identity
    node_name: str = "pyMC",
    adv_type: int = ADV_TYPE_CHAT,      # 1=chat, 2=repeater, 3=room, 4=sensor
    max_contacts: int = 1000,
    max_channels: int = 40,
    offline_queue_size: int = 512,
    radio_config: dict | None = None,
)
```

### Lifecycle

```python
await companion.start()      # start dispatcher task
await companion.stop()       # cancel dispatcher
companion.is_running         # bool property
```

### Messaging

```python
# Direct text message
result = await companion.send_text_message(pub_key, "hello", txt_type=0, attempt=1)
# result: SentResult(success, is_flood, expected_ack, timeout_ms)

# Group channel message
ok = await companion.send_channel_message(channel_idx=0, text="hello group")

# Pop oldest queued offline message
msg = companion.sync_next_message()  # -> QueuedMessage | None

# Raw binary data (direct path only)
result = await companion.send_raw_data(dest_key, data=b"\x01\x02", path=None)
```

### Advertisements

```python
await companion.advertise(flood=True)       # broadcast presence
await companion.share_contact(pub_key)      # share a contact via direct advert
```

### Contact Management

```python
from pymc_core.companion import Contact

# List / lookup
contacts = companion.get_contacts(since=0)
contact  = companion.get_contact_by_key(pub_key_bytes)
contact  = companion.get_contact_by_name("Alice")

# Add / update / remove
companion.add_update_contact(Contact(public_key=key, name="Bob"))
companion.remove_contact(pub_key_bytes)

# Reset routing path (force re-discovery)
companion.reset_path(pub_key_bytes)

# Serialise for sharing
blob   = companion.export_contact(pub_key)   # bytes
ok     = companion.import_contact(blob)      # bool
```

### Channel Management

```python
from pymc_core.companion import Channel

companion.set_channel(0, name="General", secret=b"shared_secret_key_here__________")
ch = companion.get_channel(0)   # -> Channel | None
```

### Path Discovery & Tracing

```python
# Path discovery (returns SentResult, fires on_path_discovery_response callback)
result = await companion.send_path_discovery_req(pub_key)

# Trace path through the network
ok = await companion.send_trace_path(pub_key, tag=42, auth_code=0, flags=0)

# Get recently heard advert path
advert_path = companion.get_advert_path(pub_key_prefix_7bytes)
```

### Repeater Interaction

```python
# Login to a repeater
resp = await companion.send_login(repeater_key, password="secret")

# Request repeater status
resp = await companion.send_status_request(repeater_key)

# Request telemetry
resp = await companion.send_telemetry_request(
    repeater_key,
    want_base=True,
    want_location=True,
    want_environment=False,
    timeout=10.0,
)

# Send a text command to a repeater
resp = await companion.send_repeater_command(repeater_key, command="status")
```

### Binary Requests

The generic binary request/response mechanism uses random 4-byte tags for matching.

```python
# Send and wait for response
result = await companion.send_binary_req(pub_key, data=b"\x01", timeout_seconds=10)

# Register a callback for responses
companion.on_binary_response(
    lambda tag, data, parsed, req_type: print(f"Response: {parsed}")
)
```

### Device Configuration

```python
companion.set_advert_name("NewName")                   # max 31 chars
companion.set_advert_latlon(37.7749, -122.4194)        # GPS coordinates
companion.set_radio_params(915_000_000, 250_000, 10, 5)  # freq, bw, SF, CR
companion.set_tx_power(22)                              # dBm
companion.set_tuning_params(rx_delay=0.0, airtime_factor=0.0)

# Location sharing in adverts
from pymc_core.companion import ADVERT_LOC_SHARE
companion.set_other_params(
    manual_add=0,
    telemetry_modes=(0, 0, 0),
    advert_loc_policy=ADVERT_LOC_SHARE,
    multi_acks=0,
)

prefs = companion.get_self_info()   # -> NodePrefs
```

### Cryptographic Signing

```python
buf_size = companion.sign_start()          # returns max buffer size (8192)
companion.sign_data(b"data to sign...")
signature = companion.sign_finish()        # -> 64-byte Ed25519 signature
```

### Statistics

```python
from pymc_core.companion import STATS_TYPE_CORE, STATS_TYPE_RADIO, STATS_TYPE_PACKETS

stats = companion.get_stats(STATS_TYPE_CORE)
# {'uptime': 3600, 'queue_len': 2, 'contacts_count': 15, 'channels_count': 3}

stats = companion.get_stats(STATS_TYPE_PACKETS)
# {'flood_tx': 42, 'flood_rx': 108, 'direct_tx': 5, 'direct_rx': 12, ...}
```

---

## CompanionBridge

`CompanionBridge` is designed for repeater integration. It does not own a radio or `MeshNode` — instead, the repeater host feeds received packets in via `process_received_packet()`, and all outbound packets go through a `packet_injector` callback you provide. This lets a companion identity coexist alongside a repeater on the same radio.

### Quick Start

```python
import asyncio
from pymc_core import LocalIdentity
from pymc_core.companion import CompanionBridge, ADV_TYPE_CHAT

async def main():
    identity = LocalIdentity()

    async def packet_injector(pkt, wait_for_ack=False):
        """Forward packet to the repeater's radio."""
        return await my_repeater.send_packet(pkt)

    def authenticate(user_hash, password):
        """Validate login attempts. Return (success, acl_bits)."""
        if user_hash == expected_hash:
            return (True, 0x01)
        return (False, 0)

    bridge = CompanionBridge(
        identity=identity,
        packet_injector=packet_injector,
        node_name="myBridge",
        adv_type=ADV_TYPE_CHAT,
        authenticate_callback=authenticate,
    )

    bridge.on_message_received(
        lambda key, text, ts, tt: print(f"Bridge msg: {text}")
    )

    await bridge.start()

    # Feed packets from the repeater's dispatcher
    async def on_repeater_rx(packet):
        await bridge.process_received_packet(packet)

    # ... register on_repeater_rx with your repeater ...

asyncio.run(main())
```

### Constructor

```python
CompanionBridge(
    identity: LocalIdentity,
    packet_injector: Callable,          # async (pkt, wait_for_ack=False) -> bool
    node_name: str = "pyMC",
    adv_type: int = ADV_TYPE_CHAT,
    max_contacts: int = 1000,
    max_channels: int = 40,
    offline_queue_size: int = 512,
    radio_config: dict | None = None,
    authenticate_callback: Callable | None = None,  # (hash, pw) -> (bool, int)
)
```

### RX Entry Point

```python
# Called by the repeater host for every received packet
await bridge.process_received_packet(packet)
```

The bridge registers internal handlers for these payload types:

| Payload Type | Handler |
|---|---|
| ACK | Bridge ACK handler (matches pending CRCs) |
| TXT_MSG | TextMessageHandler |
| ADVERT | AdvertHandler |
| PATH | PathHandler |
| ANON_REQ | LoginServerHandler |
| GRP_TXT | GroupTextHandler |
| RESPONSE | LoginResponseHandler |

### All Other APIs

`CompanionBridge` exposes the same messaging, contact, channel, path, signing, stats, and configuration APIs as `CompanionRadio` (inherited from `CompanionBase`). The only behavioral difference is that all TX goes through the `packet_injector` instead of an owned radio.

---

## Use Cases

### 1. Chat Application

Build a terminal or GUI chat client that discovers peers and exchanges messages.

```python
companion = CompanionRadio(radio, identity, node_name="ChatApp")

companion.on_message_received(display_message)
companion.on_advert_received(add_to_contact_list)

await companion.start()
await companion.advertise()

# User picks a contact and sends
contact = companion.get_contact_by_name("Alice")
await companion.send_text_message(contact.public_key, user_input)
```

### 2. Sensor Gateway

Collect telemetry from sensor nodes in the mesh, forward to a database or MQTT.

```python
companion = CompanionRadio(radio, identity, node_name="Gateway", adv_type=ADV_TYPE_CHAT)

async def on_telemetry(event_data):
    # event_data contains parsed CayenneLPP sensor readings
    publish_to_mqtt(event_data)

companion.on_telemetry_response(on_telemetry)

await companion.start()

# Periodically poll known sensors
for sensor in companion.get_contacts():
    if sensor.adv_type == ADV_TYPE_SENSOR:
        await companion.send_telemetry_request(
            sensor.public_key, want_base=True,
            want_location=True, want_environment=True, timeout=15,
        )
```

### 3. Repeater Companion (Bridge Mode)

Add a companion identity to an existing repeater without a second radio.

```python
bridge = CompanionBridge(
    identity=identity,
    packet_injector=repeater.inject_packet,
    node_name="RepeaterBot",
    authenticate_callback=auth_check,
)

bridge.on_message_received(handle_bot_command)
await bridge.start()

# In the repeater's RX loop:
async def repeater_on_rx(pkt):
    await bridge.process_received_packet(pkt)
    # ... also handle repeater logic ...
```

### 4. Network Diagnostics Tool

Trace paths and discover topology.

```python
companion.on_trace_received(lambda data: print(f"Trace: {data}"))
companion.on_path_discovery_response(
    lambda tag, key, out_path, in_path: print(f"Path to {key.hex()[:8]}: out={out_path}, in={in_path}")
)

# Trace route to a node
await companion.send_trace_path(target_key, tag=1, auth_code=0)

# Discover paths
await companion.send_path_discovery_req(target_key)
```

### 5. Group Chat / Channels

```python
companion.set_channel(0, name="Emergency", secret=b"shared_channel_secret___________")
companion.set_channel(1, name="General",   secret=b"another_shared_secret___________")

companion.on_channel_message_received(
    lambda ch_name, sender, text, ts, path_len, idx:
        print(f"[{ch_name}] {sender}: {text}")
)

await companion.send_channel_message(0, "Emergency broadcast")
```

---

## Push Callbacks Reference

Register callbacks to receive asynchronous events. Both sync and async functions are supported.

| Registration Method | Callback Signature |
|---|---|
| `on_message_received` | `(sender_key: bytes, text: str, timestamp: int, txt_type: int)` |
| `on_channel_message_received` | `(channel_name: str, sender_name: str, text: str, timestamp: int, path_len: int, channel_idx: int)` |
| `on_advert_received` | `(contact: Contact)` |
| `on_contact_path_updated` | `(contact: Contact)` |
| `on_send_confirmed` | `(ack_crc: int)` |
| `on_trace_received` | `(trace_data)` |
| `on_node_discovered` | `(event_data)` |
| `on_login_result` | `(result_data)` |
| `on_telemetry_response` | `(event_data)` |
| `on_status_response` | `(status_data)` |
| `on_raw_data_received` | `(raw_data)` |
| `on_binary_response` | `(tag: bytes, data: bytes, parsed: dict\|None, request_type: int\|None)` |
| `on_path_discovery_response` | `(tag: bytes, contact_pubkey: bytes, out_path: bytes, in_path: bytes)` |

---

## Models Reference

### Contact

```python
@dataclass
class Contact:
    public_key: bytes           # 32-byte Ed25519 public key
    name: str = ""              # up to 32 characters
    adv_type: int = 0           # ADV_TYPE_CHAT / REPEATER / ROOM / SENSOR
    flags: int = 0
    out_path_len: int = -1      # -1=unknown, 0=direct, >0=multi-hop
    out_path: bytes = b""
    last_advert_timestamp: int = 0
    lastmod: int = 0
    gps_lat: float = 0.0
    gps_lon: float = 0.0
```

### Channel

```python
@dataclass
class Channel:
    name: str           # up to 32 characters
    secret: bytes       # 16-byte pre-shared key
```

### SentResult

```python
@dataclass
class SentResult:
    success: bool
    is_flood: bool = False
    expected_ack: int | None = None
    timeout_ms: int | None = None
```

### QueuedMessage

```python
@dataclass
class QueuedMessage:
    sender_key: bytes
    txt_type: int = 0           # TXT_TYPE_PLAIN / CLI_DATA / SIGNED_PLAIN
    timestamp: int = 0
    text: str = ""
    is_channel: bool = False
    channel_idx: int = 0
    path_len: int = 0
```

---

## Constants

```python
# Advertisement types
ADV_TYPE_CHAT      = 1
ADV_TYPE_REPEATER  = 2
ADV_TYPE_ROOM      = 3
ADV_TYPE_SENSOR    = 4

# Text message types
TXT_TYPE_PLAIN         = 0
TXT_TYPE_CLI_DATA      = 1
TXT_TYPE_SIGNED_PLAIN  = 2

# Telemetry modes
TELEM_MODE_DENY        = 0
TELEM_MODE_ALLOW_FLAGS = 1
TELEM_MODE_ALLOW_ALL   = 2

# Location policy
ADVERT_LOC_NONE  = 0
ADVERT_LOC_SHARE = 1

# Auto-add config bitmask
AUTOADD_OVERWRITE_OLDEST = 0x01
AUTOADD_CHAT             = 0x02
AUTOADD_REPEATER         = 0x04
AUTOADD_ROOM             = 0x08
AUTOADD_SENSOR           = 0x10

# Stats types
STATS_TYPE_CORE    = 0
STATS_TYPE_RADIO   = 1
STATS_TYPE_PACKETS = 2

# Binary request types (IntEnum)
BinaryReqType.STATUS     # 0x01
BinaryReqType.KEEP_ALIVE # 0x02
BinaryReqType.TELEMETRY  # 0x03
BinaryReqType.MMA        # 0x04
BinaryReqType.ACL        # 0x05
BinaryReqType.NEIGHBOURS # 0x06

# Protocol codes
PROTOCOL_CODE_RAW_DATA    = 0x00
PROTOCOL_CODE_BINARY_REQ  = 0x02
PROTOCOL_CODE_ANON_REQ    = 0x07

# Timeouts
DEFAULT_RESPONSE_TIMEOUT_MS = 10000
```

---

## Unimplemented MeshCore Companion Features

The following features from the MeshCore companion radio firmware (`examples/companion_radio/`) are **not yet implemented** in pyMC_core:

| Feature | Firmware Command | Description |
|---|---|---|
| Device query | `CMD_DEVICE_QUERY` (0x16) | Hardware capability & firmware version handshake |
| App start handshake | `CMD_APP_START` (0x01) | Initial BLE/serial session setup with self-info response |
| Device time get/set | `CMD_GET_DEVICE_TIME` / `CMD_SET_DEVICE_TIME` | RTC clock synchronisation |
| Reboot | `CMD_REBOOT` (0x13) | Remote device reboot (with confirmation string) |
| Factory reset | `CMD_FACTORY_RESET` (0x33) | Erase all data and reset to defaults |
| BLE PIN | `CMD_SET_DEVICE_PIN` (0x25) | Set BLE pairing PIN |
| Battery & storage | `CMD_GET_BATT_AND_STORAGE` (0x14) | Battery voltage and flash storage info |
| Logout | `CMD_LOGOUT` (0x1D) | Disconnect from a server/repeater session |
| Has connection | `CMD_HAS_CONNECTION` (0x1C) | Check if active connection exists to a contact |
| Contact-by-key lookup (protocol) | `CMD_GET_CONTACT_BY_KEY` (0x1E) | Protocol-level single-contact fetch (available in-memory via `get_contact_by_key`) |
| GPS configuration | GPS enable/interval | GPS hardware control and periodic fix interval |
| Data persistence | File I/O (`/contacts3`, `/channels2`, `/new_prefs`) | Automatic save/load of contacts, channels, and preferences to flash storage |
| Push: contact deleted | `PUSH_CODE_CONTACT_DELETED` (0x8F) | Notification when a contact is overwritten by auto-add |
| Push: contacts full | `PUSH_CODE_CONTACTS_FULL` (0x90) | Notification when contact storage is full |
| Push: RX data log | `PUSH_CODE_LOG_RX_DATA` (0x88) | Raw received packet logging for diagnostics |
| Keep-alive mechanism | Server-driven keep-alive | Periodic keep-alive packets for active server connections |
| Firmware version reporting | `FIRMWARE_VER_CODE` / `FIRMWARE_BUILD_DATE` | Version and build metadata in device info response |

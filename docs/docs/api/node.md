# Node API Reference

This section documents the node management classes and functions in pyMC_Core.

## Dispatcher default path hash mode

The dispatcher can apply a **default path hash mode** to flood packets with 0 hops
that have not already had path hash mode set by the companion. This allows
packets built without the companion (e.g. ``PacketBuilder.create_flood_advert()``
and ``send_packet()``) to use 2- or 3-byte path hashes when the host sets a default.

- **``path_hash_mode``**: ``Optional[int] = None`` — 0=1-byte, 1=2-byte, 2=3-byte; ``None`` disables.
- **``set_default_path_hash_mode(mode)``**: Set or clear the default; ``mode`` must be ``None``, 0, 1, or 2.

The default is applied only to flood-routed packets with 0 hops. Packets that
already have path hash mode applied by the companion (marked with
``_path_hash_mode_applied``) are never overwritten.

**TRACE and flood:** The TRACE payload type is only sent via direct routing in the
firmware (path/SNR in payload, ``path_len = 0``). Flood TRACE is explicitly
unsupported. If ``send_packet()`` is called with a packet that is both
flood-routed and TRACE payload type, the dispatcher does not transmit and
returns ``False``.

**Repeater forwarding:** When implementing repeater-style forwarding of packets as
flood (e.g. path-return or reply floods), preserve the incoming packet's path
hash size on the outgoing packet so repeaters use the same 1-, 2-, or 3-byte
path hashes. For example: use ``incoming.get_path_hash_size()`` and call
``outgoing.apply_path_hash_mode(size - 1)`` when building the reply (mode 0=1-byte,
1=2-byte, 2=3-byte). This matches firmware behavior where
``sendFlood(..., packet->getPathHashSize())`` is used when forwarding.

## MeshNode

::: pymc_core.node.node.MeshNode
    handler: python
    options:
      show_root_heading: true
      show_source: false
      show_symbol_type_heading: true

## Event System

::: pymc_core.node.events
    handler: python
    options:
      show_root_heading: true
      show_source: false

## Packet Handlers

### Base Handler

::: pymc_core.node.handlers.base
    handler: python
    options:
      show_root_heading: true
      show_source: false

### ACK Handler

::: pymc_core.node.handlers.ack
    handler: python
    options:
      show_root_heading: true
      show_source: false

### Advert Handler

::: pymc_core.node.handlers.advert
    handler: python
    options:
      show_root_heading: true
      show_source: false

### Text Handler

::: pymc_core.node.handlers.text
    handler: python
    options:
      show_root_heading: true
      show_source: false

### Group Text Handler

::: pymc_core.node.handlers.group_text
    handler: python
    options:
      show_root_heading: true
      show_source: false

### Login Response Handler

::: pymc_core.node.handlers.login_response
    handler: python
    options:
      show_root_heading: true
      show_source: false

### Path Handler

::: pymc_core.node.handlers.path
    handler: python
    options:
      show_root_heading: true
      show_source: false

### Protocol Response Handler

::: pymc_core.node.handlers.protocol_response
    handler: python
    options:
      show_root_heading: true
      show_source: false

### Trace Handler

::: pymc_core.node.handlers.trace
    handler: python
    options:
      show_root_heading: true
      show_source: false

    def __init__(self):
        """Initialize the packet dispatcher."""

    def register_handler(
        self,
        packet_type: PacketType,
        handler: Callable[[Packet], Awaitable[None]]
    ) -> None:
        """Register a handler for a specific packet type."""

    def unregister_handler(self, packet_type: PacketType) -> None:
        """Remove handler for a packet type."""

    async def dispatch_packet(self, packet: Packet) -> None:
        """Dispatch packet to registered handler."""

    def get_registered_types(self) -> List[PacketType]:
        """Get list of registered packet types."""
```

## Event System

```python
class EventEmitter:
    """Simple event emission system for node events."""

    def on(self, event: str, callback: Callable) -> None:
        """Register event callback."""

    def off(self, event: str, callback: Callable) -> None:
        """Remove event callback."""

    def emit(self, event: str, *args, **kwargs) -> None:
        """Emit an event to all registered callbacks."""
```

## Node Events

The mesh node emits the following events:

- `packet_received`: When a packet is received
- `packet_sent`: When a packet is successfully sent
- `node_discovered`: When a new node is discovered
- `node_lost`: When a node becomes unreachable
- `network_error`: When a network error occurs

```python
# Example event handling
node = MeshNode(radio, identity)

@node.on('packet_received')
async def handle_packet(packet: Packet):
    print(f"Received packet from {packet.source.hex()[:8]}")

@node.on('node_discovered')
async def handle_discovery(node_id: bytes):
    print(f"Discovered node {node_id.hex()[:8]}")
```

## Packet Handlers

### ACK Handler

```python
class AckHandler:
    """Handles acknowledgment packets."""

    def __init__(self, node: MeshNode):
        """Initialize ACK handler."""

    async def handle_ack(self, packet: Packet) -> None:
        """Process incoming ACK packet."""
```

### Advert Handler

```python
class AdvertHandler:
    """Handles node advertisement packets."""

    def __init__(self, node: MeshNode):
        """Initialize advert handler."""

    async def handle_advert(self, packet: Packet) -> None:
        """Process incoming advertisement."""

    def get_known_nodes(self) -> List[bytes]:
        """Get list of known node IDs."""
```

### Text Handler

```python
class TextHandler:
    """Handles text message packets."""

    def __init__(self, node: MeshNode):
        """Initialize text handler."""

    async def handle_text(self, packet: Packet) -> None:
        """Process incoming text message."""

    async def send_text(
        self,
        destination: bytes,
        message: str
    ) -> None:
        """Send a text message to destination."""
```

### Group Text Handler

```python
class GroupTextHandler:
    """Handles group text message packets."""

    def __init__(self, node: MeshNode):
        """Initialize group text handler."""

    async def handle_group_text(self, packet: Packet) -> None:
        """Process incoming group message."""

    async def send_group_text(
        self,
        group_id: bytes,
        message: str
    ) -> None:
        """Send message to group."""

    def create_group(self, group_name: str) -> bytes:
        """Create a new message group."""
```

## Node Configuration

```python
@dataclass
class NodeConfig:
    """Configuration options for mesh nodes."""

    max_hops: int = 16
    packet_timeout: float = 30.0
    ack_timeout: float = 5.0
    retransmit_attempts: int = 3
    broadcast_interval: float = 60.0
    keep_alive_interval: float = 300.0
```

## Node Statistics

```python
@dataclass
class NodeStats:
    """Runtime statistics for a mesh node."""

    packets_sent: int = 0
    packets_received: int = 0
    packets_forwarded: int = 0
    acks_sent: int = 0
    acks_received: int = 0
    retransmits: int = 0
    known_nodes: int = 0
    uptime: float = 0.0

    def reset(self) -> None:
        """Reset all statistics to zero."""
```

## Error Handling

```python
class NodeError(Exception):
    """Base exception for node-related errors."""
    pass

class NetworkTimeoutError(NodeError):
    """Raised when network operations timeout."""
    pass

class InvalidPacketError(NodeError):
    """Raised when an invalid packet is received."""
    pass

class RadioError(NodeError):
    """Raised when radio hardware errors occur."""
    pass
```

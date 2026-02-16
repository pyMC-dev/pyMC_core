#!/usr/bin/env python3
"""
Minimal example: Discover nearby mesh nodes.

This example demonstrates how to broadcast a discovery request
and collect responses from nearby repeaters and nodes in the mesh network.

The discovery request is sent as a zero-hop broadcast, and nearby nodes
will respond with their public key and signal strength information.

Features:
- Asynchronous callback-based response collection
- Configurable discovery filter (node types to discover)
- Signal strength data (SNR and RSSI) for each discovered node
- Automatic timeout after specified duration
"""

import asyncio
import random
import time

from common import create_mesh_node

from pymc_core.protocol.packet_builder import PacketBuilder

# ADV_TYPE_REPEATER = 2, so filter mask is (1 << 2) = 0x04
FILTER_REPEATERS = 0x04  # Bit 2 set for repeater node type


async def discover_nodes(
    radio_type: str = "waveshare",
    serial_port: str = "/dev/ttyUSB0",
    timeout: float = 5.0,
    filter_mask: int = FILTER_REPEATERS,
):
    """
    Discover nearby mesh nodes using control packets.

    Args:
        radio_type: Radio hardware type ("waveshare", "uconsole", etc.)
        serial_port: Serial port for KISS TNC
        timeout: How long to wait for responses (seconds)
        filter_mask: Node types to discover (bitmask of ADV_TYPE values, e.g., ADV_TYPE_REPEATER = 2, so mask = 0x04 for repeaters)
    """
    mesh_node, identity = create_mesh_node("DiscoveryNode", radio_type, serial_port)

    # Dictionary to store discovered nodes
    discovered_nodes = {}

    # Create callback to collect discovery responses
    def on_discovery_response(response_data: dict):
        """Handle discovery response callback."""
        tag = response_data.get("tag", 0)
        node_type = response_data.get("node_type", 0)
        inbound_snr = response_data.get("inbound_snr", 0.0)  # Their RX of our request
        response_snr = response_data.get("response_snr", 0.0)  # Our RX of their response
        rssi = response_data.get("rssi", 0)
        pub_key = response_data.get("pub_key", "")
        timestamp = response_data.get("timestamp", 0)

        # Get node type name
        node_type_names = {1: "Chat Node", 2: "Repeater", 3: "Room Server"}
        node_type_name = node_type_names.get(node_type, f"Unknown({node_type})")

        # Store node info
        node_id = pub_key[:16]  # Use first 8 bytes as ID
        if node_id not in discovered_nodes:
            discovered_nodes[node_id] = {
                "pub_key": pub_key,
                "node_type": node_type_name,
                "inbound_snr": inbound_snr,
                "response_snr": response_snr,
                "rssi": rssi,
                "timestamp": timestamp,
            }

            print(
                f"✓ Discovered {node_type_name}: {node_id}... "
                f"(TX→RX SNR: {inbound_snr:+.1f}dB, RX←TX SNR: {response_snr:+.1f}dB, "
                f"RSSI: {rssi}dBm)"
            )

    # Get the control handler and set up callback
    control_handler = mesh_node.dispatcher.control_handler
    if not control_handler:
        print("Error: Control handler not available")
        return

    # Generate random tag for this discovery request
    discovery_tag = random.randint(0, 0xFFFFFFFF)

    # Set up callback for responses matching this tag
    control_handler.set_response_callback(discovery_tag, on_discovery_response)

    # Create discovery request packet
    # filter_mask: 0x04 = bit 2 set (1 << ADV_TYPE_REPEATER where ADV_TYPE_REPEATER=2)
    # since: 0 = discover all nodes regardless of modification time
    pkt = PacketBuilder.create_discovery_request(
        tag=discovery_tag, filter_mask=filter_mask, since=0, prefix_only=False
    )

    print(f"Sending discovery request (tag: 0x{discovery_tag:08X})...")
    print(f"Filter mask: 0x{filter_mask:02X} (node types to discover)")
    print(f"Waiting {timeout} seconds for responses...\n")

    # Send as zero-hop broadcast (no routing path)
    success = await mesh_node.dispatcher.send_packet(pkt, wait_for_ack=False)

    if success:
        print("Discovery request sent successfully")

        # Wait for responses
        start_time = time.time()
        while time.time() - start_time < timeout:
            await asyncio.sleep(0.1)

        # Display results
        print(f"\n{'='*60}")
        print(f"Discovery complete - found {len(discovered_nodes)} node(s)")
        print(f"{'='*60}\n")

        if discovered_nodes:
            for node_id, info in discovered_nodes.items():
                print(f"Node: {node_id}...")
                print(f"  Type:        {info['node_type']}")
                print(f"  TX→RX SNR:   {info['inbound_snr']:+.1f} dB (our request at their end)")
                print(f"  RX←TX SNR:   {info['response_snr']:+.1f} dB (their response at our end)")
                print(f"  RSSI:        {info['rssi']} dBm")
                print(f"  Public Key:  {info['pub_key']}")
                print()
        else:
            print("No nodes discovered.")
            print("This could mean:")
            print("  - No nodes are within range")
            print("  - No nodes match the filter criteria")
            print("  - Radio configuration mismatch")

    else:
        print("Failed to send discovery request")

    # Clean up callback
    control_handler.clear_response_callback(discovery_tag)


def main():
    """Main function for running the discovery example."""
    import argparse

    parser = argparse.ArgumentParser(description="Discover nearby mesh nodes")
    parser.add_argument(
        "--radio-type",
        choices=["waveshare", "uconsole", "meshadv-mini", "kiss-tnc", "kiss-modem"],
        default="waveshare",
        help="Radio hardware type (default: waveshare)",
    )
    parser.add_argument(
        "--serial-port",
        default="/dev/ttyUSB0",
        help="Serial port for KISS TNC (default: /dev/ttyUSB0)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Discovery timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--filter",
        type=lambda x: int(x, 0),
        default=FILTER_REPEATERS,
        help="Node type filter mask (default: 0x04 for repeaters, bit position = node type)",
    )

    args = parser.parse_args()

    print(f"Using {args.radio_type} radio configuration")
    if args.radio_type == "kiss-tnc":
        print(f"Serial port: {args.serial_port}")

    asyncio.run(discover_nodes(args.radio_type, args.serial_port, args.timeout, args.filter))


if __name__ == "__main__":
    main()

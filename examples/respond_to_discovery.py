#!/usr/bin/env python3
"""
Minimal example: Respond to discovery requests.

This example demonstrates how to listen for discovery requests from other nodes
and automatically respond with this node's information.

Simply run this script and it will respond to any discovery requests until stopped.
"""

import asyncio

from common import create_mesh_node

from pymc_core.protocol.packet_builder import PacketBuilder

# Node type values from C++ AdvertDataHelpers.h
ADV_TYPE_REPEATER = 2
ADV_TYPE_CHAT_NODE = 1
ADV_TYPE_ROOM_SERVER = 3


async def respond_to_discovery(
    radio_type: str = "waveshare",
    serial_port: str = "/dev/ttyUSB0",
    node_type: int = ADV_TYPE_REPEATER,
):
    """
    Listen for discovery requests and respond with node information.

    Args:
        radio_type: Radio hardware type ("waveshare", "uconsole", etc.)
        serial_port: Serial port for KISS TNC
        node_type: Type of this node (1=chat, 2=repeater, 3=room_server)
    """
    mesh_node, identity = create_mesh_node("DiscoveryResponder", radio_type, serial_port)

    # Get our public key for responses
    our_pub_key = identity.get_public_key()

    # Node type names for logging
    node_type_names = {
        ADV_TYPE_CHAT_NODE: "Chat Node",
        ADV_TYPE_REPEATER: "Repeater",
        ADV_TYPE_ROOM_SERVER: "Room Server",
    }
    node_type_name = node_type_names.get(node_type, f"Unknown({node_type})")

    # Create callback to handle discovery requests
    def on_discovery_request(request_data: dict):
        """Handle incoming discovery request."""
        tag = request_data.get("tag", 0)
        filter_byte = request_data.get("filter", 0)
        prefix_only = request_data.get("prefix_only", False)
        snr = request_data.get("snr", 0.0)
        rssi = request_data.get("rssi", 0)

        print(
            f"📡 Discovery request: tag=0x{tag:08X}, "
            f"filter=0x{filter_byte:02X}, SNR={snr:+.1f}dB, RSSI={rssi}dBm"
        )

        # Check if filter matches our node type
        filter_mask = 1 << node_type
        if (filter_byte & filter_mask) == 0:
            print(f"   ↳ Filter doesn't match, ignoring")
            return

        # Create and send discovery response
        print(f"   ↳ Sending response...")

        pkt = PacketBuilder.create_discovery_response(
            tag=tag,
            node_type=node_type,
            inbound_snr=snr,
            pub_key=our_pub_key,
            prefix_only=prefix_only,
        )

        # Send the response
        asyncio.create_task(send_response(mesh_node, pkt, tag))

    async def send_response(node, pkt, tag):
        """Send discovery response packet."""
        try:
            success = await node.dispatcher.send_packet(pkt, wait_for_ack=False)
            if success:
                print(f"   ✓ Response sent\n")
            else:
                print(f"   ✗ Failed to send\n")
        except Exception as e:
            print(f"   ✗ Error: {e}\n")

    # Get the control handler and set up request callback
    control_handler = mesh_node.dispatcher.control_handler
    if not control_handler:
        print("Error: Control handler not available")
        return

    control_handler.set_request_callback(on_discovery_request)

    print(f"   Listening for discovery requests as {node_type_name}")
    print(f"   Node type: {node_type} (filter: 0x{1 << node_type:02X})")
    print(f"   Public key: {our_pub_key.hex()[:32]}...")
    print(f"   Press Ctrl+C to stop\n")

    # Listen forever
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n\n  Stopped\n")

    control_handler.clear_request_callback()


def main():
    """Main function for running the discovery responder example."""
    import argparse

    parser = argparse.ArgumentParser(description="Respond to mesh node discovery requests")
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
        "--node-type",
        type=int,
        choices=[1, 2, 3],
        default=ADV_TYPE_CHAT_NODE,
        help="Node type: 1=chat, 2=repeater, 3=room_server (default: 1)",
    )

    args = parser.parse_args()

    print(f"Using {args.radio_type} radio configuration")
    if args.radio_type == "kiss-tnc":
        print(f"Serial port: {args.serial_port}")

    asyncio.run(respond_to_discovery(args.radio_type, args.serial_port, args.node_type))


if __name__ == "__main__":
    main()

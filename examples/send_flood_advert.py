#!/usr/bin/env python3
"""
Minimal example: Send a flood advertisement packet.

This example demonstrates how to create and broadcast an advertisement
packet that will be flooded throughout the mesh network using SX1262 radio hardware.

Usage:
    python send_flood_advert.py [radio_type]

Arguments:
    radio_type: 'waveshare' (default) or 'uconsole'

The flood advert is sent without expecting any acknowledgment or response.
"""

import asyncio
import sys

from common import create_mesh_node, print_packet_info

from pymc_core.protocol.constants import ADVERT_FLAG_IS_CHAT_NODE
from pymc_core.protocol.packet_builder import PacketBuilder


async def send_flood_advert(radio_type: str = "waveshare", serial_port: str = "/dev/ttyUSB0"):
    # Create a mesh node with SX1262 radio
    mesh_node, identity = create_mesh_node("MyNode", radio_type, serial_port)

    # Create a flood advertisement packet
    # Parameters: identity, node_name, lat, lon, feature1, feature2, flags
    advert_packet = PacketBuilder.create_flood_advert(
        local_identity=identity,
        name="MyNode",
        lat=37.7749,  # San Francisco latitude
        lon=-122.4194,  # San Francisco longitude
        flags=ADVERT_FLAG_IS_CHAT_NODE,
    )

    print_packet_info(advert_packet, "Created flood advert packet")
    print("Sending packet...")

    # Send the packet through the mesh node's dispatcher
    success = await mesh_node.dispatcher.send_packet(advert_packet, wait_for_ack=False)

    if success:
        print("Packet sent successfully!")
    else:
        print("Failed to send packet")

    return advert_packet


def main():
    """Main function for running the example."""
    import argparse

    parser = argparse.ArgumentParser(description="Send a flood advertisement packet")
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

    args = parser.parse_args()

    print(f"Using {args.radio_type} radio configuration")
    if args.radio_type == "kiss-tnc":
        print(f"Serial port: {args.serial_port}")

    asyncio.run(send_flood_advert(args.radio_type, args.serial_port))


if __name__ == "__main__":
    main()

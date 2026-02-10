#!/usr/bin/env python3
"""
Simple text message send example: Send a text message with CRC.

This example sends a secure text message with CRC validation
and encryption to another node in the mesh network.
"""

import asyncio

from common import create_mesh_node, print_packet_info

from pymc_core.protocol import Packet
from pymc_core.protocol.packet_builder import PacketBuilder


async def send_text_message(radio_type: str = "waveshare", serial_port: str = "/dev/ttyUSB0"):
    """Send a text message with CRC validation."""
    print("Starting text message send example...")

    # Create mesh node
    mesh_node, identity = create_mesh_node("MessageSender", radio_type, serial_port)

    # Initialize packet variable
    packet = Packet()

    # Create a mock contact for demonstration
    class MockContact:
        def __init__(self, name, pubkey_hex):
            self.name = name
            self.public_key = pubkey_hex  # Store as hex string, not bytes
            self.out_path = []

    # Create mock contact
    mock_contact = MockContact(
        "TestRecipient",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    # Message to send
    message_text = "Hello from PyMC Core! This is a test message"
    print(f"Message: {message_text}")
    print("Creating text message packet...")

    try:
        # Create text message packet
        packet, crc = PacketBuilder.create_text_message(
            contact=mock_contact,
            local_identity=identity,
            message=message_text,
            attempt=0,
            message_type="flood",
        )

        print_packet_info(packet, "Created text message packet")
        print(f"CRC: {crc:08X}")
        print("Sending message...")

        # Send the packet (wait for ACK to ensure delivery)
        success = await mesh_node.dispatcher.send_packet(packet, wait_for_ack=True)

        if success:
            print("Message sent successfully with ACK received!")
            print(f"Delivered: {message_text}")
        else:
            print("Failed to send message - no ACK received")

    except Exception as e:
        print(f"Error: {e}")

    return packet, mesh_node


def main():
    """Main function for running the example."""
    import argparse

    parser = argparse.ArgumentParser(description="Send a text message to the mesh network")
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

    try:
        packet, node = asyncio.run(send_text_message(args.radio_type, args.serial_port))
        print("Example completed")
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()

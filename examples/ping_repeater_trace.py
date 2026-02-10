#!/usr/bin/env python3
"""
Minimal example: Ping a repeater using the trace command.

This example demonstrates how to create and send a trace packet
to ping a specific repeater node in the mesh network using SX1262 radio hardware.

The trace packet is sent directly to the target repeater and should elicit
a trace response containing routing information, SNR, and RSSI data.

Features:
- Asynchronous callback-based response handling
- Early termination when response is received (no fixed 10s wait)
- Proper timeout handling
"""

import asyncio
import random

from common import create_mesh_node, print_packet_info

from pymc_core.protocol.constants import PAYLOAD_TYPE_TRACE
from pymc_core.protocol.packet_builder import PacketBuilder
from pymc_core.protocol.packet_utils import PacketDataUtils


async def ping_repeater(radio_type: str = "waveshare", serial_port: str = "/dev/ttyUSB0"):
    """
    Ping a specific repeater using trace packets with callback response handling.
    This demonstrates the proper way to handle asynchronous trace responses.
    """
    mesh_node, identity = create_mesh_node("PingNode", radio_type, serial_port)

    # Create an event to signal when response is received
    response_received = asyncio.Event()

    # Set up trace response callback
    def on_trace_response(success: bool, response_text: str, response_data: dict):
        """Handle trace response callback with signal strength data."""
        if success:
            print(f"Received trace response: {response_text}")
            print(f"Response data: {response_data}")
        else:
            print("Trace request failed or timed out")

        # Signal that we received a response (success or failure)
        response_received.set()

    # Get the trace handler and set up callback for the target repeater hash
    trace_handler = mesh_node.dispatcher.trace_handler
    if trace_handler:
        # Use the target repeater's hash for the callback
        repeater_hash_hex = "b5d8df576ee9ab9ba4e71dc3ef753c6383f1215306139b0cc3bb2c02136d7f65"
        repeater_pubkey_hash = bytes.fromhex(repeater_hash_hex)
        repeater_hash = repeater_pubkey_hash[0]

        trace_handler.set_response_callback(repeater_hash, on_trace_response)

        # Create and send trace packet to the target repeater
        trace_tag = random.randint(0, 0xFFFFFFFF)
        pkt = PacketBuilder.create_trace(
            tag=trace_tag, auth_code=0x12345678, flags=0x00, path=[repeater_hash]
        )

        print(f"Sending trace ping to repeater (hash: 0x{repeater_hash:02X})...")
        success = await mesh_node.dispatcher.send_packet(pkt, wait_for_ack=False)

        if success:
            print("Trace ping sent. Waiting for response...")
            try:
                # Wait for response with timeout - will break early when callback is called
                await asyncio.wait_for(response_received.wait(), timeout=10.0)
                print("Response received!")
            except asyncio.TimeoutError:
                print("Timeout: No response received within 10 seconds")
        else:
            print("Failed to send trace ping")
    else:
        print("Trace handler not available")


def main():
    """Main function for running the example."""
    import argparse

    parser = argparse.ArgumentParser(description="Ping a repeater using trace packets")
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

    asyncio.run(ping_repeater(args.radio_type, args.serial_port))


if __name__ == "__main__":
    main()

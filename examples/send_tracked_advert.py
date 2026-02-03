#!/usr/bin/env python3
"""
Simple tracked advert example: Send an advert and count repeats.

This example sends a location-tracked advertisement and counts
any incoming advert repeats from the mesh network.

this is a very basic example and not how you should do it in real code!

"""

import asyncio
import time

from common import create_mesh_node, print_packet_info

from pymc_core.protocol.constants import (
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_IS_CHAT_NODE,
    PAYLOAD_TYPE_ADVERT,
)
from pymc_core.protocol.packet_builder import PacketBuilder

# Global counter for repeats
repeat_count = 0


def simple_repeat_counter(raw_data: bytes):
    """Simple handler that just counts packet repeats."""
    global repeat_count

    try:
        # Simple check - just count any received packet as a potential repeat
        # I have kept it simple but you would want to check if it's actually an advert etc.
        repeat_count += 1
        print(f"PACKET REPEAT HEARD #{repeat_count} ({len(raw_data)} bytes)")
    except Exception as e:
        print(f"Error processing packet: {e}")


async def send_simple_tracked_advert(
    radio_type: str = "waveshare", serial_port: str = "/dev/ttyUSB0"
):
    """Send a tracked advert and count responses."""
    global repeat_count

    # Create mesh node
    mesh_node, identity = create_mesh_node("SimpleTracker", radio_type, serial_port)

    # Create advert packet
    advert_packet = PacketBuilder.create_advert(
        local_identity=identity,
        name="SimpleTracker",
        lat=51.5074,  # London coordinates
        lon=-0.1278,
        feature1=0,
        feature2=0,
        flags=ADVERT_FLAG_IS_CHAT_NODE | ADVERT_FLAG_HAS_LOCATION,
    )

    print_packet_info(advert_packet, "Created advert packet")

    # Send the packet
    print("\nSending advert...")
    success = await mesh_node.dispatcher.send_packet(advert_packet, wait_for_ack=False)

    if success:
        # Some backends (e.g. CH341) may run in best-effort TX mode if IRQ/TX_DONE cannot
        # be confirmed. Dispatcher stores TX metadata on the packet when available.
        tx_meta = getattr(advert_packet, "_tx_metadata", None)
        if isinstance(tx_meta, dict) and tx_meta.get("tx_confirmed") is False:
            print("Advert sent (TX not confirmed; best-effort mode)")
        else:
            print("Advert sent successfully!")
        print("Listening for repeats... (Ctrl+C to stop)")
        print("-" * 40)

        # Set up simple repeat counter directly on the radio
        mesh_node.radio.set_rx_callback(simple_repeat_counter)

        # Listen continuously
        try:
            await mesh_node.dispatcher.run_forever()
        except KeyboardInterrupt:
            print(f"\nStopped listening. Total repeats: {repeat_count}")
        except Exception as e:
            print(f"Error during listening: {e}")

    else:
        print("Failed to send advert")

    return advert_packet, mesh_node


def main():
    """Main function for running the example."""
    import argparse

    parser = argparse.ArgumentParser(description="Send a location-tracked advertisement")
    parser.add_argument(
        "--radio-type",
        choices=["waveshare", "uconsole", "meshadv-mini", "kiss-tnc", "ch341"],
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
        packet, node = asyncio.run(send_simple_tracked_advert(args.radio_type, args.serial_port))
        print("Example completed")
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()

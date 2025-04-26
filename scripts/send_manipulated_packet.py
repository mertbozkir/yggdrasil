#!/usr/bin/env python
import logging
import argparse
# from scapy.all import IP, UDP, Raw, send, fragment # Old import
from scapy.layers.inet import IP, UDP  # Import IP/UDP layers
from scapy.packet import Raw          # Import Raw layer
from scapy.sendrecv import send       # Import send function
from scapy.layers.inet import fragment # Import fragment function
import time # Import time here as it's used conditionally
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - SENDER - %(levelname)s - %(message)s"
)
logging.getLogger("scapy.runtime").setLevel(
    logging.ERROR
)  # Suppress Scapy's verbose logging

DEFAULT_TARGET_IP = "127.0.0.1"
DEFAULT_TARGET_PORT = 12345
DEFAULT_PAYLOAD = "This is a test payload."
DEFAULT_TTL = 64
DEFAULT_FLAG = "DF"  # Don't Fragment flag by default


def send_single_packet(target_ip, target_port, payload_str, ttl, flags):
    """Sends a single UDP packet with specified IP header modifications."""
    payload = Raw(load=payload_str.encode())
    logging.info("Payload: %s (%d bytes)", payload_str, len(payload))

    # Construct the packet layers
    ip_layer = IP(dst=target_ip, ttl=ttl, flags=flags)
    udp_layer = UDP(dport=target_port, sport=54321)  # Example source port

    packet = ip_layer / udp_layer / payload
    logging.info("Constructed packet summary:")
    packet.show()

    try:
        send(packet, verbose=0)  # Send the packet on Layer 3
        logging.info(
            "Packet sent to %s:%d with TTL=%d, Flags=%s",
            target_ip,
            target_port,
            ttl,
            flags,
        )
    except Exception as e:
        logging.error("Failed to send packet: %s", e)


def send_fragmented_packets(target_ip, target_port, large_payload_str, mtu=100):
    """Sends a large payload as manually fragmented IP packets."""
    large_payload = Raw(load=large_payload_str.encode())
    logging.info("Large Payload: %s (%d bytes)", large_payload_str, len(large_payload))
    logging.info("Simulating MTU: %d bytes (for IP payload)", mtu)

    # Base IP layer (ID will be set by fragment(), flags/frag will be overridden)
    ip_layer = IP(dst=target_ip)
    udp_layer = UDP(dport=target_port, sport=54321)

    # Scapy's fragment() handles the details of setting ID, MF flag, and frag offset
    # It expects the L3 packet *without* the payload that needs fragmentation
    # NOTE: fragment() operates on the *IP payload*. Our UDP header is part of that.
    # MTU needs to account for IP header (20 bytes usually)
    scapy_mtu = mtu  # fragment() takes the payload MTU

    base_packet_no_payload = ip_layer / udp_layer
    fragments = fragment(base_packet_no_payload / large_payload, fragsize=scapy_mtu)

    logging.info("Payload will be sent in %d fragments.", len(fragments))
    for i, frag_pkt in enumerate(fragments):
        logging.info("Sending fragment %d/%d:", i + 1, len(fragments))
        frag_pkt.show2()  # show2() gives more detail, including calculated checksums
        try:
            send(frag_pkt, verbose=0)
            logging.info("Fragment %d sent.", i + 1)
        except Exception as e:
            logging.error("Failed to send fragment %d: %s", i + 1, e)
        time.sleep(0.1)  # Small delay between fragments


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Send packets with manipulated IP headers."
    )
    parser.add_argument(
        "-t", "--target_ip", default=DEFAULT_TARGET_IP, help="Target IP address."
    )
    parser.add_argument(
        "-p",
        "--target_port",
        type=int,
        default=DEFAULT_TARGET_PORT,
        help="Target UDP port.",
    )
    parser.add_argument(
        "-m",
        "--message",
        default=DEFAULT_PAYLOAD,
        help="Payload message for single packet.",
    )
    parser.add_argument(
        "--ttl", type=int, default=DEFAULT_TTL, help="IP Time-To-Live value."
    )
    parser.add_argument(
        "--flags",
        default=DEFAULT_FLAG,
        choices=["", "DF", "MF"],
        help="IP Flags (''=None, DF, MF).",
    )
    parser.add_argument(
        "--fragment", action="store_true", help="Send a large payload fragmented."
    )
    parser.add_argument(
        "--mtu", type=int, default=100, help="MTU size for fragmentation demo."
    )
    parser.add_argument(
        "--large_message",
        default="This is a much larger payload that will hopefully exceed the MTU and require fragmentation to be sent correctly across the network simulation.",
        help="Payload for fragmentation demo.",
    )

    args = parser.parse_args()

    if args.fragment:
        # Need root/admin privileges for raw socket access used by fragment() often

        send_fragmented_packets(
            args.target_ip, args.target_port, args.large_message, args.mtu
        )
    else:
        # Need root/admin privileges for raw socket access used by send() often
        send_single_packet(
            args.target_ip, args.target_port, args.message, args.ttl, args.flags
        )

#!/usr/bin/env python
import logging
# from scapy.all import IP, UDP, Raw, sniff, raw # Old import
from scapy.layers.inet import IP, UDP  # Import IP/UDP layers
from scapy.packet import Raw          # Import Raw layer
from scapy.sendrecv import sniff      # Import sniff function
from scapy.layers.inet import raw     # Import raw function
from collections import defaultdict
import argparse
from typing import Dict, DefaultDict  # Import necessary types

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - SNIFFER - %(levelname)s - %(message)s"
)
logging.getLogger("scapy.runtime").setLevel(
    logging.ERROR
)  # Suppress Scapy's verbose logging

DEFAULT_LISTEN_PORT = 12345

# Dictionary to store fragments: {packet_id: {offset: payload_fragment}}
fragments_buffer: DefaultDict[int, Dict[int, bytes]] = defaultdict(dict)
fragments_last_offset: DefaultDict[int, int] = defaultdict(
    int
)  # Store offset of the last expected fragment if known
fragments_total_len: DefaultDict[int, int] = defaultdict(
    int
)  # Track received length for potential checks


def validate_ip_checksum(ip_layer: IP) -> tuple[bool, str]:
    """Validates the checksum of a received IP layer."""
    if not ip_layer:
        return False, "No IP layer"

    received_chksum = ip_layer.chksum

    # Create a copy, zero out checksum field *in the copy*, then get raw bytes
    ip_copy = ip_layer.copy()
    ip_copy.chksum = 0
    ip_copy_bytes_no_chksum = raw(ip_copy)

    # Rebuild from raw bytes *without* the original checksum to force recalculation
    rebuilt_ip = IP(ip_copy_bytes_no_chksum)
    calculated_chksum = rebuilt_ip.chksum

    valid = (received_chksum == calculated_chksum)

    log_level = logging.DEBUG if valid else logging.WARNING
    status_str = "VALID" if valid else "INVALID"

    logging.log(log_level,
        "IP Checksum %s (Received: %#04x, Calculated: %#04x)",
        status_str, received_chksum, calculated_chksum
    )

    # Add a note if the calculation resulted in 0, likely due to offloading
    if not valid and calculated_chksum == 0:
        reason = f"Invalid (Rcv: {received_chksum:#04x}, Calc: {calculated_chksum:#04x} - Possibly due to checksum offloading)"
        logging.warning("Calculated checksum is 0. This might be due to NIC checksum offloading when capturing locally.")
    elif not valid:
        reason = f"Invalid (Rcv: {received_chksum:#04x}, Calc: {calculated_chksum:#04x})"
    else:
        reason = "Valid"

    # Return validation status and reason, but don't necessarily drop packet here
    # based only on this check when capturing locally. The main goal is demonstration.
    return valid, reason


def reassemble_fragments(packet_id):
    """Attempts to reassemble fragments for a given packet ID."""
    if packet_id not in fragments_buffer:
        logging.warning("Attempted reassembly for unknown packet ID: %d", packet_id)
        return None

    frags = fragments_buffer[packet_id]
    sorted_offsets = sorted(frags.keys())

    # Check if we have the last fragment (based on previously stored offset)
    # Note: A more robust check might involve total length if available
    expected_last_offset = fragments_last_offset.get(packet_id, -1)
    if expected_last_offset == -1:
        logging.debug("Don't know the last offset for ID %d yet.", packet_id)
        return None  # Cannot determine completeness yet

    # Check if the highest offset we have matches the expected last offset
    if not frags or sorted_offsets[-1] != expected_last_offset:
        logging.debug(
            "Highest received offset %d != expected last %d for ID %d",
            sorted_offsets[-1] if frags else "N/A",
            expected_last_offset,
            packet_id,
        )
        return None  # Not all fragments received yet

    # Check for contiguous fragments
    reassembled_payload = b""
    current_offset = 0
    for offset in sorted_offsets:
        if offset != current_offset:
            logging.warning(
                "Missing fragment for ID %d at offset %d", packet_id, current_offset
            )
            return None  # Gap detected
        fragment_data = frags[offset]
        reassembled_payload += fragment_data
        current_offset += len(fragment_data)

    logging.info(
        "Successfully reassembled %d bytes for Packet ID %d.",
        len(reassembled_payload),
        packet_id,
    )
    # Clean up buffer for this ID
    del fragments_buffer[packet_id]
    del fragments_last_offset[packet_id]
    if packet_id in fragments_total_len:
        del fragments_total_len[packet_id]
    return reassembled_payload


def process_packet(packet):
    """Callback function for sniff(). Processes individual packets."""
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_id = ip_layer.id
        flags = ip_layer.flags
        frag_offset = ip_layer.frag

        logging.info(
            "Received IP Packet ID: %d from %s to %s (Flags: %s, Frag Offset: %d)",
            packet_id,
            src_ip,
            dst_ip,
            flags,
            frag_offset,
        )

        # Validate IP Checksum
        is_valid_checksum, reason = validate_ip_checksum(ip_layer)
        # NOTE: We log the warning but won't drop based on checksum for this demo
        # if not is_valid_checksum:
        #     logging.warning(
        #         "Dropping packet ID %d due to invalid IP checksum.", packet_id
        #     )
        #     return  # Don't process further

        payload = packet.payload  # This is the next layer (e.g., UDP) or Raw

        # Handle Fragmentation
        is_fragmented = flags.MF or (frag_offset > 0)
        if is_fragmented:
            logging.info("Packet ID %d is a fragment.", packet_id)
            # Store the payload of the IP packet (which includes UDP header + data)
            fragment_payload = raw(payload)
            offset_bytes = frag_offset * 8  # Offset is in units of 8 bytes
            fragments_buffer[packet_id][offset_bytes] = fragment_payload
            fragments_total_len[packet_id] += len(fragment_payload)

            if not flags.MF:  # This is the last fragment for this ID
                logging.info(
                    "Last fragment received for ID %d at offset %d.",
                    packet_id,
                    offset_bytes,
                )
                fragments_last_offset[packet_id] = offset_bytes
                # Attempt reassembly now that we have the last fragment
                reassembled_ip_payload = reassemble_fragments(packet_id)
                if reassembled_ip_payload:
                    # Now we need to parse the reassembled L4+ data
                    # Assuming UDP for this example
                    try:
                        # Rebuild the next layer(s) from the reassembled bytes
                        # Important: This assumes the payload *after* IP was consistent
                        # If L4 headers were also fragmented, this is more complex
                        l4_packet = UDP(
                            reassembled_ip_payload
                        )  # Attempt to parse as UDP
                        if l4_packet.haslayer(Raw):
                            app_payload = l4_packet[Raw].load
                            logging.info(
                                "[Reassembled] UDP Payload (%d bytes): %s",
                                len(app_payload),
                                app_payload.decode(errors="ignore"),
                            )
                        else:
                            logging.warning(
                                "[Reassembled] No Raw payload found after UDP."
                            )
                    except Exception as e:
                        logging.error(
                            "[Reassembled] Failed to parse L4+ payload for ID %d: %s",
                            packet_id,
                            e,
                        )

        else:  # Not a fragment
            if UDP in packet and Raw in packet:
                udp_payload = packet[Raw].load
                logging.info(
                    "[Unfragmented] UDP Payload (%d bytes): %s",
                    len(udp_payload),
                    udp_payload.decode(errors="ignore"),
                )
            else:
                logging.debug(
                    "Received non-fragmented IP packet without expected UDP/Raw layers."
                )

    else:
        logging.debug("Received non-IP packet.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sniff UDP packets and demonstrate IP checksum validation and reassembly."
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_LISTEN_PORT,
        help="UDP port to listen on.",
    )
    parser.add_argument(
        "-i",
        "--iface",
        default=None,
        help="Interface to sniff on (optional, Scapy usually finds default).",
    )

    args = parser.parse_args()

    filter_str = f"udp port {args.port}" # Restore the filter string
    logging.info(
        "Starting sniffer on interface '%s' with filter: '%s'", # Restore log message with filter
        args.iface or "default",
        filter_str, # Use filter in log
    )
    logging.info("Waiting for packets...")

    try:
        # store=0 prevents Scapy from keeping all packets in memory
        sniff(filter=filter_str, prn=process_packet, iface=args.iface, store=0) # Use filter in sniff()
    except PermissionError:
        logging.error(
            "Permission denied. Sniffing requires root/administrator privileges."
        )
    except Exception as e:
        logging.error("An error occurred during sniffing: %s", e)
    finally:
        logging.info("Sniffer stopped.")

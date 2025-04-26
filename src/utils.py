"""Utility functions for the secure file transfer system."""

import hashlib
import struct
import time
import os
from typing import Dict, Set, Optional, Tuple
import socket
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from .config import (
    HEADER_FORMAT,
    HEADER_SIZE,
    WINDOW_SIZE,
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
)


def calculate_checksum(data: bytes) -> bytes:
    """Calculates the MD5 checksum for the given data."""
    return hashlib.md5(data).digest()


def create_packet(seq_num: int, data: bytes, flags: int = 0) -> bytes:
    """Creates a packet with header and data."""
    checksum = calculate_checksum(data)
    data_len = len(data)
    header = struct.pack(HEADER_FORMAT, seq_num, data_len, checksum, flags)
    return header + data


def unpack_header(header_data: bytes) -> tuple[int, int, bytes, int]:
    """Unpacks the header data."""
    if len(header_data) != HEADER_SIZE:
        raise ValueError(
            f"Invalid header size: expected {HEADER_SIZE}, got {len(header_data)}"
        )
    return struct.unpack(HEADER_FORMAT, header_data)


class SlidingWindow:
    """Implements sliding window for flow control."""

    def __init__(self, size: int = WINDOW_SIZE):
        self.size = size
        self.base = 0
        self.next_seq_num = 0
        # Store the actual packet bytes and potentially original data if needed later
        self.packets: Dict[
            int, Tuple[bytes, Optional[bytes]]
        ] = {}  # {seq: (packet_bytes, original_data)}
        self.send_times: Dict[int, float] = {}
        self.acked: Set[int] = set()

    def is_full(self) -> bool:
        return self.next_seq_num >= self.base + self.size

    def has_outstanding_packets(self) -> bool:
        """Check if there are any packets sent but not yet acknowledged."""
        return self.base < self.next_seq_num

    def slide(self, ack_num: int):
        if ack_num >= self.base:
            self.acked.add(ack_num)
            while self.base in self.acked and self.base < self.next_seq_num:
                self.packets.pop(self.base, None)
                self.send_times.pop(self.base, None)
                # No need to pop from self.acked, keep it for potential duplicate ACKs
                self.base += 1

    def add_packet(
        self, seq_num: int, packet_bytes: bytes, original_data: Optional[bytes] = None
    ):
        """Add packet bytes and its send time to the window buffer."""
        if seq_num >= self.base + self.size:
            logging.warning(
                "Attempted to add packet %d beyond window size (%d) from base %d",
                seq_num,
                self.size,
                self.base,
            )
            return  # Or raise error
        self.packets[seq_num] = (packet_bytes, original_data)
        self.send_times[seq_num] = time.time()
        self.next_seq_num = max(self.next_seq_num, seq_num + 1)

    def update_send_time(self, seq_num: int):
        """Update the send time for a retransmitted packet."""
        if seq_num in self.send_times:
            self.send_times[seq_num] = time.time()

    def get_packet_for_retransmission(
        self, seq_num: int
    ) -> Tuple[Optional[bytes], Optional[bytes]]:
        """Get the packet bytes and original data for retransmission."""
        return self.packets.get(seq_num, (None, None))

    def get_timeout_packets(self, timeout: float) -> Set[int]:
        current_time = time.time()
        # Return sequence numbers of packets in the current window that timed out
        return {
            seq_num
            for seq_num in range(self.base, self.next_seq_num)
            if seq_num not in self.acked
            and seq_num in self.send_times
            and current_time - self.send_times[seq_num] > timeout
        }


class PacketBuffer:
    """Handles packet reassembly on receiver side."""

    def __init__(self):
        self.received: Dict[int, bytes] = {}
        self.missing: Set[int] = set()
        self.next_expected = 0
        self.highest_received = -1

    def add_packet(self, seq_num: int, data: bytes) -> bool:
        """Add packet to buffer and return True if it was needed."""
        if seq_num < self.next_expected:
            return False  # Already processed this packet

        self.received[seq_num] = data
        self.highest_received = max(self.highest_received, seq_num)

        # Update missing packets set
        if seq_num > self.next_expected:
            self.missing.update(range(self.next_expected, seq_num))
        self.missing.discard(seq_num)

        # Update next expected
        while self.next_expected in self.received:
            self.next_expected += 1

        return True

    def get_missing_packets(self) -> Set[int]:
        """Get sequence numbers of missing packets."""
        return self.missing

    def is_complete_until(self, seq_num: int) -> bool:
        """Check if all packets up to seq_num are received."""
        return all(i in self.received for i in range(self.next_expected, seq_num))

    def get_completed_data(self) -> Tuple[bytes, int]:
        """Get reassembled data up to the first gap."""
        data = b""
        last_seq = self.next_expected
        for seq_num in range(self.next_expected):
            if seq_num not in self.received:
                break
            data += self.received[seq_num]
            last_seq = seq_num + 1
            del self.received[seq_num]
        return data, last_seq


# --- Cryptography Functions ---


def load_private_key(path):
    """Loads an RSA private key from a PEM file."""
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Add password if key is encrypted
        )
    return private_key


def load_public_key(path):
    """Loads an RSA public key from a PEM file."""
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Encrypts data using RSA public key (OAEP padding)."""
    return public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Decrypts data using RSA private key (OAEP padding)."""
    return private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_sign(private_key, data: bytes) -> bytes:
    """Signs data using RSA private key (PSS padding)."""
    return private_key.sign(
        data,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    """Verifies an RSA signature using the public key (PSS padding)."""
    try:
        public_key.verify(
            signature,
            data,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def generate_aes_key() -> bytes:
    """Generates a random AES key."""
    return os.urandom(AES_KEY_SIZE)


def aes_encrypt(aes_key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Encrypts plaintext using AES-GCM. Returns (nonce, ciphertext)."""
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(AES_NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # No associated data
    return nonce, ciphertext


def aes_decrypt(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypts ciphertext using AES-GCM."""
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)  # No associated data


def calculate_file_hash(filepath: str) -> bytes:
    """Calculates the SHA-256 hash of a file."""
    hasher = hashes.Hash(hashes.SHA256())
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.finalize()


# --- Network Helpers ---


def receive_all(sock: socket.socket, length: int) -> bytes | None:
    """Helper function to receive exactly 'length' bytes from a socket."""
    data = b""
    try:
        # Set a temporary timeout specifically for this receive operation
        # Use the socket's default timeout if available, otherwise a reasonable value
        # original_timeout = sock.gettimeout()
        # where are we using this? if not, remove it

        # If no timeout is set, let's not impose one here unless necessary
        # sock.settimeout(max(original_timeout, 5.0) if original_timeout else 5.0)

        while len(data) < length:
            more = sock.recv(length - len(data))
            if not more:
                logging.error(
                    "Socket connection broken prematurely while expecting %d bytes (got %d).",
                    length,
                    len(data),
                )
                return None
            data += more
        return data
    except socket.timeout:
        logging.warning(
            "Timeout while waiting for %d bytes (received %d).", length, len(data)
        )
        return None  # Indicate timeout occurred
    except socket.error as e:  # <-- Catch specific socket errors
        logging.error("Socket error receiving data in receive_all: %s", e)
        return None  # Indicate socket error
    # Removed the general Exception catch, let others propagate if needed
    # finally:
    # Restore original timeout if it was changed
    # sock.settimeout(original_timeout)


def send_data_with_length(sock: socket.socket, data: bytes):
    """Sends data prefixed with its 4-byte length."""
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)


def receive_data_with_length(sock: socket.socket) -> bytes | None:
    """Receives data prefixed with its 4-byte length."""
    length_bytes = receive_all(sock, 4)
    if length_bytes is None:
        return None
    length = struct.unpack("!I", length_bytes)[0]
    return receive_all(sock, length)

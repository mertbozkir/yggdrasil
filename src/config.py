import struct
import os

# Network configuration
SERVER_HOST = "127.0.0.1"  # Loopback address for local testing
SERVER_PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

# File transfer parameters
CHUNK_SIZE = 1024  # Size of data payload for each packet
HEADER_FORMAT = "!II16sB"  # Format: Sequence num (uint32), Data len (uint32), Checksum (16 bytes), Flags (uint8)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Flow control parameters
WINDOW_SIZE = 5  # Number of packets in flight
MAX_RETRIES = 3  # Maximum retransmission attempts
ACK_TIMEOUT = 2.0  # Seconds to wait for ACK

# Packet types and flags
FLAG_FIN = 0x01  # Final packet
FLAG_ACK = 0x02  # Acknowledgment
FLAG_NACK = 0x04  # Negative acknowledgment
FLAG_RETRANS = 0x08  # Retransmitted packet

# File paths and directories
OUTPUT_DIR = ".files/output"  # Directory for received files
INPUT_DIR = ".files/input"  # Directory for input files
os.makedirs(OUTPUT_DIR, exist_ok=True)  # Create output directory if it doesn't exist
os.makedirs(INPUT_DIR, exist_ok=True)  # Create input directory if it doesn't exist

# Timeout for socket operations (optional but recommended)
SOCKET_TIMEOUT = 5  # seconds

# Default input file
DEFAULT_INPUT_FILE = ".files/input/test.txt"

# Security parameters
KEY_DIR = ".keys"
SERVER_PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "server_private.pem")
SERVER_PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "server_public.pem")
CLIENT_PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "client_private.pem")
CLIENT_PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "client_public.pem")

AUTH_CHALLENGE_SIZE = 32  # Size of the random challenge for authentication
AES_KEY_SIZE = 32  # AES-256 key size in bytes
AES_NONCE_SIZE = 12  # AES-GCM recommended nonce size

# Integrity
FILE_HASH_ALGO = "sha256"

import socket
import os
import struct
import logging
import argparse
import time
from .config import (
    SERVER_HOST,
    SERVER_PORT,
    HEADER_SIZE,
    CHUNK_SIZE,
    FLAG_FIN,
    FLAG_ACK,
    FLAG_NACK,
    FLAG_RETRANS,
    SOCKET_TIMEOUT,
    ACK_TIMEOUT,
    MAX_RETRIES,
    DEFAULT_INPUT_FILE,
    CLIENT_PRIVATE_KEY_PATH,
    SERVER_PUBLIC_KEY_PATH,
    AUTH_CHALLENGE_SIZE,
    FILE_HASH_ALGO,
)
from .utils import (
    create_packet,
    unpack_header,
    SlidingWindow,
    receive_all,
    load_private_key,
    load_public_key,
    rsa_sign,
    rsa_encrypt,
    generate_aes_key,
    aes_encrypt,
    calculate_file_hash,
    send_data_with_length,
    receive_data_with_length,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - CLIENT - %(levelname)s - %(message)s"
)


def handle_ack(sock: socket.socket, window: SlidingWindow) -> bool:
    """Handle incoming ACK/NACK. Returns False if connection should be terminated."""
    try:
        sock.settimeout(0.1)
        header_data = sock.recv(HEADER_SIZE)
        if not header_data:
            logging.warning("No ACK data received, might be end of connection.")
            return False

        seq_num, _, _, flags = unpack_header(header_data)

        if flags & FLAG_ACK:
            logging.debug(f"Received ACK for sequence {seq_num}")
            window.slide(seq_num)
        elif flags & FLAG_NACK:
            logging.warning(f"Received NACK for sequence {seq_num}")
            if seq_num in window.packets:
                packet_to_resend, _ = window.get_packet_for_retransmission(seq_num)
                if packet_to_resend:
                    logging.info(f"Resending packet {seq_num} due to NACK.")
                    sock.sendall(packet_to_resend)
                    window.update_send_time(seq_num)
            else:
                logging.warning(
                    f"Received NACK for {seq_num}, but packet not in window buffer."
                )
        else:
            logging.warning(f"Received packet with unexpected flags: {flags:#04x}")

        return True
    except socket.timeout:
        return True
    except struct.error as e:
        logging.error(f"Error unpacking header during ACK handling: {e}")
        return False
    except Exception as e:
        logging.error(f"Error handling ACK: {e}")
        return False
    finally:
        sock.settimeout(SOCKET_TIMEOUT)


def run_client(host=SERVER_HOST, port=SERVER_PORT, input_file=None):
    """Runs the secure file transfer client."""
    if not input_file or not os.path.exists(input_file):
        logging.error(f"Input file not found or not specified: {input_file}")
        return

    try:
        client_private_key = load_private_key(CLIENT_PRIVATE_KEY_PATH)
        server_public_key = load_public_key(SERVER_PUBLIC_KEY_PATH)
        logging.info("Client and Server keys loaded.")
    except Exception as e:
        logging.error(f"Failed to load cryptographic keys: {e}")
        return

    aes_key = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            logging.info(f"Connecting to {host}:{port}...")
            s.connect((host, port))
            s.settimeout(SOCKET_TIMEOUT)
            logging.info("Connected.")

            logging.info("Starting authentication...")
            challenge = receive_data_with_length(s)
            if not challenge:
                logging.error("Failed to receive challenge from server.")
                return
            logging.debug(f"Received challenge: {challenge.hex()}")

            signature = rsa_sign(client_private_key, challenge)
            logging.debug(f"Generated signature: {signature.hex()}")

            send_data_with_length(s, signature)
            logging.info("Sent signature to server.")

            auth_result = receive_data_with_length(s)
            if not auth_result or auth_result != b"AUTH_OK":
                logging.error(f"Authentication failed. Server response: {auth_result}")
                return
            logging.info("Authentication successful.")

            logging.info("Starting AES key exchange...")
            aes_key = generate_aes_key()
            logging.debug(f"Generated AES key: {aes_key.hex()}")

            encrypted_aes_key = rsa_encrypt(server_public_key, aes_key)
            logging.debug(f"Encrypted AES key: {encrypted_aes_key.hex()}")

            send_data_with_length(s, encrypted_aes_key)
            logging.info("Sent encrypted AES key to server.")

            key_ack = receive_data_with_length(s)
            if not key_ack or key_ack != b"AES_KEY_OK":
                logging.error(
                    f"Server did not confirm AES key reception. Response: {key_ack}"
                )
                return
            logging.info("AES key exchange successful.")

            logging.info("Sending file information...")
            original_filename = os.path.basename(input_file)
            send_data_with_length(s, original_filename.encode("utf-8"))

            file_hash = calculate_file_hash(input_file)
            logging.info(f"Calculated file hash ({FILE_HASH_ALGO}): {file_hash.hex()}")
            send_data_with_length(s, file_hash)
            logging.info("Sent filename and file hash.")

            logging.info("Starting encrypted file transfer...")
            window = SlidingWindow()
            seq_num = 0
            retries = {}

            with open(input_file, "rb") as f:
                eof_reached = False
                last_ack_received_time = time.time()

                while not eof_reached or window.has_outstanding_packets():
                    current_time = time.time()

                    if (
                        window.has_outstanding_packets()
                        and current_time - last_ack_received_time
                        > SOCKET_TIMEOUT * MAX_RETRIES
                    ):
                        logging.error(
                            "Connection timed out waiting for ACKs for too long."
                        )
                        raise socket.timeout("Overall ACK timeout")

                    if handle_ack(s, window):
                        last_ack_received_time = time.time()

                    timeout_packets = window.get_timeout_packets(ACK_TIMEOUT)
                    for seq_timeout in timeout_packets:
                        retry_count = retries.get(seq_timeout, 0)
                        if retry_count >= MAX_RETRIES:
                            logging.error(
                                f"Max retries exceeded for packet {seq_timeout}. Aborting."
                            )
                            raise ConnectionError(
                                f"Max retries exceeded for packet {seq_timeout}"
                            )

                        packet_to_resend, original_data = (
                            window.get_packet_for_retransmission(seq_timeout)
                        )
                        if packet_to_resend:
                            logging.warning(
                                f"Timeout detected for packet {seq_timeout}. Resending (Attempt {retry_count + 1})..."
                            )
                            s.sendall(packet_to_resend)
                            window.update_send_time(seq_timeout)
                            retries[seq_timeout] = retry_count + 1

                    while not window.is_full() and not eof_reached:
                        chunk = f.read(CHUNK_SIZE)
                        flags = 0
                        if not chunk:
                            eof_reached = True
                            break

                        nonce, ciphertext = aes_encrypt(aes_key, chunk)
                        encrypted_payload = nonce + ciphertext

                        packet = create_packet(seq_num, encrypted_payload, flags)
                        s.sendall(packet)
                        window.add_packet(seq_num, packet, chunk)
                        retries[seq_num] = 0
                        logging.debug(
                            f"Sent encrypted packet {seq_num}, Payload size: {len(encrypted_payload)}"
                        )
                        seq_num += 1

                    if (
                        window.is_full() or eof_reached
                    ) and window.has_outstanding_packets():
                        time.sleep(0.05)

                if eof_reached and not window.has_outstanding_packets():
                    logging.info("All data packets ACKed. Sending FIN.")
                    fin_packet = create_packet(seq_num, b"", FLAG_FIN)
                    fin_acked = False
                    fin_retries = 0
                    while not fin_acked and fin_retries < MAX_RETRIES:
                        s.sendall(fin_packet)
                        try:
                            s.settimeout(ACK_TIMEOUT)
                            header_data = s.recv(HEADER_SIZE)
                            if header_data:
                                ack_seq, _, _, ack_flags = unpack_header(header_data)
                                if ack_seq == seq_num and ack_flags & FLAG_ACK:
                                    fin_acked = True
                                    logging.info("FIN packet acknowledged by server.")
                            else:
                                logging.warning(
                                    "Server closed connection before FIN ACK."
                                )
                                break
                        except socket.timeout:
                            logging.warning(
                                f"Timeout waiting for FIN ACK (Attempt {fin_retries + 1})"
                            )
                            fin_retries += 1
                        except Exception as e:
                            logging.error(f"Error receiving FIN ACK: {e}")
                            break

                    if not fin_acked:
                        logging.error("Failed to get acknowledgment for FIN packet.")

                    logging.info("File transfer process complete.")
                else:
                    logging.error(
                        "Transfer loop exited unexpectedly before sending FIN."
                    )

        except socket.timeout:
            logging.error(f"Connection timed out during operation with {host}:{port}.")
        except ConnectionRefusedError:
            logging.error(f"Connection refused by server {host}:{port}.")
        except ConnectionError as e:
            logging.error(f"Connection error: {e}")
        except Exception as e:
            logging.error(f"An unexpected client error occurred: {e}", exc_info=True)
        finally:
            logging.info("Closing connection.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send a file securely to the server.")
    parser.add_argument("filepath", help="Path to the file to send.")
    parser.add_argument(
        "-s",
        "--server",
        default=SERVER_HOST,
        help=f"Server hostname or IP address (default: {SERVER_HOST})",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=SERVER_PORT,
        help=f"Server port number (default: {SERVER_PORT})",
    )
    args = parser.parse_args()

    run_client(host=args.server, port=args.port, input_file=args.filepath)

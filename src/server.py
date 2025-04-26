"""Server implementation for the secure file transfer system."""

import socket
import logging
import argparse
import os

from .config import (
    SERVER_HOST,
    SERVER_PORT,
    HEADER_SIZE,
    FLAG_FIN,
    FLAG_ACK,
    FLAG_NACK,
    SOCKET_TIMEOUT,
    OUTPUT_DIR,
    SERVER_PRIVATE_KEY_PATH,
    CLIENT_PUBLIC_KEY_PATH,
    AUTH_CHALLENGE_SIZE,
    AES_NONCE_SIZE,
    FILE_HASH_ALGO,
)
from .utils import (
    unpack_header,
    calculate_checksum,
    PacketBuffer,
    create_packet,
    load_private_key,
    load_public_key,
    rsa_verify,
    rsa_decrypt,
    aes_decrypt,
    calculate_file_hash,
    send_data_with_length,
    receive_data_with_length,
    receive_all,
)
from cryptography.exceptions import InvalidTag

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - SERVER - %(levelname)s - %(message)s"
)


def send_ack(sock: socket.socket, seq_num: int):
    """Send acknowledgment for received packet."""
    try:
        ack_packet = create_packet(seq_num, b"", FLAG_ACK)
        sock.sendall(ack_packet)
        logging.debug("Sent ACK for Seq=%d", seq_num)
    except Exception as e:
        logging.error("Failed to send ACK for Seq=%d: %s", seq_num, e)


def send_nack(sock: socket.socket, seq_num: int):
    """Send negative acknowledgment for corrupted packet."""
    try:
        nack_packet = create_packet(seq_num, b"", FLAG_NACK)
        sock.sendall(nack_packet)
        logging.warning("Sent NACK for Seq=%d", seq_num)
    except Exception as e:
        logging.error("Failed to send NACK for Seq=%d: %s", seq_num, e)


def run_server(host=SERVER_HOST, port=SERVER_PORT):
    """Runs the secure file transfer server."""
    try:
        # Load Keys
        server_private_key = load_private_key(SERVER_PRIVATE_KEY_PATH)
        client_public_key = load_public_key(CLIENT_PUBLIC_KEY_PATH)
        logging.info("Server and Client keys loaded.")
    except Exception as e:
        logging.error("Failed to load cryptographic keys: %s", e)
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        logging.info("Server listening securely on %s:%d", host, port)

        while True:  # Keep server running for multiple connections
            conn, addr = s.accept()
            aes_key = None  # Reset for each connection
            output_path = None
            received_file_hash = None
            transfer_successful = False

            with conn:
                conn.settimeout(SOCKET_TIMEOUT)
                logging.info("Connection accepted from %s", addr)

                try:
                    # --- Stage 1: Authentication ---
                    logging.info("Starting authentication with %s...", addr)
                    # 1. Generate and send challenge
                    challenge = os.urandom(AUTH_CHALLENGE_SIZE)
                    send_data_with_length(conn, challenge)
                    logging.debug("Sent challenge: %s", challenge.hex())

                    # 2. Receive signature
                    signature = receive_data_with_length(conn)
                    if not signature:
                        raise ConnectionError("Client did not send signature.")
                    logging.debug("Received signature: %s", signature.hex())

                    # 3. Verify signature
                    if not rsa_verify(client_public_key, signature, challenge):
                        logging.error(
                            "Authentication failed for %s. Invalid signature.", addr
                        )
                        send_data_with_length(conn, b"AUTH_FAILED_SIGNATURE")
                        continue  # Close connection and wait for next
                    logging.info("Client signature verified.")

                    # 4. Send authentication success
                    send_data_with_length(conn, b"AUTH_OK")
                    logging.info("Authentication successful for %s.", addr)

                    # --- Stage 2: AES Key Exchange ---
                    logging.info("Starting AES key exchange with %s...", addr)
                    # 1. Receive encrypted AES key
                    encrypted_aes_key = receive_data_with_length(conn)
                    if not encrypted_aes_key:
                        raise ConnectionError("Client did not send AES key.")
                    logging.debug("Received encrypted AES key.")

                    # 2. Decrypt AES key
                    try:
                        aes_key = rsa_decrypt(server_private_key, encrypted_aes_key)
                        if len(aes_key) != 32:  # Basic sanity check for AES-256
                            raise ValueError("Decrypted key has incorrect length.")
                        logging.debug("Decrypted AES key: %s", aes_key.hex())
                    except Exception as e:
                        logging.error("Failed to decrypt AES key from %s: %s", addr, e)
                        send_data_with_length(conn, b"AES_KEY_DECRYPT_FAILED")
                        continue  # Close connection

                    # 3. Send confirmation
                    send_data_with_length(conn, b"AES_KEY_OK")
                    logging.info("AES key exchange successful with %s.", addr)

                    # --- Stage 3: File Info and Hashing ---
                    logging.info("Receiving file information from %s...", addr)
                    # 1. Receive original filename
                    original_filename_bytes = receive_data_with_length(conn)
                    if not original_filename_bytes:
                        raise ConnectionError("Client did not send filename.")
                    original_filename = original_filename_bytes.decode("utf-8")

                    # 2. Receive file hash
                    received_file_hash = receive_data_with_length(conn)
                    if not received_file_hash:
                        raise ConnectionError("Client did not send file hash.")
                    logging.info("Receiving file: %s", original_filename)
                    logging.info(
                        "Expected hash (%s): %s",
                        FILE_HASH_ALGO,
                        received_file_hash.hex(),
                    )

                    # Create output path
                    output_filename = f"received-{original_filename}"
                    output_path = os.path.join(OUTPUT_DIR, output_filename)
                    logging.info("Will save as: %s", output_path)

                    # --- Stage 4: Encrypted File Transfer ---
                    logging.info("Starting encrypted file transfer from %s...", addr)
                    buffer = PacketBuffer()
                    last_packet_received = False
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)

                    with open(output_path, "wb") as f:
                        while not last_packet_received:
                            try:
                                # Receive header
                                header_data = receive_all(conn, HEADER_SIZE)
                                if header_data is None:
                                    logging.error(
                                        "Connection closed unexpectedly while receiving header."
                                    )
                                    break

                                seq_num, data_len, received_checksum, flags = (
                                    unpack_header(header_data)
                                )
                                logging.debug(
                                    "Received Encrypted Header: Seq=%d, EncryptedLen=%d, Flags=%#04x",
                                    seq_num,
                                    data_len,
                                    flags,
                                )

                                # Check for FIN flag first
                                if flags & FLAG_FIN:
                                    logging.info(
                                        "FIN flag received in packet Seq=%d.", seq_num
                                    )
                                    last_packet_received = True
                                    send_ack(conn, seq_num)  # ACK the FIN
                                    # Write remaining buffer
                                    completed_data, next_expected = (
                                        buffer.get_completed_data()
                                    )
                                    if completed_data:
                                        f.write(completed_data)
                                        logging.debug(
                                            "Wrote final buffered data up to seq %d",
                                            next_expected - 1,
                                        )
                                    break

                                # Receive encrypted payload (Nonce + Ciphertext)
                                encrypted_payload = b""
                                if data_len > 0:
                                    encrypted_payload = receive_all(conn, data_len)
                                    if encrypted_payload is None:
                                        logging.error(
                                            "Failed to receive encrypted payload for Seq=%d.",
                                            seq_num,
                                        )
                                        break

                                # Verify Checksum (of the encrypted payload)
                                calculated_checksum = calculate_checksum(
                                    encrypted_payload
                                )
                                if received_checksum != calculated_checksum:
                                    logging.warning(
                                        "Checksum mismatch for encrypted Seq=%d. Sending NACK.",
                                        seq_num,
                                    )
                                    send_nack(conn, seq_num)
                                    continue

                                # Decrypt payload
                                try:
                                    if len(encrypted_payload) < AES_NONCE_SIZE:
                                        raise ValueError(
                                            "Encrypted payload too short to contain nonce."
                                        )
                                    nonce = encrypted_payload[:AES_NONCE_SIZE]
                                    ciphertext = encrypted_payload[AES_NONCE_SIZE:]
                                    decrypted_data = aes_decrypt(
                                        aes_key, nonce, ciphertext
                                    )
                                except InvalidTag as e:
                                    logging.error(
                                        "Decryption failed (Invalid Tag) for Seq=%d: %s. Sending NACK.",
                                        seq_num,
                                        e,
                                    )
                                    send_nack(conn, seq_num)
                                    continue

                                # Add decrypted packet to buffer
                                if buffer.add_packet(seq_num, decrypted_data):
                                    logging.debug(
                                        "Added decrypted packet Seq=%d to buffer.",
                                        seq_num,
                                    )
                                    send_ack(conn, seq_num)
                                else:
                                    logging.warning(
                                        "Duplicate or old packet Seq=%d, sending ACK anyway.",
                                        seq_num,
                                    )
                                    send_ack(conn, seq_num)

                                # Write completed data
                                completed_data, next_expected = (
                                    buffer.get_completed_data()
                                )
                                if completed_data:
                                    f.write(completed_data)
                                    logging.debug(
                                        "Wrote buffered data up to seq %d",
                                        next_expected - 1,
                                    )

                            except socket.timeout:
                                logging.warning(
                                    "Socket timed out waiting for packet data."
                                )
                                break
                            except ValueError as e:
                                logging.error("Header/Decryption error: %s", e)
                                break
                            except Exception as e:
                                logging.error(
                                    "Unexpected error in receive loop: %s",
                                    e,
                                    exc_info=True,
                                )
                                break

                    # --- Stage 5: Integrity Check ---
                    if last_packet_received:
                        missing_packets = buffer.get_missing_packets()
                        if not missing_packets:
                            logging.info(
                                "File reassembly complete. Verifying integrity..."
                            )
                            # Close file before hashing
                            calculated_hash = calculate_file_hash(output_path)
                            logging.info(
                                "Calculated hash for received file: %s",
                                calculated_hash.hex(),
                            )
                            if calculated_hash == received_file_hash:
                                logging.info(
                                    "Integrity check PASSED. File received successfully."
                                )
                                transfer_successful = True
                                # Optionally send final confirmation to client
                                # send_data_with_length(conn, b"TRANSFER_COMPLETE_OK")
                            else:
                                logging.error(
                                    "Integrity check FAILED! Hashes do not match."
                                )
                                # Optionally send failure message
                                # send_data_with_length(conn, b"TRANSFER_FAILED_HASH")
                        else:
                            logging.error(
                                "File transfer incomplete. Missing sequence numbers: %s",
                                sorted(list(missing_packets)),
                            )
                    else:
                        logging.error(
                            "File transfer did not complete normally (FIN not received or connection lost)."
                        )

                except ConnectionError as e:
                    logging.error("Connection error with %s: %s", addr, e)
                except socket.timeout:
                    logging.error(
                        "Socket timeout during critical operation with %s.", addr
                    )
                except Exception as e:
                    logging.error(
                        "Unhandled exception during connection with %s: %s",
                        addr,
                        e,
                        exc_info=True,
                    )
                finally:
                    logging.info("Closing connection with %s.", addr)
                    # Clean up incomplete file if transfer failed and path exists
                    if (
                        not transfer_successful
                        and output_path
                        and os.path.exists(output_path)
                    ):
                        try:
                            logging.warning(
                                "Deleting potentially corrupt/incomplete file: %s",
                                output_path,
                            )
                            os.remove(output_path)
                        except OSError as e_os:
                            logging.error(
                                "Failed to delete incomplete file %s: %s",
                                output_path,
                                e_os,
                            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Start the secure file transfer server."
    )
    parser.add_argument(
        "-s",
        "--host",
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

    run_server(host=args.host, port=args.port)

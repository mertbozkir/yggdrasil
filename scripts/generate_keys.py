from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# Configuration
KEY_DIR = ".keys"
SERVER_PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "server_private.pem")
SERVER_PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "server_public.pem")
CLIENT_PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "client_private.pem")
CLIENT_PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "client_public.pem")
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_and_save_keys(private_path, public_path):
    """Generates an RSA key pair and saves them to PEM files."""
    print(f"Generating RSA key pair ({KEY_SIZE} bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE
    )
    public_key = private_key.public_key()

    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # Use password protection in production
    )

    # Serialize public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Save keys to files
    os.makedirs(KEY_DIR, exist_ok=True)
    with open(private_path, "wb") as f:
        f.write(pem_private)
    print(f"Private key saved to {private_path}")

    with open(public_path, "wb") as f:
        f.write(pem_public)
    print(f"Public key saved to {public_path}")


if __name__ == "__main__":
    generate_and_save_keys(SERVER_PRIVATE_KEY_PATH, SERVER_PUBLIC_KEY_PATH)
    generate_and_save_keys(CLIENT_PRIVATE_KEY_PATH, CLIENT_PUBLIC_KEY_PATH)
    print("RSA key generation complete.")

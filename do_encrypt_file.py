#!/usr/bin/env python3
import sys
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import argparse
import hashlib

def derive_key(uuid_key):
    """
    Derives an AES key from UUID using PBKDF2 with same parameters as JavaScript implementation:
    - SHA-256 hash
    - 100000 iterations
    - Fixed salt "salt"
    - 256-bit key length
    """
    # Convert string salt to bytes, matching JavaScript TextEncoder
    salt = "salt".encode('utf-8')

    # Create PBKDF2HMAC instance matching JavaScript parameters
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    # Derive key from UUID
    key = kdf.derive(uuid_key.encode('utf-8'))
    return key

def sha256_base64url(data: bytes) -> str:
    import base64
    h = hashlib.sha256(data).digest()
    b64 = base64.urlsafe_b64encode(h).decode('ascii')
    return b64.rstrip('=')

def encrypt_file(input_file, key_bytes):
    """
    Encrypts a file using AES-GCM with the provided raw key bytes.
    If you want to derive a key from a UUID string, call `derive_key(uuid)` before passing.
    Format: [12 bytes IV][remaining bytes ciphertext]
    """
    # key_bytes must be raw bytes of length suitable for AES (16/24/32)
    if not isinstance(key_bytes, (bytes, bytearray)):
        raise TypeError('key_bytes must be bytes')

    # Create AESGCM instance
    aesgcm = AESGCM(key_bytes)

    # Generate 12-byte IV (same as JavaScript)
    iv = os.urandom(12)

    # Read input file
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Encrypt the data
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    # Write IV followed by ciphertext
    output_file = input_file + '.encrypted'
    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

    return output_file

def main():
    parser = argparse.ArgumentParser(description='Encrypt a file using AES-GCM. Key may be a UUID (string) or a path to a raw key file.')
    parser.add_argument('key', help='UUID string or path to key file (raw bytes)')
    parser.add_argument('input_file', help='Path to input file to encrypt')
    parser.add_argument('--hash-filename', action='store_true', help='If set, write output to a filename that is the base64url(SHA256(key)) + .encrypted')
    args = parser.parse_args()

    key_arg = args.key
    input_file = args.input_file

    # If key_arg is a path to an existing file, read raw bytes and use as key
    if os.path.isfile(key_arg):
        with open(key_arg, 'rb') as kf:
            key_bytes = kf.read()
    else:
        # Treat as UUID string and derive key via PBKDF2
        key_bytes = derive_key(key_arg)

    # Validate key length for AESGCM (must be 16/24/32 bytes)
    if len(key_bytes) not in (16, 24, 32):
        print(f"Error: key length is {len(key_bytes)} bytes; AES key must be 16, 24, or 32 bytes.")
        sys.exit(1)

    try:
        if args.hash_filename:
            # compute base64url sha256 of key bytes and write output to that filename in same dir as input
            name = sha256_base64url(key_bytes)
            out_dir = os.path.dirname(os.path.abspath(input_file)) or '.'
            output_file = os.path.join(out_dir, f"{name}.encrypted")

            # Encrypt and write to the chosen filename
            aesgcm = AESGCM(key_bytes)
            iv = os.urandom(12)
            with open(input_file, 'rb') as f:
                plaintext = f.read()
            ciphertext = aesgcm.encrypt(iv, plaintext, None)
            with open(output_file, 'wb') as f:
                f.write(iv + ciphertext)
            print(f"File encrypted successfully. Output written to: {output_file}")
        else:
            output_file = encrypt_file(input_file, key_bytes)
            print(f"File encrypted successfully. Output written to: {output_file}")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

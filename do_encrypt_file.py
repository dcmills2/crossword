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

def encrypt_file(input_file, uuid_key):
    """
    Encrypts a file using AES-GCM with a key derived from UUID.
    Uses same parameters as JavaScript implementation.
    Format: [12 bytes IV][remaining bytes ciphertext]
    """
    # Derive the key
    key = derive_key(uuid_key)

    # Create AESGCM instance
    aesgcm = AESGCM(key)

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
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <encryption_key> <input_file>")
        sys.exit(1)

    key = sys.argv[1]
    input_file = sys.argv[2]

    try:
        output_file = encrypt_file(input_file, key)
        print(f"File encrypted successfully. Output written to: {output_file}")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

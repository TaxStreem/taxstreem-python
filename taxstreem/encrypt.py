# ---------------------
# Encryption Helpers
# ---------------------
import hashlib
import json
import os
import base64
from typing import Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(shared_secret: str) -> bytes:
    """
    Derive a 32-byte AES key from shared secret.
    TaxStreem docs specify: SHA-256(sharedSecret) → AES-256 key material.
    """
    return hashlib.sha256(shared_secret.encode()).digest()


def encrypt_payload(obj: Dict, aes_key: bytes) -> str:
    """
    Encrypt a JSON object with AES-256-GCM and return Base64(IV||ciphertext||tag).
    """
    # Convert JSON to bytes
    data = json.dumps(obj).encode("utf-8")

    # Generate a fresh 12-byte IV (96 bits)
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)

    # Perform encryption
    ciphertext = aesgcm.encrypt(iv, data, associated_data=None)

    # Final format: Base64(IV || ciphertext || tag)
    return base64.b64encode(iv + ciphertext).decode("utf-8")

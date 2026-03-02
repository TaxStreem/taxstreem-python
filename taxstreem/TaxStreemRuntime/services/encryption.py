"""
EncryptionService — mirrors src/services/encryption.service.ts from the Node SDK.

Encrypts credentials using AES-256-GCM so that the TaxStreem API can safely
receive sensitive data (e.g. TaxProMax login details) in transit.

Encryption format (matches Node SDK exactly):
    Base64( IV[12 bytes] || Ciphertext || Auth-Tag[16 bytes] )

Key derivation:
    key = SHA-256(shared_secret)  →  32-byte AES-256 key

AAD (Additional Authenticated Data):
    shared_secret encoded as UTF-8  (matches Node SDK: cipher.setAAD(...))
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Dict


class EncryptionService:
    """
    Provides AES-256-GCM encryption for sensitive credential payloads.

    Usage::

        svc = EncryptionService(shared_secret="your-shared-secret")
        encrypted = svc.encrypt_tax_pro_max_credential(
            {"email": "user@example.com", "password": "s3cr3t"}
        )
    """

    def __init__(self, shared_secret: str) -> None:
        self._shared_secret = shared_secret

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encrypt_tax_pro_max_credential(self, tpm_cred: Dict[str, Any]) -> str:
        """
        Encrypt TaxProMax credentials using AES-256-GCM.

        Matches the encryption logic in the Node SDK's
        ``EncryptionService.encryptTaxProMaxCredential``.

        Args:
            tpm_cred: A dictionary containing the credentials to encrypt
                      (e.g. ``{"email": "…", "password": "…"}``).

        Returns:
            Base64-encoded string: ``IV || Ciphertext || Auth-Tag``.
        """
        # Lazy import so `cryptography` is only required when encryption is used
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Derive 32-byte AES key: SHA-256(shared_secret)
        key: bytes = hashlib.sha256(self._shared_secret.encode("utf-8")).digest()

        # 12-byte random IV (96 bits) — same as Node SDK's randomBytes(12)
        iv: bytes = os.urandom(12)

        # Additional Authenticated Data — shared_secret as UTF-8 bytes
        # Matches Node SDK: cipher.setAAD(Buffer.from(this.sharedSecret, "utf8"))
        aad: bytes = self._shared_secret.encode("utf-8")

        plaintext: bytes = json.dumps(tpm_cred, separators=(",", ":")).encode("utf-8")

        aesgcm = AESGCM(key)
        # cryptography library appends the 16-byte auth tag to the ciphertext
        ciphertext_with_tag: bytes = aesgcm.encrypt(iv, plaintext, aad)

        # Final layout: IV (12) || Ciphertext || Tag (16)
        return base64.b64encode(iv + ciphertext_with_tag).decode("utf-8")

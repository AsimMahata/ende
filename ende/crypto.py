"""
Cryptographic primitives for ende.
Implements AES-256-GCM authenticated encryption and PBKDF2-HMAC-SHA256 key derivation.
Author: asim
"""

import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass

class AuthenticationError(CryptoError):
    """Raised when authentication fails (incorrect password or corrupted/tampered file)."""
    pass

PBKDF2_ITERATIONS = 200_000
KEY_SIZE_BYTES = 32  # 256 bits
SALT_SIZE_BYTES = 16
NONCE_SIZE_BYTES = 12

def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derives a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256."""
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    if not isinstance(salt, (bytes, bytearray)):
        raise ValueError("Salt must be bytes.")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_data(data: bytes, password: str, associated_data: bytes = None, iterations: int = PBKDF2_ITERATIONS) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts data using AES-256-GCM.
    Returns: (salt, nonce, ciphertext_with_tag)
    """
    salt = secrets.token_bytes(SALT_SIZE_BYTES)
    nonce = secrets.token_bytes(NONCE_SIZE_BYTES)
    key = derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)
    return salt, nonce, ciphertext

def decrypt_data(ciphertext: bytes, password: str, salt: bytes, nonce: bytes, associated_data: bytes = None, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Decrypts data using AES-256-GCM.
    Raises AuthenticationError if tag verification fails.
    """
    key = derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except InvalidTag as e:
        raise AuthenticationError("Authentication failed: Incorrect password or corrupted/tampered file.") from e

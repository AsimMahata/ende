"""
Binary container format and packaging for .ende files.
Supports single and double encryption layers, compression, and tamper detection.
Author: asim
"""

import json
import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from ende.crypto import (
    encrypt_data,
    decrypt_data,
    AuthenticationError,
    CryptoError,
    SALT_SIZE_BYTES,
    NONCE_SIZE_BYTES,
)
from ende.utils import calculate_sha256_bytes

MAGIC = b"ENDE"
CURRENT_VERSION = 1

# Header flags
FLAG_COMPRESSED = 0x01
FLAG_DOUBLE = 0x02

# Header struct: 4s (MAGIC) + B (VERSION) + B (FLAGS) + 16s (SALT) + 12s (NONCE) = 34 bytes
HEADER_FORMAT = f">4sBB{SALT_SIZE_BYTES}s{NONCE_SIZE_BYTES}s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class ContainerError(Exception):
    """Exception for format or container validation errors."""
    pass


class IntegrityError(ContainerError):
    """Exception when data checksum verification fails."""
    pass


def is_ende_file(file_path: Path) -> bool:
    """Checks if a file starts with the ENDE magic header."""
    if not file_path.is_file() or file_path.stat().st_size < HEADER_SIZE:
        return False
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            return magic == MAGIC
    except Exception:
        return False


def inspect_header(file_bytes: bytes) -> Dict[str, Any]:
    """Inspects the unencrypted header of an ENDE container."""
    if len(file_bytes) < HEADER_SIZE:
        raise ContainerError("File is too small to be a valid ENDE container.")
    
    magic, version, flags, salt, nonce = struct.unpack_from(HEADER_FORMAT, file_bytes, 0)
    if magic != MAGIC:
        raise ContainerError("Invalid file signature. Not an ENDE file.")
    
    return {
        "magic": magic.decode("latin1"),
        "version": version,
        "flags": flags,
        "is_compressed": bool(flags & FLAG_COMPRESSED),
        "is_double": bool(flags & FLAG_DOUBLE),
        "salt": salt,
        "nonce": nonce,
        "header_size": HEADER_SIZE,
    }


def encrypt_file_data(
    data: bytes,
    original_name: str,
    password: str,
    compress: bool = True,
    double_encrypt: bool = False,
    password2: Optional[str] = None,
) -> bytes:
    """
    Encrypts raw file bytes into an ENDE container.
    If double_encrypt is True, applies two layers of encryption:
      Layer 1 (inner): encrypted with password
      Layer 2 (outer): encrypted with password2 (or password if password2 is None)
    """
    original_size = len(data)
    original_sha256 = calculate_sha256_bytes(data)

    # 1. Inner Layer
    payload_to_encrypt = zlib.compress(data) if compress else data
    inner_metadata = {
        "author": "asim",
        "original_name": original_name,
        "original_size": original_size,
        "sha256": original_sha256,
        "compressed": compress,
        "layers": 2 if double_encrypt else 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    meta_json = json.dumps(inner_metadata).encode("utf-8")
    meta_len_bytes = struct.pack(">I", len(meta_json))
    inner_plaintext = meta_len_bytes + meta_json + payload_to_encrypt

    # Inner encryption
    inner_flags = (FLAG_COMPRESSED if compress else 0)
    salt1, nonce1, ciphertext1 = encrypt_data(inner_plaintext, password)
    inner_header = struct.pack(HEADER_FORMAT, MAGIC, CURRENT_VERSION, inner_flags, salt1, nonce1)
    inner_container = inner_header + ciphertext1

    if not double_encrypt:
        return inner_container

    # 2. Outer Layer (Double Encryption)
    outer_pwd = password2 if password2 is not None else password
    outer_flags = FLAG_DOUBLE | (FLAG_COMPRESSED if compress else 0)
    outer_metadata = {
        "author": "asim",
        "original_name": original_name,
        "original_size": original_size,
        "sha256": original_sha256,
        "layers": 2,
        "layer_type": "outer",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    outer_meta_json = json.dumps(outer_metadata).encode("utf-8")
    outer_meta_len_bytes = struct.pack(">I", len(outer_meta_json))
    outer_plaintext = outer_meta_len_bytes + outer_meta_json + inner_container

    salt2, nonce2, ciphertext2 = encrypt_data(outer_plaintext, outer_pwd)
    outer_header = struct.pack(HEADER_FORMAT, MAGIC, CURRENT_VERSION, outer_flags, salt2, nonce2)
    return outer_header + ciphertext2


def wrap_existing_ende_with_layer2(
    existing_ende_bytes: bytes,
    password2: str,
) -> bytes:
    """
    Wraps an existing .ende file with a second layer of encryption (double encryption).
    """
    header_info = inspect_header(existing_ende_bytes)
    if header_info["is_double"]:
        raise ContainerError("File is already double-encrypted.")

    outer_flags = FLAG_DOUBLE | (FLAG_COMPRESSED if header_info["is_compressed"] else 0)
    outer_metadata = {
        "author": "asim",
        "layers": 2,
        "layer_type": "outer_wrapper",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    outer_meta_json = json.dumps(outer_metadata).encode("utf-8")
    outer_meta_len_bytes = struct.pack(">I", len(outer_meta_json))
    outer_plaintext = outer_meta_len_bytes + outer_meta_json + existing_ende_bytes

    salt, nonce, ciphertext = encrypt_data(outer_plaintext, password2)
    outer_header = struct.pack(HEADER_FORMAT, MAGIC, CURRENT_VERSION, outer_flags, salt, nonce)
    return outer_header + ciphertext


def decrypt_container_layer(
    container_bytes: bytes,
    password: str,
) -> Tuple[Dict[str, Any], bytes]:
    """
    Decrypts a single layer of an ENDE container.
    Returns: (metadata_dict, payload_bytes)
    """
    header_info = inspect_header(container_bytes)
    salt = header_info["salt"]
    nonce = header_info["nonce"]
    ciphertext = container_bytes[HEADER_SIZE:]

    plaintext = decrypt_data(ciphertext, password, salt, nonce)

    if len(plaintext) < 4:
        raise ContainerError("Decrypted data is corrupt (missing metadata prefix).")

    (meta_len,) = struct.unpack_from(">I", plaintext, 0)
    if len(plaintext) < 4 + meta_len:
        raise ContainerError("Decrypted data is corrupt (truncated metadata).")

    meta_json = plaintext[4 : 4 + meta_len].decode("utf-8")
    metadata = json.loads(meta_json)
    payload = plaintext[4 + meta_len :]

    return metadata, payload


def decrypt_file_data(
    container_bytes: bytes,
    password: str,
    password2: Optional[str] = None,
    pwd_callback=None,
) -> Tuple[Dict[str, Any], bytes]:
    """
    Fully decrypts an ENDE container.
    Handles single-layer and double-layer files.
    If double-encrypted:
      - Uses outer password (password2 if provided, else password) for outer layer
      - Uses inner password (password if password2 was provided, else callback/password) for inner layer
    Returns: (final_metadata, restored_plaintext_data)
    """
    header_info = inspect_header(container_bytes)

    if not header_info["is_double"]:
        # Single layer
        metadata, payload = decrypt_container_layer(container_bytes, password)
        if metadata.get("compressed", False):
            payload = zlib.decompress(payload)

        # Verify integrity
        expected_sha = metadata.get("sha256")
        if expected_sha:
            actual_sha = calculate_sha256_bytes(payload)
            if actual_sha != expected_sha:
                raise IntegrityError(f"Integrity check failed! Expected SHA-256 {expected_sha}, got {actual_sha}.")

        return metadata, payload

    # Double Encrypted
    # Outer layer is encrypted with Layer 2 password (password2, or password if only 1 given)
    outer_pwd = password2 if password2 is not None else password
    try:
        outer_meta, inner_bytes = decrypt_container_layer(container_bytes, outer_pwd)
    except AuthenticationError:
        # If user passed password and password2 in swapped order, try password
        if password2 is not None and outer_pwd != password:
            outer_meta, inner_bytes = decrypt_container_layer(container_bytes, password)
            outer_pwd = password
        elif pwd_callback:
            outer_pwd = pwd_callback("Enter Layer 2 (Outer) password: ")
            outer_meta, inner_bytes = decrypt_container_layer(container_bytes, outer_pwd)
        else:
            raise

    # Step 2: Inner layer
    if password2 is not None and outer_pwd == password2:
        inner_pwd = password
    elif password2 is not None and outer_pwd == password:
        inner_pwd = password2
    else:
        # Only one password was passed, try it first
        try:
            inner_meta, payload = decrypt_container_layer(inner_bytes, password)
            inner_pwd = password
        except AuthenticationError:
            if pwd_callback:
                inner_pwd = pwd_callback("Enter Layer 1 (Inner) password: ")
                inner_meta, payload = decrypt_container_layer(inner_bytes, inner_pwd)
            else:
                raise

    if "inner_meta" not in locals():
        inner_meta, payload = decrypt_container_layer(inner_bytes, inner_pwd)

    if inner_meta.get("compressed", False):
        payload = zlib.decompress(payload)

    # Verify integrity
    expected_sha = inner_meta.get("sha256")
    if expected_sha:
        actual_sha = calculate_sha256_bytes(payload)
        if actual_sha != expected_sha:
            raise IntegrityError(f"Integrity check failed! Expected SHA-256 {expected_sha}, got {actual_sha}.")

    return inner_meta, payload

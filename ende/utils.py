"""
Utility functions for hashing, file formatting, secure wipe, and input.
Author: asim
"""

import getpass
import hashlib
import os
import secrets
from pathlib import Path

def calculate_sha256_bytes(data: bytes) -> str:
    """Computes SHA-256 hex digest of byte data."""
    return hashlib.sha256(data).hexdigest()

def calculate_sha256_file(file_path: Path) -> str:
    """Computes SHA-256 hex digest of a file in chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def format_size(size_bytes: int) -> str:
    """Converts bytes to human readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    for unit in ["KB", "MB", "GB", "TB"]:
        size_bytes /= 1024.0
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
    return f"{size_bytes:.2f} PB"

def prompt_password(prompt_text: str = "Enter password: ", confirm: bool = False) -> str:
    """Prompts the user for a password securely."""
    pwd = getpass.getpass(prompt_text)
    if not pwd:
        raise ValueError("Password cannot be empty.")
    if confirm:
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            raise ValueError("Passwords do not match!")
    return pwd

def secure_shred(file_path: Path, passes: int = 3) -> None:
    """
    Securely wipes a file by overwriting it multiple times before deletion.
    Pass 1: random bytes
    Pass 2: 0xFF
    Pass 3: 0x00
    """
    if not file_path.exists():
        return
    
    file_size = file_path.stat().st_size
    with open(file_path, "ba+", buffering=0) as f:
        for p in range(passes):
            f.seek(0)
            if p == 0:
                remaining = file_size
                while remaining > 0:
                    chunk_size = min(remaining, 65536)
                    f.write(secrets.token_bytes(chunk_size))
                    remaining -= chunk_size
            elif p == 1:
                remaining = file_size
                pattern = b"\xff" * 65536
                while remaining > 0:
                    chunk_size = min(remaining, 65536)
                    f.write(pattern[:chunk_size])
                    remaining -= chunk_size
            else:
                remaining = file_size
                pattern = b"\x00" * 65536
                while remaining > 0:
                    chunk_size = min(remaining, 65536)
                    f.write(pattern[:chunk_size])
                    remaining -= chunk_size
            f.flush()
            os.fsync(f.fileno())
    
    file_path.unlink()

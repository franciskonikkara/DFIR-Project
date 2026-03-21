"""Cryptographic hashing utilities for evidence integrity verification."""

import hashlib
import os
from pathlib import Path
from typing import Dict, Optional


SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


def compute_hashes(file_path: str, algorithms: tuple = ("md5", "sha1", "sha256")) -> Dict[str, str]:
    """Compute multiple hashes for a file simultaneously (single read pass)."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    hashers = {alg: hashlib.new(alg) for alg in algorithms}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            for h in hashers.values():
                h.update(chunk)

    return {alg: h.hexdigest() for alg, h in hashers.items()}


def compute_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Compute a single hash for a file."""
    return compute_hashes(file_path, (algorithm,))[algorithm]


def verify_hash(file_path: str, expected: str, algorithm: str = "sha256") -> bool:
    """Verify a file's hash matches an expected value (constant-time compare)."""
    actual = compute_hash(file_path, algorithm)
    return actual.lower() == expected.lower()


def hash_string(data: str, algorithm: str = "sha256") -> str:
    """Hash an arbitrary string."""
    return hashlib.new(algorithm, data.encode()).hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Hash raw bytes."""
    return hashlib.new(algorithm, data).hexdigest()

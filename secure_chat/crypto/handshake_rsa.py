# secure_chat/crypto/handshake_rsa.py
"""
Phase 1 identity helpers: static RSA keypair for the server.

- Use this to generate and load the server's long-term identity keys.
- The handshake (X25519 ECDH + RSA signature verification) is implemented in
  `handshake_x25519.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


@dataclass
class ServerIdentityPaths:
    private_pem: Path
    public_pem: Path


def generate_server_identity(paths: ServerIdentityPaths, key_size: int = 3072) -> Tuple[Path, Path]:
    """
    Generate a static RSA identity for the server and write PEM files.
    Returns (private_path, public_path).
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    pub = priv.public_key()

    paths.private_pem.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    paths.public_pem.write_bytes(
        pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return paths.private_pem, paths.public_pem


def load_private_pem(path: str | Path) -> bytes:
    """Read and return the server private key PEM bytes."""
    return Path(path).read_bytes()


def load_public_pem(path: str | Path) -> bytes:
    """Read and return the server public key PEM bytes (for pinning on client)."""
    return Path(path).read_bytes()

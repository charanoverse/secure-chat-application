# secure_chat/crypto/handshake_x25519.py

from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
import os
import time
import hashlib

from cryptography.hazmat.primitives.asymmetric import x25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

from ..app_config import (
    HKDF_TOTAL_BYTES, AES_KEY_BYTES,
    HKDF_INFO_HANDSHAKE, PROTOCOL_VERSION,
)

@dataclass(frozen=True)
class HandshakeParams:
    client_peer_id: str
    server_peer_id: str

@dataclass(frozen=True)
class HandshakeResult:
    session_id: bytes          # 32-byte SHA256 transcript hash
    k_enc: bytes               # 32 bytes (AES-256-GCM key)
    k_auth: bytes              # 32 bytes (reserved)
    client_ephemeral_pub: bytes
    server_ephemeral_pub: bytes
    started_at: float          # unix ts

def _hkdf_derive(shared_secret: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_TOTAL_BYTES,
        salt=salt,
        info=HKDF_INFO_HANDSHAKE,
    )
    okm = hkdf.derive(shared_secret)
    return okm[:AES_KEY_BYTES], okm[AES_KEY_BYTES:]  # k_enc, k_auth

def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()

def _now_s() -> float:
    return time.time()

# ---------- Server side ----------

def server_begin(handshake_params: HandshakeParams, server_rsa_private_pem: bytes) -> tuple[dict, x25519.X25519PrivateKey]:
    """
    Server generates ephemeral key, signs transcript (authenticating itself).
    Returns (ServerHello payload dict, server ephemeral private key).
    """
    server_eph_priv = x25519.X25519PrivateKey.generate()
    server_eph_pub = server_eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Load RSA private key (server static identity)
    server_priv = serialization.load_pem_private_key(server_rsa_private_pem, password=None)
    assert isinstance(server_priv, rsa.RSAPrivateKey)

    ts = int(_now_s() * 1000)
    transcript = (
        b"SCv1" +
        server_eph_pub +
        handshake_params.server_peer_id.encode() +
        handshake_params.client_peer_id.encode() +
        ts.to_bytes(8, "big")
    )

    signature = server_priv.sign(
        transcript,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    server_hello = {
        "version": PROTOCOL_VERSION,
        "server_ephemeral_pub": server_eph_pub,
        "server_peer_id": handshake_params.server_peer_id,
        "ts_ms": ts,
        "signature": signature,
    }
    return server_hello, server_eph_priv

def server_finalize(client_hello: dict, server_eph_priv: x25519.X25519PrivateKey) -> HandshakeResult:
    """
    After receiving ClientHello, compute shared secret and derive keys.
    """
    client_eph_pub = x25519.X25519PublicKey.from_public_bytes(client_hello["client_ephemeral_pub"])
    shared = server_eph_priv.exchange(client_eph_pub)
    salt = _sha256(client_hello["client_ephemeral_pub"], server_eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ))
    k_enc, k_auth = _hkdf_derive(shared, salt)
    session_id = _sha256(b"SID", client_hello["client_ephemeral_pub"], server_eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ))
    return HandshakeResult(
        session_id=session_id,
        k_enc=k_enc,
        k_auth=k_auth,
        client_ephemeral_pub=client_hello["client_ephemeral_pub"],
        server_ephemeral_pub=server_eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ),
        started_at=_now_s(),
    )

# ---------- Client side ----------

def client_begin(client_peer_id: str) -> tuple[dict, x25519.X25519PrivateKey]:
    """
    Client creates ephemeral key, sends ClientHello.
    """
    client_eph_priv = x25519.X25519PrivateKey.generate()
    client_eph_pub = client_eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    ts = int(_now_s() * 1000)
    client_hello = {
        "version": PROTOCOL_VERSION,
        "client_ephemeral_pub": client_eph_pub,
        "client_peer_id": client_peer_id,
        "ts_ms": ts,
    }
    return client_hello, client_eph_priv

def client_finalize(
    server_hello: dict,
    client_eph_priv: x25519.X25519PrivateKey,
    pinned_server_rsa_pubkey_pem: bytes,
    handshake_params: HandshakeParams,
) -> HandshakeResult:
    """
    Verify server signature with *pinned* RSA pubkey. Derive keys.
    """
    # Load pinned server public key
    server_pub = serialization.load_pem_public_key(pinned_server_rsa_pubkey_pem)
    assert isinstance(server_pub, rsa.RSAPublicKey)

    server_eph_pub = server_hello["server_ephemeral_pub"]
    ts = server_hello["ts_ms"]

    transcript = (
        b"SCv1" +
        server_eph_pub +
        handshake_params.server_peer_id.encode() +
        handshake_params.client_peer_id.encode() +
        ts.to_bytes(8, "big")
    )

    try:
        server_pub.verify(
            server_hello["signature"],
            transcript,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as e:
        raise ValueError("Server identity verification failed (bad signature).") from e

    # Key agreement
    srv_pub = x25519.X25519PublicKey.from_public_bytes(server_eph_pub)
    shared = client_eph_priv.exchange(srv_pub)

    client_eph_pub = client_eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    salt = _sha256(client_eph_pub, server_eph_pub)
    k_enc, k_auth = _hkdf_derive(shared, salt)
    session_id = _sha256(b"SID", client_eph_pub, server_eph_pub)

    return HandshakeResult(
        session_id=session_id,
        k_enc=k_enc,
        k_auth=k_auth,
        client_ephemeral_pub=client_eph_pub,
        server_ephemeral_pub=server_eph_pub,
        started_at=_now_s(),
    )

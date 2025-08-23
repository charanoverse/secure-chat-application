# import socket
# import struct

# # Length-prefixed frames (4-byte big-endian unsigned int)

# def send_frame(sock: socket.socket, payload: bytes) -> None:
#     header = struct.pack(">I", len(payload))
#     sock.sendall(header + payload)

# def recv_exact(sock: socket.socket, n: int) -> bytes:
#     buf = bytearray()
#     while len(buf) < n:
#         chunk = sock.recv(n - len(buf))
#         if not chunk:
#             raise ConnectionError("Socket closed during recv")
#         buf.extend(chunk)
#     return bytes(buf)

# def recv_frame(sock: socket.socket) -> bytes:
#     header = recv_exact(sock, 4)
#     (length,) = struct.unpack(">I", header)
#     if length > 32 * 1024 * 1024:  # 32 MB sanity cap
#         raise ValueError("Frame too large")
#     return recv_exact(sock, length)

# secure_chat/net/framing.py
from __future__ import annotations

import socket
import struct
import time
from typing import Tuple

from ..crypto import aead

# Frame format (all big-endian):
#   4B   total_length (excludes this prefix)
#   8B   seq
#   8B   timestamp_ms
#   12B  nonce
#   4B   ciphertext length (L)
#   L    ciphertext_with_tag
#
# => recv_frame_decoded() returns (seq, ts_ms, plaintext)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send a raw payload with a 4-byte length prefix."""
    header = struct.pack(">I", len(payload))
    sock.sendall(header + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed during recv")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    """Receive a raw frame (without interpreting)."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > 32 * 1024 * 1024:  # 32 MB sanity cap
        raise ValueError("Frame too large")
    return recv_exact(sock, length)


# ---------- Encrypted Framing (Protocol v1) ----------

def send_frame_enc(
    sock: socket.socket,
    sess: aead.AEADSession,
    seq: int,
    peer_id: str,
    plaintext: bytes,
    timestamp_ms: int | None = None,
) -> None:
    """
    Encrypt and send a framed message.
    """
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    nonce, ct = sess.encrypt(seq, timestamp_ms, peer_id, plaintext)

    # Build frame body
    body = (
        struct.pack(">Q", seq) +
        struct.pack(">Q", timestamp_ms) +
        nonce +
        struct.pack(">I", len(ct)) +
        ct
    )
    send_frame(sock, body)


def recv_frame_decoded(
    sock: socket.socket,
    sess: aead.AEADSession,
    peer_id: str,
) -> Tuple[int, int, bytes]:
    """
    Receive, decrypt, and return (seq, timestamp_ms, plaintext).
    """
    body = recv_frame(sock)
    if len(body) < 8 + 8 + 12 + 4:
        raise ValueError("Frame too short")

    seq = int.from_bytes(body[0:8], "big")
    ts_ms = int.from_bytes(body[8:16], "big")
    nonce = body[16:28]
    ct_len = int.from_bytes(body[28:32], "big")
    if len(body) != 32 + ct_len:
        raise ValueError("Frame length mismatch")
    ct = body[32:]

    pt = sess.decrypt(seq, ts_ms, peer_id, nonce, ct)
    return seq, ts_ms, pt

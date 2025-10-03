# secure_chat/services/chat_service.py
from __future__ import annotations

import json
import socket
import sys
import base64
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple
from secure_chat.storage.history import store_message
from rich import print

from ..net.framing import send_frame, recv_frame  # raw len-prefixed I/O
from ..crypto.aead import encrypt_aead_v1, decrypt_aead_v1, NONCE_SIZE
from ..crypto.handshake_x25519 import (
    HandshakeParams,
    client_begin,
    client_finalize,
    server_begin,
    server_finalize,
    HandshakeResult,
)
from ..storage.logs import append_encrypted_line, read_last_n_decrypted
from ..app_config import (
    PROTOCOL_VERSION,
    REKEY_EVERY_N_MESSAGES,
    REKEY_EVERY_T_SECONDS,
    HKDF_INFO_REKEY,
    HKDF_TOTAL_BYTES,
    AES_KEY_BYTES,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def _now_ms() -> int:
    return int(time.time() * 1000)


def _hkdf_rekey(k_enc: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_TOTAL_BYTES,
        salt=salt,
        info=HKDF_INFO_REKEY,
    )
    okm = hkdf.derive(k_enc)
    return okm[:AES_KEY_BYTES], okm[AES_KEY_BYTES:]


@dataclass
class SessionState:
    session_id: bytes
    k_enc: bytes
    k_auth: bytes
    # no AEADSession field; we use encrypt_aead_v1/decrypt_aead_v1 directly
    send_seq: int = 1
    recv_highest_seq: int = 0
    last_rekey_at_s: float = field(default_factory=lambda: time.time())
    msgs_since_rekey: int = 0

    def maybe_rekey(self, last_nonce: bytes) -> None:
        now_s = time.time()
        if self.msgs_since_rekey >= REKEY_EVERY_N_MESSAGES or (now_s - self.last_rekey_at_s) >= REKEY_EVERY_T_SECONDS:
            salt = last_nonce + (self.send_seq).to_bytes(8, "big")
            self.k_enc, self.k_auth = _hkdf_rekey(self.k_enc, salt)
            # self.aead = AEADSession.new(self.k_enc)  # ← delete this
            self.last_rekey_at_s = now_s
            self.msgs_since_rekey = 0


@dataclass
class ConnectionState:
    sock: socket.socket
    history_file: str
    local_peer_id: str
    remote_peer_id: str
    session: SessionState


# ------------ Handshake helpers ------------

def _server_handshake(conn: socket.socket, server_peer_id: str, server_priv_pem_path: Path) -> Tuple[ConnectionState, dict]:
    """
    Server receives ClientHello (JSON), sends ServerHello (JSON), derives session keys.
    Returns: (ConnectionState, client_hello)
    """
    # receive ClientHello
    raw = recv_frame(conn)
    try:
        client_hello = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid client hello JSON: {e}") from e

    # 🔧 decode pubkey back into bytes
    if isinstance(client_hello.get("client_ephemeral_pub"), str):
        client_hello["client_ephemeral_pub"] = base64.b64decode(client_hello["client_ephemeral_pub"])

    params = HandshakeParams(
        client_peer_id=client_hello["client_peer_id"],
        server_peer_id=server_peer_id,
    )

    server_priv_pem = server_priv_pem_path.read_bytes()
    server_hello, eph_priv = server_begin(params, server_priv_pem)

    # Encode binary fields for JSON
    server_hello["server_ephemeral_pub"] = base64.b64encode(server_hello["server_ephemeral_pub"]).decode("ascii")
    server_hello["signature"] = base64.b64encode(server_hello["signature"]).decode("ascii")

    # Send ServerHello to client
    send_frame(conn, json.dumps(server_hello).encode("utf-8"))

    # Finalize keys (compute shared secret and derive keys)
    result: HandshakeResult = server_finalize(client_hello, eph_priv)
    session = SessionState(
        session_id=result.session_id,
        k_enc=result.k_enc,
        k_auth=result.k_auth,

    )

    state = ConnectionState(
        sock=conn,
        history_file="",
        local_peer_id=server_peer_id,
        remote_peer_id=client_hello["client_peer_id"],
        session=session,
    )

    return state, client_hello


def _client_handshake(sock: socket.socket, client_peer_id: str, server_peer_id: str, pinned_server_pubkey_path: Path) -> ConnectionState:
    """
    Client sends ClientHello, receives ServerHello, verifies signature with pinned RSA pubkey,
    derives session keys and returns initialized ConnectionState.
    """
    client_hello, eph_priv = client_begin(client_peer_id)
    if isinstance(client_hello.get("client_ephemeral_pub"), (bytes, bytearray)):
        client_hello["client_ephemeral_pub"] = base64.b64encode(
            client_hello["client_ephemeral_pub"]
        ).decode("utf-8")

    send_frame(sock, json.dumps(client_hello).encode("utf-8"))

    raw = recv_frame(sock)
    try:
        server_hello = json.loads(raw.decode("utf-8"))
        server_hello["server_ephemeral_pub"] = base64.b64decode(server_hello["server_ephemeral_pub"])
        server_hello["signature"] = base64.b64decode(server_hello["signature"])

    except Exception as e:
        raise ValueError(f"Invalid server hello JSON: {e}") from e

    pinned_pem = pinned_server_pubkey_path.read_bytes()

    result: HandshakeResult = client_finalize(
        server_hello=server_hello,
        client_eph_priv=eph_priv,
        pinned_server_rsa_pubkey_pem=pinned_pem,
        handshake_params=HandshakeParams(client_peer_id=client_peer_id, server_peer_id=server_peer_id),
    )

    session = SessionState(
        session_id=result.session_id,
        k_enc=result.k_enc,
        k_auth=result.k_auth,
    )

    state = ConnectionState(
        sock=sock,
        history_file="",
        local_peer_id=client_peer_id,
        remote_peer_id=server_peer_id,
        session=session,
    )

    return state


# ------------ Secure send/recv (with access to nonce for rekey salt) ------------

def _send_secure(state: ConnectionState, plaintext: bytes) -> None:
    """
    Encrypt using AES-GCM (Protocol v1) and write frame:
      [seq:8][ts:8][nonce:12][ct_len:4][ct...]
    Note: ts is in seconds (not ms) to match aead.py.
    Additionally, store the message locally in encrypted searchable history.
    """
    from secure_chat.storage.history import store_message  # import locally to avoid circular deps
    import time

    s = state.session
    ts_s = int(time.time())

    # 1️⃣ Encrypt using existing AES-GCM logic
    # encrypt_aead_v1(key, plaintext, seq, ts, peer_id)
    blob = encrypt_aead_v1(
        s.k_enc,
        plaintext,
        s.send_seq,
        ts_s,
        state.local_peer_id.encode("utf-8"),
    )
    # blob = nonce(12) || ct
    nonce = blob[:NONCE_SIZE]
    ct = blob[NONCE_SIZE:]

    # 2️⃣ Frame for network
    frame = (
        s.send_seq.to_bytes(8, "big")
        + ts_s.to_bytes(8, "big")
        + nonce
        + len(ct).to_bytes(4, "big")
        + ct
    )

    send_frame(state.sock, frame)

    # 3️⃣ Bookkeeping for rekey
    s.msgs_since_rekey += 1
    s.maybe_rekey(nonce)
    s.send_seq += 1

    # 4️⃣ Store locally for searchable encrypted history
    try:
        # plaintext here is bytes; decode to string for indexing
        store_message(state.local_peer_id, plaintext.decode("utf-8"))
    except Exception as e:
        # avoid breaking sending if DB fails
        print(f"[Warning] Failed to store message in history: {e}")



def _recv_secure(state: ConnectionState) -> Optional[bytes]:
    try:
        body = recv_frame(state.sock)
    except (ConnectionError, OSError, ValueError):
        return None

    # seq(8) + ts(8) + nonce(12) + ct_len(4) = 32 bytes min
    if len(body) < 32:
        return None

    seq = int.from_bytes(body[0:8], "big")
    ts_s = int.from_bytes(body[8:16], "big")
    nonce = body[16:28]
    ct_len = int.from_bytes(body[28:32], "big")
    if len(body) != 32 + ct_len:
        return None
    ct = body[32:]

    s = state.session

    # Anti-replay / ordering
    if seq <= s.recv_highest_seq:
        return b"[replay-or-out-of-order]"

    try:
        blob = nonce + ct
        pt = decrypt_aead_v1(
            s.k_enc,
            blob,
            seq,
            ts_s,
            state.remote_peer_id.encode("utf-8"),
        )
    except Exception:
        return b"[decryption error]"

    s.recv_highest_seq = seq
    return pt



# ---------------- Public API: Server ----------------

def run_server(
    bind_host: str,
    port: int,
    history_file: str,
    server_peer_id: str,
    server_private_pem: str | Path,
) -> None:
    print(f"[bold green]Server[/bold green] listening on {bind_host}:{port}")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, port))
    srv.listen(1)

    conn, addr = srv.accept()
    print(f"[server] Connection from {addr}")

    # --- Phase 1 handshake ---
    state, client_hello = _server_handshake(conn, server_peer_id, Path(server_private_pem))
    state.history_file = history_file
    print("[green]Handshake complete[/green]")

    # Optional: show last 10 messages (if implemented)
    try:
        msgs = read_last_n_decrypted(history_file, state.session.k_enc, 10)
        if msgs:
            print("\n[bold]Last 10 messages:[/bold]")
            for m in msgs:
                print(m)
    except Exception:
        # If log helper has different signature or fails, ignore silently
        pass

    # Start threads
    threading.Thread(target=_recv_loop, args=(state,), daemon=True).start()
    _send_loop(state, label="You")

    print("[yellow]Server exiting...[/yellow]")
    try:
        conn.close()
    except Exception:
        pass
    srv.close()


# ---------------- Public API: Client ----------------

def run_client(
    host: str,
    port: int,
    history_file: str,
    client_peer_id: str,
    server_peer_id: str,
    pinned_server_pubkey_pem: str | Path,
) -> None:
    print(f"[bold blue]Client[/bold blue] connecting to {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # --- Phase 1 handshake ---
    state = _client_handshake(sock, client_peer_id, server_peer_id, Path(pinned_server_pubkey_pem))
    state.history_file = history_file
    print("[blue]Handshake complete[/blue]")

    # Optional: show last 10 messages
    try:
        msgs = read_last_n_decrypted(history_file, state.session.k_enc, 10)
        if msgs:
            print("\n[bold]Last 10 messages:[/bold]")
            for m in msgs:
                print(m)
    except Exception:
        pass

    print("\nConnected. Type 'exit' to quit.")
    threading.Thread(target=_recv_loop, args=(state,), daemon=True).start()
    _send_loop(state, label="You")

    print("[yellow]Client exiting...[/yellow]")
    try:
        sock.close()
    except Exception:
        pass


# ---------------- Loops ----------------

def _recv_loop(state: ConnectionState) -> None:
    while True:
        pt = _recv_secure(state)
        if pt is None:
            print("\n[red][Disconnected][/red]")
            break

        msg = pt.decode("utf-8", errors="replace")
        sys.stdout.write(f"\rPeer: {msg}\nYou: ")
        sys.stdout.flush()

        if msg.strip():
            # Append to history using existing log helper signature (path, key, sender, message)
            try:
                append_encrypted_line(state.history_file, state.session.k_enc, "Peer", msg)
            except Exception:
                # don't fail the loop on logging errors
                pass

        if msg.strip().lower() == "exit":
            print("[red][Peer exited][/red]")
            break


def _send_loop(state: ConnectionState, label: str) -> None:
    try:
        while True:
            msg = input("You: ")
            _send_secure(state, msg.encode("utf-8"))
            try:
                append_encrypted_line(state.history_file, state.session.k_enc, label, msg)
            except Exception:
                # ignore logging errors
                pass
            if msg.lower() == "exit":
                print("[yellow][You exited][/yellow]")
                break
    except (EOFError, KeyboardInterrupt):
        try:
            _send_secure(state, b"exit")
        except Exception:
            pass

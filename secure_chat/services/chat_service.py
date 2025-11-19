# secure_chat/services/chat_service.py
from __future__ import annotations

import json
import socket
import sys
import base64
import threading
import time
import asyncio
import websockets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

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
from ..storage.app_config import (
    PROTOCOL_VERSION,
    REKEY_EVERY_N_MESSAGES,
    REKEY_EVERY_T_SECONDS,
    HKDF_INFO_REKEY,
    HKDF_TOTAL_BYTES,
    AES_KEY_BYTES,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Phase 3 imports
from secure_chat.services.epherimal_privacy import DeletionScheduler, secure_delete
import secure_chat.storage.history as history_storage


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
    send_seq: int = 1
    recv_highest_seq: int = 0
    last_rekey_at_s: float = field(default_factory=lambda: time.time())
    msgs_since_rekey: int = 0

    def maybe_rekey(self, last_nonce: bytes) -> None:
        now_s = time.time()
        if self.msgs_since_rekey >= REKEY_EVERY_N_MESSAGES or (now_s - self.last_rekey_at_s) >= REKEY_EVERY_T_SECONDS:
            salt = last_nonce + (self.send_seq).to_bytes(8, "big")
            self.k_enc, self.k_auth = _hkdf_rekey(self.k_enc, salt)
            self.last_rekey_at_s = now_s
            self.msgs_since_rekey = 0


@dataclass
class ConnectionState:
    sock: socket.socket
    history_file: str
    local_peer_id: str
    remote_peer_id: str
    session: SessionState
    scheduler: Optional[DeletionScheduler] = None


# ------------ Handshake helpers ------------

def _server_handshake(conn: socket.socket, server_peer_id: str, server_priv_pem_path: Path) -> Tuple[ConnectionState, dict]:
    """
    Server receives ClientHello (JSON), sends ServerHello (JSON), derives session keys.
    Returns: (ConnectionState, client_hello)
    """
    raw = recv_frame(conn)
    try:
        client_hello = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid client hello JSON: {e}") from e

    if isinstance(client_hello.get("client_ephemeral_pub"), str):
        client_hello["client_ephemeral_pub"] = base64.b64decode(client_hello["client_ephemeral_pub"])

    params = HandshakeParams(
        client_peer_id=client_hello["client_peer_id"],
        server_peer_id=server_peer_id,
    )

    server_priv_pem = server_priv_pem_path.read_bytes()
    server_hello, eph_priv = server_begin(params, server_priv_pem)

    server_hello["server_ephemeral_pub"] = base64.b64encode(server_hello["server_ephemeral_pub"]).decode("ascii")
    server_hello["signature"] = base64.b64encode(server_hello["signature"]).decode("ascii")

    send_frame(conn, json.dumps(server_hello).encode("utf-8"))

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
    Additionally, store the message locally in encrypted searchable history (with optional TTL).
    TTL UI: prefix message with '/ttl <seconds> ' (example: '/ttl 10 secret').
    """
    s = state.session
    ts_s = int(time.time())

    # 1️⃣ Encrypt using existing AES-GCM logic
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

    # 4️⃣ Store locally for searchable encrypted history (with optional TTL)
    try:
        msg_text = plaintext.decode("utf-8")
    except Exception:
        msg_text = ""

    ttl_seconds = None
    # simple TTL prefix parsing: "/ttl 10 message..."
    if msg_text.startswith("/ttl "):
        parts = msg_text.split(" ", 2)
        if len(parts) >= 3:
            try:
                ttl_seconds = int(parts[1])
                msg_text = parts[2]
            except Exception:
                ttl_seconds = None

    seq_for_storage = s.send_seq  # note: we incremented send_seq earlier; that's fine for storage seq
    ts_for_storage = ts_s

    try:
        message_id, expire_at = history_storage.store_message(
            sender_id=state.local_peer_id,
            encrypted_blob=ct,
            nonce=nonce,
            plaintext_for_index=msg_text,
            seq=seq_for_storage,
            ts=ts_for_storage,
            ttl_seconds=ttl_seconds,
            db_path=history_storage.DB_PATH,
        )
        # schedule deletion if TTL set and scheduler present
        if ttl_seconds and expire_at and state.scheduler:
            try:
                state.scheduler.schedule(message_id, expire_at)
            except Exception as e:
                print(f"[Warning] Failed to schedule deletion for message {message_id}: {e}")
    except Exception as e:
        print(f"[Warning] Failed to store message in history: {e}")


def _recv_secure(state: ConnectionState) -> Optional[tuple]:
    """
    Returns tuple (plaintext: bytes, nonce: bytes, ct: bytes, seq: int, ts_s: int)
    or None if disconnected / invalid.
    """
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
        return (b"[replay-or-out-of-order]", None, None, seq, ts_s)

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
        return (b"[decryption error]", None, None, seq, ts_s)

    s.recv_highest_seq = seq
    return (pt, nonce, ct, seq, ts_s)


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

    # Ensure history DB exists and start scheduler
    try:
        history_storage.init_db(history_file or history_storage.DB_PATH)
    except Exception:
        history_storage.init_db()

    # Use the same DB path that was initialized above (history_file if provided)
    scheduler_db_path = history_file or history_storage.DB_PATH
    scheduler = DeletionScheduler(db_path=scheduler_db_path)
    scheduler.start()
    state.scheduler = scheduler

    # Optional: show last 10 messages (if implemented)
    try:
        msgs = read_last_n_decrypted(history_file, state.session.k_enc, 10)
        if msgs:
            print("\n[bold]Last 10 messages:[/bold]")
            for m in msgs:
                print(m)
    except Exception:
        pass

    # Start threads
    threading.Thread(target=_recv_loop, args=(state,), daemon=True).start()
    _send_loop(state, label="You")

    print("[yellow]Server exiting...[/yellow]")
    try:
        state.sock.close()
    except Exception:
        pass
    srv.close()

    # stop scheduler
    try:
        scheduler.stop()
    except Exception:
        pass


# ---------------- Public API: Client ----------------

def run_client(
    host: str,
    port: int,
    history_file: str,
    client_peer_id: str,
    server_peer_id: str,
    pinned_server_pubkey_pem: str | Path,
    relay_url: str | None = None,   # 🆕 added
) -> None:
    print(f"[bold blue]Client[/bold blue] connecting to {host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        using_relay = False
    except Exception as e:
        print(f"[red]Direct TCP connection failed: {e}[/red]")
        if relay_url:
            using_relay = True
        else:
            print("[red]No relay URL provided. Exiting.[/red]")
            return
    if using_relay:
        asyncio.run(_relay_client_loop(relay_url, client_peer_id))
        return

    # --- Phase 1 handshake ---
    state = _client_handshake(sock, client_peer_id, server_peer_id, Path(pinned_server_pubkey_pem))
    state.history_file = history_file
    print("[blue]Handshake complete[/blue]")

    # Ensure history DB exists and start scheduler
    try:
        history_storage.init_db(history_file or history_storage.DB_PATH)
    except Exception:
        history_storage.init_db()

    # Use the same DB path that was initialized above (history_file if provided)
    scheduler_db_path = history_file or history_storage.DB_PATH
    scheduler = DeletionScheduler(db_path=scheduler_db_path)
    scheduler.start()
    state.scheduler = scheduler

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

    # stop scheduler
    try:
        scheduler.stop()
    except Exception:
        pass


# ---------------- Loops ----------------

def _recv_loop(state: ConnectionState) -> None:
    while True:
        res = _recv_secure(state)
        if res is None:
            print("\n[red][Disconnected][/red]")
            break
        pt, nonce, ct, seq, ts_s = res
        if pt is None:
            print("\n[red][Disconnected][/red]")
            break

        msg = pt.decode("utf-8", errors="replace")
        sys.stdout.write(f"\rPeer: {msg}\nYou: ")
        sys.stdout.flush()

        # store incoming message in DB for search/history
        try:
            # detect TTL prefix in received plaintext (sender may have used /ttl N msg)
            ttl_seconds = None
            msg_text_for_index = msg
            if msg_text_for_index.startswith("/ttl "):
                parts = msg_text_for_index.split(" ", 2)
                if len(parts) >= 3:
                    try:
                        ttl_seconds = int(parts[1])
                        msg_text_for_index = parts[2]  # store indexable plaintext without prefix
                    except Exception:
                        ttl_seconds = None

            # store and capture message_id (so we can schedule deletion)
            message_id, expire_at = history_storage.store_message(
                sender_id=state.remote_peer_id,
                encrypted_blob=ct,
                nonce=nonce,
                plaintext_for_index=msg_text_for_index,
                seq=seq,
                ts=ts_s,
                ttl_seconds=ttl_seconds,
                db_path=history_storage.DB_PATH,
            )

            # If TTL present and scheduler attached, schedule deletion locally
            if ttl_seconds and hasattr(state, "scheduler") and state.scheduler and message_id:
                try:
                    state.scheduler.schedule(message_id, expire_at)
                except Exception as e:
                    print(f"[Warning] Failed to schedule deletion for incoming message {message_id}: {e}")
        except Exception:
            pass


def _send_loop(state: ConnectionState, label: str) -> None:
    try:
        while True:
            msg = input("You: ")
            if not msg:
                continue

            # Stop sending if user typed exit
            if msg.lower() == "exit":
                try:
                    if state.sock:  # check if socket still exists
                        _send_secure(state, b"exit")
                except (ConnectionResetError, OSError):
                    pass  # ignore if peer already disconnected
                print("[yellow][You exited][/yellow]")
                break

            # Normal send
            try:
                _send_secure(state, msg.encode("utf-8"))
            except (ConnectionResetError, OSError):
                print("[yellow][Peer disconnected. Cannot send message][/yellow]")
                break
            except Exception as e:
                print(f"[Warning] Failed to send message: {e}")

            # Append locally (best-effort)
            try:
                append_encrypted_line(state.history_file, state.session.k_enc, label, msg)
            except Exception:
                pass

    except (EOFError, KeyboardInterrupt):
        try:
            if state.sock:
                _send_secure(state, b"exit")
        except Exception:
            pass
        print("\n[yellow][You exited via Ctrl+C][/yellow]")


# ---------------- Relay WebSocket mode (Phase 4) ----------------

async def _relay_client_loop(relay_url: str, peer_id: str) -> None:
    """
    Connects to a relay server via WebSocket and relays encrypted frames.
    The relay only forwards encrypted messages.
    """
    print(f"[blue]Connecting to relay: {relay_url}[/blue]")
    async with websockets.connect(relay_url) as ws:
        print("[green]Connected to relay. Type messages to send.[/green]")
        # Reader task
        async def recv_task():
            async for raw in ws:
                try:
                    data = json.loads(raw)
                    frame_b64 = data.get("frame_bytes")
                    if frame_b64:
                        print(f"\nPeer (relay): {frame_b64[:40]}...")  # ciphertext preview
                except Exception:
                    pass

        # Writer task
        async def send_task():
            while True:
                msg = input("You (relay): ")
                if msg.lower() == "exit":
                    break
                payload = {
                    "from_id": peer_id,
                    "frame_bytes": base64.b64encode(msg.encode()).decode()
                }
                await ws.send(json.dumps(payload))

        await asyncio.gather(recv_task(), send_task())

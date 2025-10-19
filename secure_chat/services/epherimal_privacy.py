# secure_chat/services/epherimal_privacy.py
"""
Ephemeral & privacy helpers for Phase 3.

Features:
- Peer ID generation (base58 short IDs)
- Invite payload + QR generation (optional qrcode)
- send_message_with_ttl(): helper to encrypt+send and store message with TTL
- DeletionScheduler: in-process scheduler that loads pending expirations and calls secure_delete()
- secure_delete(): best-effort overwrite + delete + VACUUM (delegates to history helpers)
"""
import os
import time
import hashlib
import threading
from typing import Optional, Tuple, List

# optional dependency for QR invites
try:
    import qrcode
except Exception:
    qrcode = None

# local imports for AEAD + DB helpers
from ..crypto.aead import encrypt_aead_v1, NONCE_SIZE
import secure_chat.storage.history as history_storage

# base58 alphabet for peer id generation (Bitcoin-style)
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


# -----------------------------
# Peer ID generation (base58)
# -----------------------------
def _int_to_base58(n: int) -> str:
    if n == 0:
        return BASE58_ALPHABET[0]
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(BASE58_ALPHABET[r])
    return ''.join(reversed(out))


def generate_peer_id(seed: Optional[bytes] = None, length: int = 8) -> str:
    """
    Generate compact human-friendly peer id (base58).
    - seed: optional bytes; otherwise uses os.urandom
    - length: requested string length (truncated/padded deterministically)
    """
    if seed is None:
        seed = os.urandom(16)
    digest = hashlib.sha256(seed + os.urandom(8)).digest()
    num = int.from_bytes(digest, 'big')
    b58 = _int_to_base58(num)
    if len(b58) >= length:
        return b58[:length]
    pad = _int_to_base58(int.from_bytes(hashlib.sha1(digest).digest(), 'big'))
    return (b58 + pad)[:length]


# -----------------------------
# Invite payload / QR helpers
# -----------------------------
def make_invite_payload(relay_host: str, room_id: str, peer_id: str, access_token: Optional[str] = None) -> str:
    payload = f"relay://{relay_host}/room/{room_id}?p={peer_id}"
    if access_token:
        payload += f"&t={access_token}"
    return payload


def generate_invite_qr(path_out: str, relay_host: str, room_id: str, peer_id: str, access_token: Optional[str] = None) -> str:
    if qrcode is None:
        raise RuntimeError("qrcode not installed. `pip install qrcode[pil]` to enable invite QR generation.")
    payload = make_invite_payload(relay_host, room_id, peer_id, access_token)
    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image()
    img.save(path_out)
    return path_out


# -----------------------------
# Secure delete helpers
# -----------------------------
def secure_delete(message_id: int, db_path: Optional[str] = None) -> None:
    """
    Best-effort secure delete for an entry identified by message_id.
    Delegates to history_storage.fetch_message_row and overwrite_and_delete_row_by_pk.
    """
    db_path = db_path or history_storage.DB_PATH
    try:
        row = history_storage.fetch_message_row(message_id, db_path)
        if not row:
            return
        pk_value, nlen, blen = row
        # call history helper to overwrite & delete by pk value
        history_storage.overwrite_and_delete_row_by_pk(pk_value, db_path)
    except Exception as e:
        # best-effort; don't raise to avoid crashing scheduler
        print(f"[Warning] secure_delete failed for {message_id}: {e}")


# -----------------------------
# Deletion scheduler
# -----------------------------
class DeletionScheduler:
    """
    Simple thread-based scheduler:
    - loads pending expirations from history_storage on start
    - schedule(message_id, expire_at) to add new events
    - background thread deletes when expire_at passes
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or history_storage.DB_PATH
        self._lock = threading.Lock()
        self._events: List[Tuple[int, int]] = []  # (expire_at, message_id)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._load_pending()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _load_pending(self) -> None:
        try:
            rows = history_storage.load_pending_expirations(db_path=self.db_path)
            # rows: list[(expire_at, message_id)]
            with self._lock:
                self._events.extend(rows)
                self._events.sort()
        except Exception as e:
            print(f"[Warning] Failed to load pending expirations: {e}")

    def schedule(self, message_id: int, expire_at: int) -> None:
        with self._lock:
            self._events.append((expire_at, message_id))
            self._events.sort()

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            now = int(time.time())
            next_event: Optional[Tuple[int, int]] = None
            with self._lock:
                if self._events:
                    next_event = self._events[0]

            if not next_event:
                self._stop.wait(timeout=5)
                continue

            expire_at, message_id = next_event
            if expire_at <= now:
                with self._lock:
                    if self._events and self._events[0] == (expire_at, message_id):
                        self._events.pop(0)
                try:
                    secure_delete(message_id, self.db_path)
                except Exception as e:
                    print(f"[Warning] secure_delete error: {e}")
                continue

            wait_seconds = max(expire_at - now, 0)
            if wait_seconds > 3600:
                wait_seconds = 3600
            self._stop.wait(timeout=wait_seconds)


# -----------------------------
# TTL send helper (high-level)
# -----------------------------
def send_message_with_ttl(
    send_func,
    plaintext: bytes,
    sender: str,
    receiver: str,
    ttl_seconds: Optional[int] = None,
    db_path: Optional[str] = None,
    scheduler: Optional[DeletionScheduler] = None,
    seq: Optional[int] = None,
) -> int:
    """
    High-level helper:
    - Encrypts plaintext using encrypt_aead_v1 (expects AEAD signature used in chat_service)
    - Stores encrypted blob (nonce + ciphertext) into history DB via history_storage.store_message
    - If ttl_seconds provided, schedules secure deletion via scheduler
    """
    db_path = db_path or history_storage.DB_PATH
    if seq is None:
        seq = int(time.time() * 1000)

    ts = int(time.time())

    # encrypt using project's AEAD helper. returns nonce||ct
    blob = encrypt_aead_v1(sender.encode() if isinstance(sender, str) else sender, plaintext, seq, ts, sender.encode())
    nonce = blob[:NONCE_SIZE]
    ct = blob[NONCE_SIZE:]

    frame = nonce + ct
    send_func(receiver, frame)

    try:
        message_id, expire_at = history_storage.store_message(
            sender_id=sender,
            encrypted_blob=ct,
            nonce=nonce,
            plaintext_for_index=(plaintext.decode("utf-8") if isinstance(plaintext, (bytes, bytearray)) else str(plaintext)),
            seq=seq,
            ts=ts,
            ttl_seconds=ttl_seconds,
            db_path=db_path,
        )
        if ttl_seconds and expire_at and scheduler:
            scheduler.schedule(message_id, expire_at)
        return message_id
    except Exception as e:
        print(f"[Warning] Failed to persist message for TTL tracking: {e}")
        raise


# -----------------------------
# Demo harness (optional)
# -----------------------------
if __name__ == "__main__":
    print("Ephemeral privacy helpers demo")
    try:
        history_storage.init_db()
    except Exception:
        pass

    peer = generate_peer_id()
    print("peer id:", peer)

    sched = DeletionScheduler()
    sched.start()

    def send_print(to, frame: bytes):
        print(f"[demo send] to={to} bytes={len(frame)}")

    mid = send_message_with_ttl(send_print, b"Hello ephemeral world", sender="me", receiver="you", ttl_seconds=10, scheduler=sched)
    print("message_id:", mid)
    print("sleeping 12s to let scheduler delete")
    time.sleep(12)
    sched.stop()
    print("done demo")
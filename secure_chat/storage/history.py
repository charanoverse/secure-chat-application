# secure_chat/storage/history.py
import sqlite3
import hmac
import hashlib
import time
import os
import threading
from typing import List, Optional, Tuple
from pathlib import Path

from secure_chat.crypto.aead import NONCE_SIZE

# ---------------- DB CONFIG ----------------
DB_PATH = os.path.join(os.getcwd(), "secure_chat_history.db")
K_IDX = b"some-32-byte-secret-key"  # HMAC key for token index

# Lock for thread-safe DB operations
DB_LOCK = threading.Lock()


# ---------------- UTILITIES ----------------
def _current_ts() -> int:
    return int(time.time())


def compute_index_key(token: str) -> str:
    """HMAC token → deterministic key for index lookup."""
    return hmac.new(K_IDX, token.encode(), hashlib.sha256).hexdigest()


def get_conn(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Return a thread-safe connection to DB with WAL mode."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _detect_pk_col(conn: sqlite3.Connection) -> str:
    """
    Detect primary key column name for messages table.
    Prefers column with pk==1; else falls back to 'message_id' or 'id' or rowid.
    """
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(messages)")
    cols = cur.fetchall()
    for r in cols:
        # r: (cid, name, type, notnull, dflt_value, pk)
        if len(r) >= 6 and r[5] == 1:
            return r[1]
    names = [r[1] for r in cols]
    if "message_id" in names:
        return "message_id"
    if "id" in names:
        return "id"
    return "rowid"


# ---------------- INIT ----------------
def init_db(db_path: Path = DB_PATH):
    """Initialize DB schema with TTL, ephemeral support, and token index."""
    with DB_LOCK:
        conn = get_conn(db_path)
        c = conn.cursor()

        # Messages table with ephemeral/TTL support and unique sender/seq
        c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT NOT NULL,
            nonce BLOB NOT NULL,
            encrypted_blob BLOB NOT NULL,
            seq INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            ttl INTEGER,
            expire_at INTEGER,
            deleted INTEGER DEFAULT 0,
            UNIQUE(sender_id, seq)
        )
        """)

        # Token index table (Phase 2 search)
        c.execute("""
        CREATE TABLE IF NOT EXISTS token_index (
            index_key TEXT NOT NULL,
            message_id INTEGER NOT NULL
        )
        """)

        # Indexes
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_expire ON messages(expire_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_token_index_key ON token_index(index_key)")

        conn.commit()
        conn.close()


# ---------------- STORE & SEARCH ----------------
def store_message(
    sender_id: str,
    encrypted_blob: bytes,
    nonce: bytes,
    plaintext_for_index: Optional[str],
    seq: int,
    ts: int,
    ttl_seconds: Optional[int] = None,
    db_path: str = DB_PATH
) -> Tuple[int, Optional[int]]:
    """
    Store encrypted message with optional TTL and index tokens.

    Returns:
        (message_id, expire_at_unix_ts_or_None)
    """
    expire_at = ts + ttl_seconds if ttl_seconds else None

    with DB_LOCK:
        conn = get_conn(db_path)
        c = conn.cursor()

        # Use INSERT OR IGNORE to prevent duplicate (sender_id, seq)
        c.execute(
            "INSERT OR IGNORE INTO messages (sender_id, nonce, encrypted_blob, seq, ts, ttl, expire_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sender_id, nonce, encrypted_blob, seq, ts, ttl_seconds, expire_at)
        )
        message_id = c.lastrowid

        # Only index tokens if new row was inserted
        if message_id and plaintext_for_index:
            tokens = plaintext_for_index.lower().split()
            for token in tokens:
                index_key = compute_index_key(token)
                c.execute(
                    "INSERT INTO token_index (index_key, message_id) VALUES (?, ?)",
                    (index_key, message_id)
                )

        conn.commit()
        conn.close()

    return message_id, expire_at


def search_messages(search_term: str, db_path: str = DB_PATH) -> List[dict]:
    """
    Search token-indexed messages.
    Returns list of dicts with encrypted blobs and metadata.
    """
    with DB_LOCK:
        conn = get_conn(db_path)
        c = conn.cursor()
        index_key = compute_index_key(search_term.lower())
        c.execute("SELECT message_id FROM token_index WHERE index_key=?", (index_key,))
        message_ids = [row[0] for row in c.fetchall()]

        results = []
        for mid in message_ids:
            c.execute("SELECT encrypted_blob, nonce, sender_id, seq, ts, deleted FROM messages WHERE message_id=?", (mid,))
            row = c.fetchone()
            if row and row[5] == 0:  # skip logically deleted
                blob, nonce, sender, seq, ts, _ = row
                results.append({
                    "message_id": mid,
                    "sender": sender,
                    "seq": seq,
                    "ts": ts,
                    "nonce": nonce,
                    "encrypted_blob": blob
                })

        conn.close()
        return results


# ---------------- EPHEMERAL / TTL ----------------
def load_pending_expirations(now_ts: Optional[int] = None, db_path: str = DB_PATH) -> List[Tuple[int, int]]:
    """
    Return list of (expire_at, message_id) for messages pending expiration, sorted ascending.
    """
    if now_ts is None:
        now_ts = _current_ts()
    with DB_LOCK:
        conn = get_conn(db_path)
        c = conn.cursor()
        c.execute(
            "SELECT message_id, expire_at FROM messages "
            "WHERE expire_at IS NOT NULL AND expire_at > ? AND deleted = 0 "
            "ORDER BY expire_at ASC",
            (now_ts,)
        )
        rows = c.fetchall()
        conn.close()
        return [(r[1], r[0]) for r in rows]


def fetch_message_row(message_pk: int, db_path: str = DB_PATH) -> Optional[Tuple[int, Optional[int], Optional[int]]]:
    """
    Fetch a message row descriptor usable by secure-delete.

    Returns:
      (pk_value, nonce_len, encrypted_blob_len) or None if not found.
    """
    with DB_LOCK:
        conn = get_conn(db_path)
        try:
            pk_col = _detect_pk_col(conn)
            cur = conn.cursor()
            sql = f"SELECT {pk_col}, length(nonce), length(encrypted_blob) FROM messages WHERE {pk_col} = ?"
            cur.execute(sql, (message_pk,))
            row = cur.fetchone()
            if not row:
                return None
            pk_value, nlen, blen = row[0], row[1], row[2]
            return (pk_value, nlen, blen)
        finally:
            conn.close()


def overwrite_and_delete_row_by_pk(pk_value: int, db_path: str = DB_PATH) -> None:
    """
    Best-effort secure delete: overwrite nonce & encrypted_blob, remove token_index rows,
    mark deleted, delete row, and VACUUM.
    """
    with DB_LOCK:
        conn = get_conn(db_path)
        try:
            pk_col = _detect_pk_col(conn)
            cur = conn.cursor()
            # fetch lengths
            cur.execute(f"SELECT length(nonce), length(encrypted_blob) FROM messages WHERE {pk_col} = ?", (pk_value,))
            lens = cur.fetchone()
            if lens:
                nlen, blen = lens
                try:
                    if blen and blen > 0:
                        cur.execute(f"UPDATE messages SET encrypted_blob = ? WHERE {pk_col} = ?", (os.urandom(blen), pk_value))
                    if nlen and nlen > 0:
                        cur.execute(f"UPDATE messages SET nonce = ? WHERE {pk_col} = ?", (os.urandom(nlen), pk_value))
                except Exception:
                    pass
            # remove token_index entries
            cur.execute("DELETE FROM token_index WHERE message_id = ?", (pk_value,))
            # mark deleted and delete row
            cur.execute(f"UPDATE messages SET deleted=1 WHERE {pk_col} = ?", (pk_value,))
            cur.execute(f"DELETE FROM messages WHERE {pk_col} = ?", (pk_value,))
            conn.commit()
            cur.execute("VACUUM")
        finally:
            conn.close()

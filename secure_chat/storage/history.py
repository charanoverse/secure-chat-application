import sqlite3
from typing import List
import hmac, hashlib
import time

from secure_chat.crypto.aead import encrypt_aead_v1, decrypt_aead_v1, NONCE_SIZE, KEY_SIZE

DB_PATH = "secure_chat_history.db"
K_IDX = b"some-32-byte-secret-key"  # store securely

# Use a fixed key for storing encrypted history (separate from session keys)
HISTORY_KEY = b"\x00" * KEY_SIZE  # replace with securely generated key

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT,
            encrypted_blob BLOB,
            seq INTEGER,
            ts INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS token_index (
            index_key TEXT,
            message_id INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def compute_index_key(token: str) -> str:
    return hmac.new(K_IDX, token.encode(), hashlib.sha256).hexdigest()

def store_message(sender_id: str, plaintext: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    seq = int(time.time() * 1000)  # just for storage; not network seq
    ts = int(time.time())
    blob = encrypt_aead_v1(HISTORY_KEY, plaintext.encode(), seq, ts, sender_id.encode())
    
    # Store message
    c.execute("INSERT INTO messages (sender_id, encrypted_blob, seq, ts) VALUES (?, ?, ?, ?)",
              (sender_id, blob, seq, ts))
    message_id = c.lastrowid

    # Tokenize & index
    tokens = plaintext.lower().split()
    for token in tokens:
        index_key = compute_index_key(token)
        c.execute("INSERT INTO token_index (index_key, message_id) VALUES (?, ?)",
                  (index_key, message_id))

    conn.commit()
    conn.close()
    return message_id

def search_messages(search_term: str) -> List[str]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    index_key = compute_index_key(search_term.lower())
    c.execute("SELECT message_id FROM token_index WHERE index_key=?", (index_key,))
    message_ids = [row[0] for row in c.fetchall()]

    results = []
    for mid in message_ids:
        c.execute("SELECT encrypted_blob, sender_id, seq, ts FROM messages WHERE message_id=?", (mid,))
        row = c.fetchone()
        if row:
            blob, sender_id, seq, ts = row
            try:
                plaintext = decrypt_aead_v1(HISTORY_KEY, blob, seq, ts, sender_id.encode()).decode()
                results.append(plaintext)
            except Exception as e:
                print(f"[Warning] Failed to decrypt message {mid}: {e}")
    conn.close()
    return results
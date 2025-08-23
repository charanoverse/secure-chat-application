import os
import time
from pathlib import Path
from ..crypto.aead import encrypt_aead_v1, decrypt_aead_v1, gen_key

LOG_DIR = Path.home() / ".secure_chat"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "chat.log"

# For now we keep a static key on disk just for logs (NOT the session key)
KEY_FILE = LOG_DIR / "log_key.bin"

if not KEY_FILE.exists():
    KEY_FILE.write_bytes(gen_key())

LOG_KEY = KEY_FILE.read_bytes()


def append_encrypted_line(line: str, seq: int, ts: int, peer_id: str) -> None:
    data = line.encode("utf-8")
    blob = encrypt_aead_v1(LOG_KEY, data, seq, ts, peer_id)
    with open(LOG_FILE, "ab") as f:
        f.write(len(blob).to_bytes(4, "big") + blob)


def read_last_n_decrypted(n: int, peer_id: str) -> list[str]:
    """
    Reads the last n encrypted log entries and decrypts them.
    For simplicity we re-use seq numbers as incremental counters from file order.
    """
    if not LOG_FILE.exists():
        return []

    lines = []
    with open(LOG_FILE, "rb") as f:
        blobs = []
        while True:
            length_bytes = f.read(4)
            if not length_bytes:
                break
            length = int.from_bytes(length_bytes, "big")
            blob = f.read(length)
            blobs.append(blob)

        # Only keep last n
        blobs = blobs[-n:]

        for i, blob in enumerate(blobs):
            try:
                # Use file index as seq, current time as ts
                msg = decrypt_aead_v1(LOG_KEY, blob, seq=i, ts=int(time.time()), peer_id=peer_id)
                lines.append(msg.decode("utf-8"))
            except Exception as e:
                lines.append(f"[DECRYPT ERROR: {e}]")

    return lines

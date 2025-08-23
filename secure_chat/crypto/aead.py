#Authenticated Encryption with Associated Data
import os
import struct
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

NONCE_SIZE = 12  # 96-bit recommended for AES-GCM
KEY_SIZE = 32    # 256-bit key


def gen_key() -> bytes:
    """Generate a fresh 256-bit AES key."""
    return os.urandom(KEY_SIZE)


def _aad(seq: int, ts: int, peer_id: bytes) -> bytes:
    """Build Associated Data (AAD) for AES-GCM."""
    return struct.pack(">QQ", seq, ts) + peer_id


def encrypt_aead_v1(key: bytes, plaintext: bytes, seq: int, ts: int | None = None, peer_id: bytes = b"peer") -> bytes:
    """AES-GCM encryption with modern AAD (Protocol v1)."""
    if ts is None:
        ts = int(time.time())
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    aad = _aad(seq, ts, peer_id)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt_aead_v1(key: bytes, blob: bytes, seq: int, ts: int, peer_id: bytes = b"peer") -> bytes:
    """AES-GCM decryption with modern AAD (Protocol v1)."""
    if len(blob) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short")
    nonce = blob[:NONCE_SIZE]
    ct = blob[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    aad = _aad(seq, ts, peer_id)
    return aesgcm.decrypt(nonce, ct, aad)


# --------------------------------------------------------------------
# Session wrapper (Phase 1)
# --------------------------------------------------------------------
class AEADSession:
    """
    AEAD session that manages:
      - Sequence numbers
      - Peer identity binding
      - Forward secrecy (simple rekeying every N messages)
    """

    def __init__(self, key: bytes, peer_id: bytes, rekey_interval: int = 50):
        self.key = key
        self.peer_id = peer_id
        self.seq = 0
        self.rekey_interval = rekey_interval

    def _rekey(self):
        """Derive a new key from the old one using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=struct.pack(">Q", self.seq),
            info=b"rekey"
        )
        self.key = hkdf.derive(self.key)

    def encrypt(self, plaintext: bytes) -> tuple[bytes, int, int]:
        """
        Encrypt a message.
        Returns: (ciphertext, seq, ts)
        """
        ts = int(time.time())
        ct = encrypt_aead_v1(self.key, plaintext, self.seq, ts, self.peer_id)
        out = (ct, self.seq, ts)

        # Increment sequence + maybe rekey
        self.seq += 1
        if self.seq % self.rekey_interval == 0:
            self._rekey()

        return out

    def decrypt(self, blob: bytes, seq: int, ts: int) -> bytes:
        """
        Decrypt a message given seq & ts (provided by sender).
        """
        return decrypt_aead_v1(self.key, blob, seq, ts, self.peer_id)


# --------------------------------------------------------------------
# Backward-compatible aliases
# --------------------------------------------------------------------
encrypt_aead = encrypt_aead_v1
decrypt_aead = decrypt_aead_v1

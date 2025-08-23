# from dataclasses import dataclass

# @dataclass
# class AppConfig:
#     bind_host: str = "0.0.0.0"
#     port: int = 65432
#     history_file: str = "chat_history.enc"
#     # RSA key size for Phase 0 handshake (hybrid RSA + AES-GCM)
#     rsa_key_size: int = 2048

# secure_chat/app_config.py

from dataclasses import dataclass
from pathlib import Path
import os

PROTOCOL_VERSION = 1

# Rekey policy
REKEY_EVERY_N_MESSAGES = 100        # rotate after N messages
REKEY_EVERY_T_SECONDS = 15 * 60     # or after T seconds (whichever first)

# AES-GCM
AES_KEY_BYTES = 32         # AES-256-GCM
GCM_NONCE_BYTES = 12       # 4-byte session salt + 8-byte seq
AAD_PEER_HASH_BYTES = 16   # hash(peer_id) truncated to 16 bytes

# Key derivation
HKDF_TOTAL_BYTES = 64      # k_enc(32) || k_auth(32)
HKDF_INFO_HANDSHAKE = b"secure-chat/v1/handshake"
HKDF_INFO_REKEY = b"secure-chat/v1/rekey"

# Identity pinning (client side)
DEFAULT_PINNED_SERVER_PUBKEY = Path(
    os.environ.get("SECURE_CHAT_PINNED_SERVER_PEM", "server_pubkey.pem")
)

# Networking framing
MAX_FRAME_BYTES = 64 * 1024  # sanity limit

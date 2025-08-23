# Secure Chat (Phase 0)

- AES-GCM (AEAD)
- Per-message random 12-byte nonce
- Length-prefixed frames
- Typer CLI

## Usage

```bash
pip install -e .
secure-chat server --port 65432
secure-chat client --host 127.0.0.1 --port 65432

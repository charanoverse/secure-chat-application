# secure_chat/ui/client_worker.py
from PySide6.QtCore import QObject, Signal, Slot
import socket
import threading
from pathlib import Path

from secure_chat.services.chat_service import (
    _client_handshake,
    _recv_secure,
    _send_secure,
    DeletionScheduler,
)
import secure_chat.storage.history as history_storage


class ClientWorker(QObject):
    """
    Client worker for secure chat.

    Signals:
        connected(str)          -> remote peer ID
        disconnected()          -> connection closed
        message_received(str)   -> plaintext message from peer (UI-visible, TTL prefix removed)
        message_sent(str)       -> plaintext message we successfully sent (UI-visible, TTL prefix removed)
        log(str)                -> debug/info text (NOT for chat UI)
    """

    connected = Signal(str)
    disconnected = Signal()
    message_received = Signal(str)
    message_sent = Signal(str)
    log = Signal(str)

    def __init__(
        self,
        host: str,
        port: int,
        client_peer_id: str,
        server_peer_id: str,
        pinned_server_pubkey_pem: str,
        history_file: str,
        parent=None
    ):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.client_peer_id = client_peer_id
        self.server_peer_id = server_peer_id
        self.pinned_path = Path(pinned_server_pubkey_pem)
        self.history_file = history_file

        self._running = False
        self._state = None
        self._sock = None
        self._scheduler = None

    # ----------------------------------------------------------------------
    # Start connection
    # ----------------------------------------------------------------------
    @Slot()
    def start(self):
        """Start the secure client connection."""
        try:
            self.log.emit(f"[Client] Connecting to {self.host}:{self.port}")
            sock = socket.socket()
            sock.connect((self.host, self.port))
            self._sock = sock

            # Secure handshake
            state = _client_handshake(
                sock,
                self.client_peer_id,
                self.server_peer_id,
                self.pinned_path
            )
            state.history_file = self.history_file
            self._state = state

            # Init DB + scheduler
            try:
                history_storage.init_db(self.history_file)
            except Exception:
                history_storage.init_db()

            scheduler = DeletionScheduler(db_path=self.history_file)
            scheduler.start()
            state.scheduler = scheduler
            self._scheduler = scheduler

            self.connected.emit(state.remote_peer_id)
            self.log.emit("[Client] Handshake complete.")

            # Start receiver thread
            self._running = True
            threading.Thread(target=self._recv_loop, daemon=True).start()

        except Exception as e:
            self.log.emit(f"[Client][Error] {e}")
            self.disconnected.emit()

    # ----------------------------------------------------------------------
    # Receiving loop
    # ----------------------------------------------------------------------
    def _recv_loop(self):
        state = self._state
        if not state:
            self.disconnected.emit()
            return

        while self._running:
            result = _recv_secure(state)
            if result is None:
                break

            pt, nonce, ct, seq, ts_s = result
            if pt is None:
                # decryption error, but stay connected
                self.log.emit("[Client] Decryption error or invalid frame.")
                continue

            raw_msg = pt.decode("utf-8", errors="replace")

            # If the peer sent a TTL-prefixed message, strip prefix for UI display
            display_msg = raw_msg
            try:
                if raw_msg.startswith("/ttl "):
                    parts = raw_msg.split(" ", 2)
                    if len(parts) >= 3:
                        # parts = ["/ttl", "<seconds>", "<real message>"]
                        display_msg = parts[2]
            except Exception:
                display_msg = raw_msg

            # Emit plaintext for UI (without TTL prefix)
            self.message_received.emit(display_msg)

            # Store incoming message in DB for search/history (best-effort)
            try:
                ttl_seconds = None
                msg_for_index = display_msg
                if raw_msg.startswith("/ttl "):
                    # use TTL indicated in prefix for storage entry
                    parts = raw_msg.split(" ", 2)
                    if len(parts) >= 3:
                        try:
                            ttl_seconds = int(parts[1])
                        except Exception:
                            ttl_seconds = None

                history_storage.store_message(
                    sender_id=state.remote_peer_id,
                    encrypted_blob=ct,
                    nonce=nonce,
                    plaintext_for_index=msg_for_index,
                    seq=seq,
                    ts=ts_s,
                    ttl_seconds=ttl_seconds,
                    db_path=history_storage.DB_PATH,
                )

                # schedule deletion if TTL present and scheduler available
                # store_message returns (message_id, expire_at) in other codepaths,
                # but this call form may not return them; if your store_message does return, consider updating accordingly.
                # We intentionally don't assume return here.
            except Exception:
                pass

        self._running = False
        self.disconnected.emit()

    # ----------------------------------------------------------------------
    # Sending messages
    # ----------------------------------------------------------------------
    @Slot(str)
    def send_message(self, msg: str):
        """Encrypt and send a plaintext message to the server."""
        if not self._state or not self._running:
            self.log.emit("[Client] Cannot send: not connected.")
            return

        # -------------------------------------------------------------
        # TTL MESSAGE HANDLING (manual store + schedule)
        # -------------------------------------------------------------
        if msg.startswith("/ttl "):
            try:
                # Extract TTL seconds & actual message
                parts = msg.split(" ", 2)
                ttl_seconds = int(parts[1])
                real_msg = parts[2]

                # 1) Send normally (so receiver actually gets it)
                _send_secure(self._state, real_msg.encode('utf-8'))

                # 2) Get timestamp
                import time
                ts = int(time.time())

                # 3) Store message with TTL
                message_id, expire_at = history_storage.store_message(
                    sender_id=self._state.local_peer_id,
                    encrypted_blob=b"",        # we cannot access ciphertext; store as placeholder
                    nonce=b"",                 # same here; placeholder is OK for TTL-only deletion
                    plaintext_for_index=real_msg,
                    seq=0,                     # placeholder (not needed for deletion)
                    ts=ts,
                    ttl_seconds=ttl_seconds,
                    db_path=self.history_file,
                )

                # 4) Schedule deletion
                if self._state.scheduler:
                    self._state.scheduler.schedule(message_id, expire_at)

                # 5) Show message on UI (clean)
                #self.message_sent.emit(real_msg)
                return

            except Exception as e:
                self.log.emit(f"[Client][TTLError] {e}")
                return

        # -------------------------------------------------------------
        # NORMAL NON-TTL MESSAGE
        # -------------------------------------------------------------
        try:
            _send_secure(self._state, msg.encode("utf-8"))
            self.message_sent.emit(msg)
        except Exception as e:
            self.log.emit(f"[Client][SendError] {e}")


    # ----------------------------------------------------------------------
    # Stop
    # ----------------------------------------------------------------------
    @Slot()
    def stop(self):
        """Stop client worker and close socket."""
        self._running = False

        # Stop scheduler
        try:
            if self._scheduler:
                self._scheduler.stop()
        except:
            pass

        # Close socket
        try:
            if self._state and hasattr(self._state, "sock"):
                try:
                    self._state.sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    self._state.sock.close()
                except:
                    pass
        except:
            pass

        self.disconnected.emit()

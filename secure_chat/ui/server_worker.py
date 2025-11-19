# secure_chat/ui/server_worker.py
from PySide6.QtCore import QObject, Signal, Slot
import socket
import threading
from pathlib import Path

from secure_chat.services.chat_service import (
    _server_handshake,
    _recv_secure,
    _send_secure,
    DeletionScheduler,
)
import secure_chat.storage.history as history_storage


class ServerWorker(QObject):
    """
    Secure Chat Server Worker.

    Signals:
        connected(str)          -> remote client peer ID
        disconnected()          -> when client disconnects
        message_received(str)   -> incoming decrypted plaintext (UI-visible, TTL prefix removed)
        message_sent(str)       -> outgoing plaintext sent successfully (UI-visible, TTL prefix removed)
        log(str)                -> debug/info messages (NOT for the chat window)
    """

    connected = Signal(str)
    disconnected = Signal()
    message_received = Signal(str)
    message_sent = Signal(str)
    log = Signal(str)

    def __init__(
        self,
        bind_host: str,
        port: int,
        server_peer_id: str,
        server_private_pem: str,
        history_file: str,
        parent=None
    ):
        super().__init__(parent)

        self.bind_host = bind_host
        self.port = port
        self.server_peer_id = server_peer_id
        self.server_private_pem = Path(server_private_pem)
        self.history_file = history_file

        self._running = False
        self._state = None
        self._listen_sock = None
        self._scheduler = None

    # ----------------------------------------------------------------------
    # Start server, accept one connection, perform handshake
    # ----------------------------------------------------------------------
    @Slot()
    def start(self):
        """Start secure chat server."""
        try:
            self.log.emit(f"[Server] Binding to {self.bind_host}:{self.port}")

            listen_sock = socket.socket()
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind((self.bind_host, self.port))
            listen_sock.listen(1)
            self._listen_sock = listen_sock

            self.log.emit("[Server] Waiting for connection...")
            conn, addr = listen_sock.accept()
            self.log.emit(f"[Server] Client connected from {addr}")

            # Perform the secure handshake
            state, client_hello = _server_handshake(
                conn,
                self.server_peer_id,
                self.server_private_pem
            )
            state.history_file = self.history_file
            self._state = state

            # Initialize DB and TTL scheduler
            try:
                history_storage.init_db(self.history_file)
            except Exception:
                history_storage.init_db()

            scheduler = DeletionScheduler(db_path=self.history_file)
            scheduler.start()
            state.scheduler = scheduler
            self._scheduler = scheduler

            self.connected.emit(state.remote_peer_id)
            self.log.emit("[Server] Handshake complete. Client authenticated.")

            # Start receiving thread
            self._running = True
            threading.Thread(target=self._recv_loop, daemon=True).start()

        except Exception as e:
            self.log.emit(f"[Server][Error] {e}")
            self.disconnected.emit()

    # ----------------------------------------------------------------------
    # Receive loop
    # ----------------------------------------------------------------------
    def _recv_loop(self):
        state = self._state
        if not state:
            self.disconnected.emit()
            return

        while self._running:
            result = _recv_secure(state)
            if result is None:
                # client disconnected or fatal error
                break

            pt, nonce, ct, seq, ts_s = result
            if pt is None:
                # decryption error: stay alive but log
                self.log.emit("[Server] Decryption error or invalid frame.")
                continue

            raw_msg = pt.decode("utf-8", errors="replace")

            # If TTL-prefixed, strip prefix for display
            display_msg = raw_msg
            try:
                if raw_msg.startswith("/ttl "):
                    parts = raw_msg.split(" ", 2)
                    if len(parts) >= 3:
                        display_msg = parts[2]
            except Exception:
                display_msg = raw_msg

            self.message_received.emit(display_msg)

            # Store incoming message in DB for search/history (best-effort)
            try:
                ttl_seconds = None
                msg_for_index = display_msg
                if raw_msg.startswith("/ttl "):
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
            except Exception:
                pass

        # Cleanup
        self._running = False
        self.disconnected.emit()

    # ----------------------------------------------------------------------
    # Send message
    # ----------------------------------------------------------------------
    @Slot(str)
    def send_message(self, msg: str):
        """Encrypt and send a plaintext message to the client."""
        if not self._state or not self._running:
            self.log.emit("[Server] Cannot send: no active client.")
            return

        # -------------------------------------------------------------
        # TTL MESSAGE
        # -------------------------------------------------------------
        if msg.startswith("/ttl "):
            try:
                parts = msg.split(" ", 2)
                ttl_seconds = int(parts[1])
                real_msg = parts[2]

                # 1) Send normally so receiver gets it
                _send_secure(self._state, real_msg.encode('utf-8'))

                # 2) Timestamp
                import time
                ts = int(time.time())

                # 3) Store message with TTL
                message_id, expire_at = history_storage.store_message(
                    sender_id=self._state.local_peer_id,
                    encrypted_blob=b"",
                    nonce=b"",
                    plaintext_for_index=real_msg,
                    seq=0,
                    ts=ts,
                    ttl_seconds=ttl_seconds,
                    db_path=self.history_file,
                )

                # 4) Schedule deletion
                if self._state.scheduler:
                    self._state.scheduler.schedule(message_id, expire_at)

                # 5) UI show outgoing message
                # self.message_sent.emit(real_msg)
                return

            except Exception as e:
                self.log.emit(f"[Server][TTLError] {e}")
                return

        # -------------------------------------------------------------
        # NORMAL NON-TTL
        # -------------------------------------------------------------
        try:
            _send_secure(self._state, msg.encode("utf-8"))
            self.message_sent.emit(msg)
        except Exception as e:
            self.log.emit(f"[Server][SendError] {e}")


    # ----------------------------------------------------------------------
    # Stop server
    # ----------------------------------------------------------------------
    @Slot()
    def stop(self):
        """Stop the server, disconnect client, and shutdown listening sockets."""
        self._running = False

        # Stop TTL scheduler
        try:
            if self._scheduler:
                self._scheduler.stop()
        except:
            pass

        # Close connection socket
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

        # Close listening socket
        try:
            if self._listen_sock:
                self._listen_sock.close()
        except:
            pass

        self.disconnected.emit()

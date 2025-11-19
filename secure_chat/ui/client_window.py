# secure_chat/ui/client_window.py
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QMessageBox, QDialog
)
from PySide6.QtCore import QThread, Slot

from .chat_widget import ChatWidget
from .connect_dialog import ConnectDialog
from .client_worker import ClientWorker
from .search_dialog import SearchDialog
from .ttl_dialog import TTLDialog


class ClientWindow(QWidget):
    """
    GUI window for the Secure Chat Client with Ephemeral Mode (custom TTL).
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Secure Chat - Client")
        self.resize(900, 600)

        self.thread: QThread | None = None
        self.worker: ClientWorker | None = None

        self._build_ui()

    # -----------------------------------------------------------
    # Build the GUI
    # -----------------------------------------------------------
    def _build_ui(self):
        layout = QVBoxLayout(self)

        # Top buttons
        top = QHBoxLayout()
        self.connect_btn = QPushButton("Connect")
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.setEnabled(False)
        self.search_btn = QPushButton("Search History")

        top.addWidget(self.connect_btn)
        top.addWidget(self.disconnect_btn)
        top.addWidget(self.search_btn)
        layout.addLayout(top)

        # Chat widget
        self.chat = ChatWidget()
        layout.addWidget(self.chat)

        # Events
        self.connect_btn.clicked.connect(self._on_connect)
        self.disconnect_btn.clicked.connect(self._on_disconnect)
        self.search_btn.clicked.connect(self._on_search_history)

        # Normal (non-TTL) messages
        self.chat.send_message.connect(self._on_send_message)

        # Ephemeral-mode messages
        self.chat.send_with_ttl.connect(self._on_send_with_ttl)

    # -----------------------------------------------------------
    # Connect to server
    # -----------------------------------------------------------
    @Slot()
    def _on_connect(self):
        if self.worker is not None:
            self.chat.append_message("System", "Already connected.")
            return

        dlg = ConnectDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return

        values = dlg.get_values()
        host = values["host"]
        port = values["port"]
        client_peer_id = values["client_peer_id"]
        server_peer_id = values["server_peer_id"]
        pinned = values["pinned_server_pubkey"]

        if not client_peer_id or not server_peer_id or not pinned:
            QMessageBox.warning(self, "Missing", "Enter peer IDs and pinned pubkey.")
            return

        # Worker thread
        self.thread = QThread()
        self.worker = ClientWorker(
            host=host,
            port=port,
            client_peer_id=client_peer_id,
            server_peer_id=server_peer_id,
            pinned_server_pubkey_pem=pinned,
            history_file="chat_history.enc",
        )
        self.worker.moveToThread(self.thread)

        # Worker signals
        self.thread.started.connect(self.worker.start)

        self.worker.connected.connect(lambda peer:
            self.chat.append_message("System", f"Connected to {peer}")
        )

        self.worker.disconnected.connect(self._on_worker_stopped)

        self.worker.message_received.connect(lambda msg:
            self.chat.append_message("Peer", msg)
        )

        self.worker.message_sent.connect(lambda msg:
            self.chat.append_message("You", msg)
        )

        # debug logs → console only
        self.worker.log.connect(print)

        # Start thread
        self.thread.start()
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(True)
        self.chat.append_message("System", "Connecting…")

    # -----------------------------------------------------------
    # Disconnect
    # -----------------------------------------------------------
    @Slot()
    def _on_disconnect(self):
        if self.worker:
            self.worker.stop()
        else:
            self._on_worker_stopped()

    # -----------------------------------------------------------
    # Cleanup on disconnect
    # -----------------------------------------------------------
    @Slot()
    def _on_worker_stopped(self):
        try:
            if self.thread:
                self.thread.quit()
                self.thread.wait(1500)
        except:
            pass

        self.thread = None
        self.worker = None
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)

        self.chat.append_message("System", "Disconnected.")

    # -----------------------------------------------------------
    # Normal message send
    # -----------------------------------------------------------
    @Slot(str)
    def _on_send_message(self, text: str):
        if not self.worker:
            self.chat.append_message("System", "Not connected.")
            return
        self.worker.send_message(text)

    # -----------------------------------------------------------
    # Ephemeral send → show TTL popup
    # -----------------------------------------------------------
    @Slot(str)
    def _on_send_with_ttl(self, text: str):
        if not self.worker:
            self.chat.append_message("System", "Not connected.")
            return

        dlg = TTLDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return

        ttl = dlg.get_ttl()
        if ttl is None:
            return

        # Build formatted TTL message
        ttl_msg = f"/ttl {ttl} {text}"

        # Send to worker
        self.worker.send_message(ttl_msg)

        # IMPORTANT: Immediately show it in the UI
        # Because worker will not emit message_sent for TTL automatically
        self.chat.append_message("You", text)

    # -----------------------------------------------------------
    # Open search history dialog
    # -----------------------------------------------------------
    @Slot()
    def _on_search_history(self):
        dlg = SearchDialog(self)
        dlg.exec()

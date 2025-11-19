# secure_chat/ui/server_window.py
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit,
    QFileDialog, QMessageBox
)
from PySide6.QtCore import QThread, Slot
from PySide6.QtWidgets import QDialog
from .chat_widget import ChatWidget
from .server_worker import ServerWorker
from .search_dialog import SearchDialog
from .ttl_dialog import TTLDialog


class ServerWindow(QWidget):
    """
    GUI window for the Secure Chat Server, with Ephemeral Mode support.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Secure Chat - Server")
        self.resize(900, 600)

        self.thread: QThread | None = None
        self.worker: ServerWorker | None = None

        self._build_ui()

    # ----------------------------------------------------------------------
    # Build the UI
    # ----------------------------------------------------------------------
    def _build_ui(self):
        layout = QVBoxLayout(self)

        # Top bar
        top = QHBoxLayout()

        top.addWidget(QLabel("Host:"))
        self.host_edit = QLineEdit("0.0.0.0")
        top.addWidget(self.host_edit)

        top.addWidget(QLabel("Port:"))
        self.port_edit = QLineEdit("65432")
        self.port_edit.setMaximumWidth(90)
        top.addWidget(self.port_edit)

        top.addWidget(QLabel("Server Peer ID:"))
        self.peer_edit = QLineEdit("SERVER")
        self.peer_edit.setMaximumWidth(180)
        top.addWidget(self.peer_edit)

        top.addWidget(QLabel("Private PEM:"))
        self.priv_edit = QLineEdit("server_priv.pem")
        top.addWidget(self.priv_edit)

        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._on_browse)
        top.addWidget(browse_btn)

        # Start/Stop
        self.start_btn = QPushButton("Start Server")
        self.stop_btn = QPushButton("Stop Server")
        self.stop_btn.setEnabled(False)

        self.search_btn = QPushButton("Search History")

        top.addWidget(self.start_btn)
        top.addWidget(self.stop_btn)
        top.addWidget(self.search_btn)

        layout.addLayout(top)

        # Chat widget
        self.chat = ChatWidget()
        layout.addWidget(self.chat)

        # Events
        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn.clicked.connect(self._on_stop)
        self.chat.send_message.connect(self._on_send_message)
        self.chat.send_with_ttl.connect(self._on_send_with_ttl)
        self.search_btn.clicked.connect(self._on_search_history)

    # ----------------------------------------------------------------------
    # Browse for private PEM
    # ----------------------------------------------------------------------
    @Slot()
    def _on_browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select PEM File", "", "PEM Files (*.pem)"
        )
        if path:
            self.priv_edit.setText(path)

    # ----------------------------------------------------------------------
    # Start server + accept connection
    # ----------------------------------------------------------------------
    @Slot()
    def _on_start(self):
        if self.worker is not None:
            self.chat.append_message("System", "Server already running.")
            return

        host = self.host_edit.text().strip()
        try:
            port = int(self.port_edit.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "Port must be a number.")
            return

        server_peer_id = self.peer_edit.text().strip()
        private_pem = self.priv_edit.text().strip()

        if not server_peer_id or not private_pem:
            QMessageBox.warning(self, "Missing", "Enter Server Peer ID & Private PEM.")
            return

        # Setup worker thread
        self.thread = QThread()
        self.worker = ServerWorker(
            bind_host=host,
            port=port,
            server_peer_id=server_peer_id,
            server_private_pem=private_pem,
            history_file="chat_history.enc",
        )
        self.worker.moveToThread(self.thread)

        # Connect worker signals
        self.thread.started.connect(self.worker.start)

        self.worker.connected.connect(lambda peer:
            self.chat.append_message("System", f"Client connected: {peer}")
        )

        self.worker.disconnected.connect(self._on_worker_stopped)

        self.worker.message_received.connect(lambda msg:
            self.chat.append_message("Peer", msg)
        )

        self.worker.message_sent.connect(lambda msg:
            self.chat.append_message("You", msg)
        )

        # Logs → console only
        self.worker.log.connect(print)

        # Start server
        self.thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.chat.append_message("System", "Server started. Waiting for client…")

    # ----------------------------------------------------------------------
    # Stop server
    # ----------------------------------------------------------------------
    @Slot()
    def _on_stop(self):
        if self.worker:
            self.worker.stop()
        else:
            self._on_worker_stopped()

    # ----------------------------------------------------------------------
    # Cleanup worker thread
    # ----------------------------------------------------------------------
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
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        self.chat.append_message("System", "Server stopped or client disconnected.")

    # ----------------------------------------------------------------------
    # Normal message send
    # ----------------------------------------------------------------------
    @Slot(str)
    def _on_send_message(self, text: str):
        if not self.worker:
            self.chat.append_message("System", "Server not running.")
            return

        self.worker.send_message(text)

    # ----------------------------------------------------------------------
    # Ephemeral send (show TTL popup)
    # ----------------------------------------------------------------------
    @Slot(str)
    def _on_send_with_ttl(self, text: str):
        if not self.worker:
            self.chat.append_message("System", "Server not running.")
            return

        dlg = TTLDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return

        ttl = dlg.get_ttl()
        if ttl is None:
            return

        ttl_msg = f"/ttl {ttl} {text}"

        # Send
        self.worker.send_message(ttl_msg)

        # Show locally
        self.chat.append_message("You", text)


    # ----------------------------------------------------------------------
    # Search history popup
    # ----------------------------------------------------------------------
    @Slot()
    def _on_search_history(self):
        dlg = SearchDialog(self)
        dlg.exec()

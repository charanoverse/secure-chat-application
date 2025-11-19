# secure_chat/ui/connect_dialog.py
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QSpinBox
)
from PySide6.QtCore import Slot


class ConnectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Connect to Server")
        self._build_ui()

    def _build_ui(self):
        v = QVBoxLayout(self)

        # host + port
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("Host:"))
        self.host_edit = QLineEdit("127.0.0.1")
        h1.addWidget(self.host_edit)
        h1.addWidget(QLabel("Port:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(65432)
        h1.addWidget(self.port_spin)
        v.addLayout(h1)

        # client peer id
        h2 = QHBoxLayout()
        h2.addWidget(QLabel("Client Peer ID:"))
        self.client_id_edit = QLineEdit()
        h2.addWidget(self.client_id_edit)
        v.addLayout(h2)

        # server id
        h3 = QHBoxLayout()
        h3.addWidget(QLabel("Server Peer ID:"))
        self.server_id_edit = QLineEdit()
        h3.addWidget(self.server_id_edit)
        v.addLayout(h3)

        # pinned server pubkey
        h4 = QHBoxLayout()
        h4.addWidget(QLabel("Pinned Server Pub PEM:"))
        self.pinned_edit = QLineEdit()
        h4.addWidget(self.pinned_edit)
        self.pick_btn = QPushButton("Browse")
        h4.addWidget(self.pick_btn)
        self.pick_btn.clicked.connect(self._on_pick)
        v.addLayout(h4)

        # buttons
        btn_row = QHBoxLayout()
        self.connect_btn = QPushButton("Connect")
        self.cancel_btn = QPushButton("Cancel")
        btn_row.addWidget(self.connect_btn)
        btn_row.addWidget(self.cancel_btn)
        v.addLayout(btn_row)

        self.connect_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)

    @Slot()
    def _on_pick(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select pinned server pub PEM", "", "PEM files (*.pem);;All files (*)")
        if path:
            self.pinned_edit.setText(path)

    def get_values(self):
        return {
            "host": self.host_edit.text().strip(),
            "port": int(self.port_spin.value()),
            "client_peer_id": self.client_id_edit.text().strip(),
            "server_peer_id": self.server_id_edit.text().strip(),
            "pinned_server_pubkey": self.pinned_edit.text().strip(),
        }

# secure_chat/ui/ttl_dialog.py
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QMessageBox
)
from PySide6.QtCore import Slot


class TTLDialog(QDialog):
    """
    Pops up to ask user for TTL duration (seconds).
    Returns an integer TTL via get_ttl() if accepted.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ephemeral Message TTL")
        self.resize(300, 120)

        self.ttl_value = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)

        row = QHBoxLayout()
        row.addWidget(QLabel("TTL (seconds):"))

        self.ttl_edit = QLineEdit()
        self.ttl_edit.setPlaceholderText("e.g. 5")
        row.addWidget(self.ttl_edit)

        layout.addLayout(row)

        btn_row = QHBoxLayout()
        self.ok_btn = QPushButton("Send")
        self.cancel_btn = QPushButton("Cancel")

        self.ok_btn.clicked.connect(self._on_ok)
        self.cancel_btn.clicked.connect(self.reject)

        btn_row.addWidget(self.ok_btn)
        btn_row.addWidget(self.cancel_btn)

        layout.addLayout(btn_row)

    @Slot()
    def _on_ok(self):
        text = self.ttl_edit.text().strip()
        if not text:
            QMessageBox.warning(self, "Missing", "Please enter a TTL value.")
            return
        try:
            ttl = int(text)
            if ttl <= 0:
                raise ValueError
        except:
            QMessageBox.warning(self, "Invalid TTL", "TTL must be a positive integer.")
            return

        self.ttl_value = ttl
        self.accept()

    def get_ttl(self):
        return self.ttl_value

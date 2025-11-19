# secure_chat/ui/search_dialog.py
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QMessageBox
)
from PySide6.QtCore import Qt

from secure_chat.storage.history import search_messages
from datetime import datetime


class SearchDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Search Encrypted History")
        self.resize(600, 500)

        layout = QVBoxLayout(self)

        # Search input row
        row = QHBoxLayout()
        row.addWidget(QLabel("Search term:"))
        self.input = QLineEdit()
        row.addWidget(self.input)

        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.perform_search)
        row.addWidget(self.search_btn)

        layout.addLayout(row)

        # Results area
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        layout.addWidget(self.results)

    def perform_search(self):
        term = self.input.text().strip()
        if not term:
            QMessageBox.warning(self, "Missing term", "Please enter a search term.")
            return

        try:
            matches = search_messages(term)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Search failed:\n{e}")
            return

        if not matches:
            self.results.setPlainText("No messages found.")
            return

        # Format results similar to CLI
        out = [f"Found {len(matches)} matches:\n"]
        for r in matches:
            mid = r.get("message_id", "<unknown>")
            sender = r.get("sender", "<unknown>")
            ts = r.get("ts", None)
            if ts:
                ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            else:
                ts_str = "<unknown>"
            out.append(f"- message_id={mid} sender={sender} ts={ts_str}")

        self.results.setPlainText("\n".join(out))

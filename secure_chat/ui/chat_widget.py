# secure_chat/ui/chat_widget.py
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit, QHBoxLayout, QLineEdit, QPushButton, QLabel
)
from PySide6.QtCore import Signal, Slot
from datetime import datetime


class ChatWidget(QWidget):
    """
    Chat widget with:
      - send_message(str)           normal send
      - send_with_ttl(str)          emitted when ephemeral mode ON -> window should ask for TTL and then send "/ttl X msg"
      - append_message(who,msg,ts)  display message with timestamp

    Ephemeral mode:
      - user toggles the Ephemeral button
      - input box highlights (visual cue)
      - when pressing Send, widget emits send_with_ttl(msg) instead of send_message(msg)
      - actual TTL is asked by the window (popup) so user can enter custom duration per message
    """
    send_message = Signal(str)
    send_with_ttl = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.ephemeral_mode = False
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # Chat view
        self.view = QTextEdit()
        self.view.setReadOnly(True)
        self.view.setAcceptRichText(False)
        layout.addWidget(self.view)

        # small row showing ephemeral mode status
        status_row = QHBoxLayout()
        self.ephemeral_label = QLabel("")  # filled when ephemeral is ON
        status_row.addWidget(self.ephemeral_label)
        status_row.addStretch()
        layout.addLayout(status_row)

        # Input row
        row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("Type a message...")
        self.send_btn = QPushButton("Send")
        self.ephemeral_btn = QPushButton("🔥 Ephemeral")
        self.ephemeral_btn.setCheckable(True)

        # Wire events
        self.ephemeral_btn.toggled.connect(self._on_ephemeral_toggled)
        self.send_btn.clicked.connect(self._on_send_clicked)
        self.input.returnPressed.connect(self._on_send_clicked)

        row.addWidget(self.ephemeral_btn)
        row.addWidget(self.input)
        row.addWidget(self.send_btn)
        layout.addLayout(row)

    # -------------------------
    # Ephemeral mode handling
    # -------------------------
    @Slot(bool)
    def _on_ephemeral_toggled(self, checked: bool):
        """Toggle ephemeral mode (visual cue only)."""
        self.ephemeral_mode = bool(checked)
        if self.ephemeral_mode:
            self.ephemeral_label.setText("Ephemeral Mode ON — you will be asked for TTL on send")
            # subtle visual cue: change placeholder and set style
            self.input.setPlaceholderText("Type a message (ephemeral mode)…")
            # inline style highlight for input (orange-ish)
            self.input.setStyleSheet("background-color: rgba(255,165,0,0.08);")
        else:
            self.ephemeral_label.setText("")
            self.input.setPlaceholderText("Type a message...")
            self.input.setStyleSheet("")

    # -------------------------
    # Sending
    # -------------------------
    @Slot()
    def _on_send_clicked(self):
        text = self.input.text().strip()
        if not text:
            return
        # do not append message here — windows will handle append on message_sent
        if self.ephemeral_mode:
            # emit signal so window can prompt TTL and then send "/ttl X msg"
            self.send_with_ttl.emit(text)
        else:
            self.send_message.emit(text)
        self.input.clear()

    # -------------------------
    # Timestamp formatting & display
    # -------------------------
    def _format_ts(self, ts=None):
        if ts is None:
            ts = datetime.now()
        elif isinstance(ts, (int, float)):
            ts = datetime.fromtimestamp(ts)
        return ts.strftime("%H:%M:%S")

    def append_message(self, who: str, msg: str, ts=None):
        """
        Append a chat message to the view.
        - who: "You", "Peer", "System"
        - msg: plaintext message
        - ts: optional datetime or unix timestamp
        """
        ts_str = self._format_ts(ts)
        self.view.append(f"[{ts_str}] {who}: {msg}")
        self.view.verticalScrollBar().setValue(self.view.verticalScrollBar().maximum())

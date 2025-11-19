# secure_chat/ui/main_window.py
import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QToolBar
from PySide6.QtGui import QAction
from .server_window import ServerWindow
from .client_window import ClientWindow
from pathlib import Path

APP_NAME = "Secure Chat GUI"


def run():
    app = QApplication(sys.argv)
    # optional styling
    css_path = Path(__file__).parent / "styles.css"
    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())

    main = QMainWindow()
    main.setWindowTitle(APP_NAME)
    toolbar = QToolBar()
    main.addToolBar(toolbar)

    server_action = QAction("Server", main)
    client_action = QAction("Client", main)
    toolbar.addAction(server_action)
    toolbar.addAction(client_action)

    server_win = ServerWindow()
    client_win = ClientWindow()

    def open_server():
        server_win.show()
        server_win.raise_()
        server_win.activateWindow()

    def open_client():
        client_win.show()
        client_win.raise_()
        client_win.activateWindow()

    server_action.triggered.connect(open_server)
    client_action.triggered.connect(open_client)

    main.show()
    sys.exit(app.exec())

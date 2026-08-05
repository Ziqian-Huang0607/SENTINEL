"""Entry point: ``python -m sentinel_ui`` launches the desktop app."""

from __future__ import annotations

import signal
import sys

from PySide6.QtCore import QTimer

from .app import create_application
from .main_window import MainWindow
from .models import APP_NAME


def main() -> int:
    """Create the application, show the main window and run the event loop."""
    app = create_application()
    window = MainWindow()
    window.show()
    # macOS opens the window behind the terminal without an explicit raise.
    window.raise_()
    window.activateWindow()

    # Ctrl+C closes the app cleanly instead of dumping a KeyboardInterrupt
    # traceback. Qt's event loop starves Python signal delivery, so a periodic
    # no-op timer gives the interpreter a chance to run the handler.
    def _handle_sigint(_signum: int, _frame: object) -> None:
        window.close()

    signal.signal(signal.SIGINT, _handle_sigint)
    pump = QTimer(app)
    pump.timeout.connect(lambda: None)
    pump.start(250)

    print(f"{APP_NAME} UI running - Ctrl+C or close the window to quit.", flush=True)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

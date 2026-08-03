"""Entry point: ``python -m sentinel_ui`` launches the desktop app."""

from __future__ import annotations

import sys

from .app import create_application
from .main_window import MainWindow


def main() -> int:
    """Create the application, show the main window and run the event loop."""
    app = create_application()
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

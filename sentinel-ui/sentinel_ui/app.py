"""QApplication bootstrap: stylesheet, window icon and app identity."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtGui import QFont, QFontDatabase, QIcon
from PySide6.QtWidgets import QApplication

from .models import APP_NAME

# Preferred UI families, first installed wins. Resolving at runtime avoids
# Qt's "missing font family" warning when Inter is not installed (macOS).
PREFERRED_FAMILIES = ("Inter", "SF Pro Text", "Segoe UI", "Helvetica Neue", "Noto Sans")

_PACKAGE_DIR = Path(__file__).resolve().parent
ASSETS_DIR = _PACKAGE_DIR.parent / "assets"
LOGO_PATH = ASSETS_DIR / "logo.png"
STYLESHEET_PATH = _PACKAGE_DIR / "theme.qss"

ORGANIZATION_NAME = "Sentinel"


def load_stylesheet() -> str:
    """Read the centralized ops-center QSS theme from disk."""
    return STYLESHEET_PATH.read_text(encoding="utf-8")


def app_icon() -> QIcon:
    """Return the SENTINEL logo as a window icon."""
    return QIcon(str(LOGO_PATH))


def resolve_ui_font() -> QFont | None:
    """Return the first preferred family installed on this machine, else None."""
    available = set(QFontDatabase.families())
    for family in PREFERRED_FAMILIES:
        if family in available:
            return QFont(family)
    return None  # Qt falls back to the platform default


def create_application(argv: list[str] | None = None) -> QApplication:
    """Create (or return) the QApplication with theme and icon applied."""
    existing = QApplication.instance()
    if existing is not None:
        return existing
    app = QApplication(list(argv) if argv is not None else sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORGANIZATION_NAME)
    font = resolve_ui_font()
    if font is not None:
        app.setFont(font)
    app.setStyleSheet(load_stylesheet())
    app.setWindowIcon(app_icon())
    return app

"""New Scan view: target, tier, formats, advanced options and scope gate."""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..models import ANALYZER_DEFAULT_URL, ScanRequest, Tier
from ..validators import CONFIRM_PHRASE, LEGAL_NOTICE, validate_confirm, validate_target

PORT_PRESETS = ("top-100", "top-1000", "full")
OUTPUT_FORMATS = ("json", "pdf", "sarif")

_SETTINGS_SCANNER = "scanner/binary"
_SETTINGS_ANALYZER = "analyzer/url"


class ScopeConfirmDialog(QDialog):
    """Modal scope gate requiring the operator to type exactly ``CONFIRM``."""

    def __init__(
        self,
        target: str,
        tier: Tier,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm Scan Scope")
        self.setModal(True)
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # QComboBox user data may round-trip a StrEnum through QVariant as a
        # plain str (PySide6 >= 6.10); normalize so .value always exists.
        tier = Tier(tier)
        summary = QLabel(f"Target: {target}\nTier: {tier.value.upper()}")
        summary.setObjectName("subheading")
        layout.addWidget(summary)

        instruction = QLabel(f"Type {CONFIRM_PHRASE} to authorize this scan.")
        layout.addWidget(instruction)

        self._input = QLineEdit()
        self._input.setPlaceholderText(CONFIRM_PHRASE)
        self._input.textChanged.connect(self._on_text_changed)
        layout.addWidget(self._input)

        legal = QLabel(LEGAL_NOTICE)
        legal.setObjectName("legalNotice")
        layout.addWidget(legal)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok_button.setText("Launch Scan")
        self._ok_button.setObjectName("primaryButton")
        self._ok_button.setEnabled(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_text_changed(self, text: str) -> None:
        """Enable the launch button only on an exact CONFIRM match."""
        self._ok_button.setEnabled(validate_confirm(text))

    def is_confirmed(self) -> bool:
        """Return True when the dialog was accepted with a valid CONFIRM."""
        return self.result() == QDialog.DialogCode.Accepted and validate_confirm(
            self._input.text()
        )


class NewScanView(QWidget):
    """Scan configuration form that emits a :class:`ScanRequest` on launch."""

    scan_requested = Signal(object)  # ScanRequest

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = QSettings()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        heading = QLabel("New Scan")
        heading.setObjectName("heading")
        layout.addWidget(heading)

        card = QFrame()
        card.setObjectName("card")
        form = QFormLayout(card)
        form.setSpacing(12)

        self._target_edit = QLineEdit()
        self._target_edit.textChanged.connect(self._on_target_changed)
        form.addRow("Target (CIDR or IP)", self._target_edit)

        self._tier_combo = QComboBox()
        for tier in Tier:
            self._tier_combo.addItem(tier.value.upper(), tier)
        form.addRow("Security tier", self._tier_combo)

        formats_row = QHBoxLayout()
        self._format_checks: dict[str, QCheckBox] = {}
        for fmt in OUTPUT_FORMATS:
            check = QCheckBox(fmt.upper())
            check.setChecked(fmt == "json")
            self._format_checks[fmt] = check
            formats_row.addWidget(check)
        formats_row.addStretch(1)
        form.addRow("Output formats", formats_row)
        layout.addWidget(card)

        advanced = QGroupBox("Advanced")
        advanced_form = QFormLayout(advanced)
        advanced_form.setSpacing(12)

        self._concurrency_spin = QSpinBox()
        self._concurrency_spin.setRange(1, 5000)
        self._concurrency_spin.setValue(200)
        advanced_form.addRow("Concurrency", self._concurrency_spin)

        self._ports_combo = QComboBox()
        self._ports_combo.addItems(PORT_PRESETS)
        self._ports_combo.setCurrentText("top-1000")
        advanced_form.addRow("Ports preset", self._ports_combo)

        self._analyzer_edit = QLineEdit(
            self._settings.value(_SETTINGS_ANALYZER, ANALYZER_DEFAULT_URL, type=str)
        )
        advanced_form.addRow("Analyzer URL", self._analyzer_edit)

        self._scanner_edit = QLineEdit(
            self._settings.value(_SETTINGS_SCANNER, "", type=str)
        )
        advanced_form.addRow("Scanner binary", self._scanner_edit)

        self._allow_public_check = QCheckBox("Allow public ranges")
        advanced_form.addRow("", self._allow_public_check)
        layout.addWidget(advanced)

        legal = QLabel(LEGAL_NOTICE)
        legal.setObjectName("legalNotice")
        layout.addWidget(legal)

        self._launch_button = QPushButton("Launch Scan")
        self._launch_button.setObjectName("primaryButton")
        self._launch_button.clicked.connect(self._on_launch)
        layout.addWidget(self._launch_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addStretch(1)

    def _on_target_changed(self, text: str) -> None:
        """Flag the target field invalid as the operator types."""
        self._target_edit.setProperty("invalid", not validate_target(text))
        self._target_edit.style().unpolish(self._target_edit)
        self._target_edit.style().polish(self._target_edit)

    def _on_launch(self) -> None:
        """Validate input, run the scope gate and emit the scan request."""
        target = self._target_edit.text().strip()
        if not validate_target(target):
            self._on_target_changed(target)
            return
        # QComboBox user data may come back as a plain str on some PySide6
        # versions (StrEnum -> QVariant loses the enum type); coerce so the
        # dialog, the ScanRequest and all downstream tier lookups get a Tier.
        tier = Tier(self._tier_combo.currentData())
        dialog = ScopeConfirmDialog(target, tier, self)
        dialog.exec()
        if not dialog.is_confirmed():
            return

        self._settings.setValue(_SETTINGS_ANALYZER, self._analyzer_edit.text().strip())
        self._settings.setValue(_SETTINGS_SCANNER, self._scanner_edit.text().strip())

        formats = [fmt for fmt, check in self._format_checks.items() if check.isChecked()]
        self.scan_requested.emit(
            ScanRequest(
                target=target,
                tier=tier,
                formats=formats or ["json"],
                concurrency=self._concurrency_spin.value(),
                ports_preset=self._ports_combo.currentText(),
                scanner_binary=self._scanner_edit.text().strip(),
                analyzer_url=self._analyzer_edit.text().strip() or ANALYZER_DEFAULT_URL,
                allow_public=self._allow_public_check.isChecked(),
            )
        )

    def set_scanning(self, scanning: bool) -> None:
        """Disable the launch button while a scan is in flight."""
        self._launch_button.setEnabled(not scanning)

    def default_analyzer_url(self) -> str:
        """Return the analyzer URL currently configured in the form."""
        return self._analyzer_edit.text().strip() or ANALYZER_DEFAULT_URL

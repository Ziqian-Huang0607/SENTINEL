"""Dashboard view: brand header, analyzer status, tier cards, risk gauge."""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPaintEvent, QPen, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..app import LOGO_PATH
from ..models import APP_NAME, TIER_PROFILES, AnalysisOutput, ScanInput, Tier

GAUGE_START_ANGLE = 210
GAUGE_SPAN = 240

COLOR_TEXT = QColor("#E5E7EB")
COLOR_MUTED = QColor("#9CA3AF")
COLOR_TRACK = QColor("#1F2937")
COLOR_ACCENT = QColor("#38BDF8")
COLOR_DANGER = QColor("#EF4444")
COLOR_WARN = QColor("#F59E0B")
COLOR_OK = QColor("#34D399")

STATUS_CAPTIONS = {
    "llm": "Analyzer Online — LLM",
    "fallback": "Analyzer Online — Fallback",
    "offline": "Analyzer Offline",
}

NO_RESULTS_TEXT = "No scan results yet."


def gauge_color(value: float) -> QColor:
    """Return the color code for a risk score on the 0–10 scale."""
    if value >= 7.5:
        return COLOR_DANGER
    if value >= 5.0:
        return COLOR_WARN
    if value >= 2.5:
        return COLOR_ACCENT
    return COLOR_OK


class RiskGauge(QWidget):
    """Custom-painted arc gauge showing the overall risk score (0–10)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._value: float | None = None
        self.setMinimumSize(220, 220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def setValue(self, value: float | None) -> None:
        """Set the displayed score; ``None`` renders the empty state."""
        self._value = None if value is None else max(0.0, min(10.0, value))
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802 - Qt override
        """Paint track arc, value arc and the centered score readout."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        side = min(self.width(), self.height()) - 16
        rect = QRectF(
            (self.width() - side) / 2,
            (self.height() - side) / 2,
            side,
            side,
        ).adjusted(12, 12, -12, -12)

        track_pen = QPen(COLOR_TRACK, 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap)
        painter.setPen(track_pen)
        painter.drawArc(rect, GAUGE_START_ANGLE * 16, -GAUGE_SPAN * 16)

        if self._value is not None:
            fraction = self._value / 10.0
            value_pen = QPen(
                gauge_color(self._value),
                12,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
            )
            painter.setPen(value_pen)
            painter.drawArc(rect, GAUGE_START_ANGLE * 16, int(-GAUGE_SPAN * fraction * 16))

        painter.setPen(QPen(COLOR_TEXT if self._value is not None else COLOR_MUTED))
        value_font = QFont(self.font())
        value_font.setPointSize(34)
        value_font.setBold(True)
        painter.setFont(value_font)
        text = "--" if self._value is None else f"{self._value:.2f}"
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)

        caption_rect = rect.adjusted(0, rect.height() / 4, 0, 0)
        caption_font = QFont(self.font())
        caption_font.setPointSize(9)
        caption_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 2)
        painter.setFont(caption_font)
        painter.setPen(QPen(COLOR_MUTED))
        painter.drawText(
            caption_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            "OVERALL RISK",
        )
        painter.end()


class CounterCard(QFrame):
    """A single headline counter (value plus caption)."""

    def __init__(self, caption: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        self._value_label = QLabel("0")
        self._value_label.setObjectName("counterValue")
        caption_label = QLabel(caption.upper())
        caption_label.setObjectName("counterCaption")
        layout.addWidget(self._value_label)
        layout.addWidget(caption_label)

    def setValue(self, value: int) -> None:
        """Update the displayed counter."""
        self._value_label.setText(str(value))


class TierCard(QFrame):
    """Summary card for one security tier from the SPEC tier table."""

    def __init__(self, tier: Tier, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        profile = TIER_PROFILES[tier]
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        name = QLabel(tier.value.upper())
        name.setObjectName("tierName")
        layout.addWidget(name)

        for caption, value in (
            ("Threat", profile.threat),
            ("Compliance", profile.compliance),
            ("Patch SLA (critical)", profile.patch_sla),
            ("Risk threshold", f"< {profile.risk_threshold:.1f}"),
        ):
            row = QLabel(f"{caption}: {value}")
            row.setObjectName("muted")
            row.setWordWrap(True)
            layout.addWidget(row)
        layout.addStretch(1)


class DashboardView(QWidget):
    """Ops-center landing page with fleet posture at a glance."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        layout.addLayout(self._build_header())

        self._empty_label = QLabel(NO_RESULTS_TEXT)
        self._empty_label.setObjectName("emptyState")
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._empty_label)

        body = QHBoxLayout()
        body.setSpacing(16)

        gauge_card = QFrame()
        gauge_card.setObjectName("card")
        gauge_layout = QVBoxLayout(gauge_card)
        self._gauge = RiskGauge()
        gauge_layout.addWidget(self._gauge)
        body.addWidget(gauge_card, 1)

        counters_grid = QGridLayout()
        counters_grid.setSpacing(16)
        self._hosts_counter = CounterCard("Hosts")
        self._ports_counter = CounterCard("Open Ports")
        self._cves_counter = CounterCard("CVEs")
        self._chains_counter = CounterCard("Attack Chains")
        counters_grid.addWidget(self._hosts_counter, 0, 0)
        counters_grid.addWidget(self._ports_counter, 0, 1)
        counters_grid.addWidget(self._cves_counter, 1, 0)
        counters_grid.addWidget(self._chains_counter, 1, 1)
        body.addLayout(counters_grid, 2)

        layout.addLayout(body, 1)

        tiers_row = QHBoxLayout()
        tiers_row.setSpacing(16)
        for tier in Tier:
            tiers_row.addWidget(TierCard(tier))
        layout.addLayout(tiers_row)
        layout.addStretch(1)

    def _build_header(self) -> QHBoxLayout:
        """Build the brand header with logo, title and analyzer status."""
        header = QHBoxLayout()
        header.setSpacing(12)

        logo = QLabel()
        pixmap = QPixmap(str(LOGO_PATH))
        if not pixmap.isNull():
            logo.setPixmap(
                pixmap.scaledToHeight(
                    48, Qt.TransformationMode.SmoothTransformation
                )
            )
        header.addWidget(logo)

        title = QLabel(APP_NAME)
        title.setObjectName("brandTitle")
        header.addWidget(title)
        header.addStretch(1)

        self._status_dot = QLabel()
        self._status_dot.setObjectName("statusDot")
        self._status_dot.setProperty("state", "offline")
        self._status_label = QLabel(STATUS_CAPTIONS["offline"])
        self._status_label.setObjectName("muted")
        header.addWidget(self._status_dot)
        header.addWidget(self._status_label)
        return header

    def set_analyzer_status(self, state: str) -> None:
        """Set the analyzer indicator to ``llm``, ``fallback`` or ``offline``."""
        normalized = state if state in STATUS_CAPTIONS else "offline"
        self._status_dot.setProperty("state", normalized)
        self._status_dot.style().unpolish(self._status_dot)
        self._status_dot.style().polish(self._status_dot)
        self._status_label.setText(STATUS_CAPTIONS[normalized])

    def update_state(
        self,
        scan: ScanInput | None,
        analysis: AnalysisOutput | None,
    ) -> None:
        """Refresh gauge and counters from the current scan and analysis."""
        self._empty_label.setVisible(scan is None)
        if scan is None:
            self._gauge.setValue(None)
            for counter in (
                self._hosts_counter,
                self._ports_counter,
                self._cves_counter,
                self._chains_counter,
            ):
                counter.setValue(0)
            return

        risk = analysis.risk_score if analysis is not None else scan.risk_score
        self._gauge.setValue(risk)
        self._hosts_counter.setValue(len(scan.hosts))
        self._ports_counter.setValue(sum(len(host.open_ports()) for host in scan.hosts))
        self._cves_counter.setValue(len(scan.vulnerabilities))
        chains = len(analysis.attack_chains) if analysis is not None else 0
        self._chains_counter.setValue(chains)

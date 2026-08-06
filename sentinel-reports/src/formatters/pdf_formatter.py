"""PDF report formatter.

Primary engine: WeasyPrint — renders the branded Jinja2 HTML template
(dark-steel print design, A4) to PDF. This is the production path.

Fallback engine: fpdf2 — a pure-Python renderer behind the same
:func:`render_pdf` interface, used when ``import weasyprint`` fails (for
example when the pango/cairo system libraries are unavailable), so PDFs
still generate in every environment.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from src.generator import AgentReport, AnalysisOutput, ScanInput

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
ASSETS_DIR = TEMPLATES_DIR / "assets"
LOGO_EMBED = ASSETS_DIR / "logo-embed.png"

try:  # Primary engine (kept in requirements.txt).
    import weasyprint as _weasyprint

    _WEASY_IMPORT_ERROR: BaseException | None = None
except Exception as exc:  # noqa: BLE001 — ImportError/OSError when system libs are missing.
    _weasyprint = None  # type: ignore[assignment]
    _WEASY_IMPORT_ERROR = exc
    logger.warning("WeasyPrint unavailable (%s); PDF engine falls back to fpdf2.", exc)

PDF_ENGINE = "weasyprint" if _weasyprint is not None else "fpdf2"

# SPEC.md four-tier metadata (threat profile / compliance baseline / SLA).
TIER_META: dict[str, dict[str, str]] = {
    "daily": {
        "threat": "Worms, script kiddies",
        "compliance": "CIS Controls v8 L1",
        "sla": "30 days (critical)",
    },
    "authority": {
        "threat": "Organized cybercrime",
        "compliance": "NIST 800-53 Moderate, ISO 27001",
        "sla": "7 days (critical)",
    },
    "hacker": {
        "threat": "APT, red teams",
        "compliance": "NIST 800-53 High, MITRE ATT&CK",
        "sla": "24 hours (critical)",
    },
    "military": {
        "threat": "Nation-state",
        "compliance": "NSA/CSS, TEMPEST, CNSS 1253",
        "sla": "Immediate / airgap",
    },
}

# Dark-steel palette (RGB).
_STEEL_950 = (11, 15, 20)
_STEEL_900 = (18, 24, 33)
_STEEL_800 = (27, 36, 48)
_STEEL_600 = (46, 58, 72)
_STEEL_TEXT = (159, 179, 200)
_ACCENT = (56, 189, 248)
_ACCENT_DARK = (12, 127, 184)
_INK = (26, 34, 44)
_MUTED = (91, 107, 124)
_PANEL = (242, 245, 248)
_WHITE = (255, 255, 255)
_BORDER = (216, 224, 232)
_RISK_COLORS = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "medium": (202, 138, 4),
    "low": (22, 163, 74),
}


def pdf_engine() -> str:
    """Return the name of the PDF engine in use (``weasyprint`` or ``fpdf2``)."""
    return PDF_ENGINE


def risk_label(score: float) -> str:
    """Human-readable risk band for a 0-10 risk score."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def risk_color(score: float) -> str:
    """Hex colour for the risk band of a 0-10 score (used by the template)."""
    rgb = _RISK_COLORS[risk_label(score)]
    return "#{:02X}{:02X}{:02X}".format(*rgb)


def cvss_class(score: float) -> str:
    """CSS badge class for a CVSS base score."""
    return risk_label(score)


def fmt_dt(value: Any) -> str:
    """Format an RFC3339 timestamp (datetime or str) for display."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return str(value)


def open_port_count(scan: ScanInput) -> int:
    """Total number of open ports observed across all hosts."""
    return sum(1 for host in scan.hosts for port in host.ports if port.state == "open")


def render_html(scan: ScanInput, analysis: AnalysisOutput, agent: AgentReport | None = None) -> str:
    """Render the branded report HTML from the Jinja2 templates."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(("html", "xml")),
    )
    template = env.get_template("report.html")
    return template.render(
        scan=scan,
        analysis=analysis,
        agent=agent,
        tiers=list(TIER_META.items()),
        open_port_count=open_port_count(scan),
        generated_at=fmt_dt(datetime.now().astimezone()),
        fmt_dt=fmt_dt,
        risk_label=risk_label,
        risk_color=risk_color,
        cvss_class=cvss_class,
    )


def render_pdf(
    scan: ScanInput,
    analysis: AnalysisOutput,
    out_path: str,
    agent: AgentReport | None = None,
) -> str:
    """Render the PDF report to ``out_path`` and return the path.

    Uses WeasyPrint when importable; otherwise the pure-Python fpdf2
    renderer behind the same interface.
    """
    if _weasyprint is not None:
        try:
            return _render_pdf_weasy(scan, analysis, out_path, agent=agent)
        except Exception:
            logger.exception("WeasyPrint render failed; falling back to fpdf2.")
    return _render_pdf_fpdf(scan, analysis, out_path, agent=agent)


def _render_pdf_weasy(
    scan: ScanInput, analysis: AnalysisOutput, out_path: str, agent: AgentReport | None = None
) -> str:
    """WeasyPrint path: full branded HTML/CSS rendering."""
    assert _weasyprint is not None
    html = render_html(scan, analysis, agent=agent)
    _weasyprint.HTML(string=html, base_url=str(TEMPLATES_DIR) + "/").write_pdf(out_path)
    return out_path


# ---------------------------------------------------------------------------
# fpdf2 fallback renderer (pure Python, same function interface)
# ---------------------------------------------------------------------------

_LATIN_REPLACEMENTS = {
    "—": "-", "–": "-", "‑": "-",
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "•": "*", "→": "->", "·": "-", "…": "...", "×": "x",
    "≥": ">=", "≤": "<=", " ": " ",
}


def _latin(text: Any) -> str:
    """Map common Unicode punctuation to Latin-1 for core PDF fonts."""
    s = str(text)
    for src, dst in _LATIN_REPLACEMENTS.items():
        s = s.replace(src, dst)
    return s.encode("latin-1", errors="replace").decode("latin-1")


def _wrap(pdf: Any, text: Any, width: float) -> list[str]:
    """Word-wrap ``text`` to ``width`` (mm) using core-font metrics."""
    lines: list[str] = []
    for paragraph in str(text).split("\n"):
        current = ""
        for word in paragraph.split(" "):
            trial = word if not current else f"{current} {word}"
            if pdf.get_string_width(_latin(trial)) <= max(width, 5.0):
                current = trial
            else:
                if current:
                    lines.append(current)
                current = word
        lines.append(current)
    return lines or [""]


def _render_pdf_fpdf(
    scan: ScanInput,
    analysis: AnalysisOutput,
    out_path: str,
    agent: AgentReport | None = None,
) -> str:
    """fpdf2 path: programmatic dark-steel report (no system libs needed)."""
    from fpdf import FPDF

    content_w = 178.0  # A4 width minus 16mm side margins

    class ReportPDF(FPDF):
        def footer(self) -> None:
            if self.page_no() == 1:  # full-bleed cover carries no footer
                return
            self.set_y(-14)
            self.set_font("helvetica", "", 7.5)
            self.set_text_color(*_MUTED)
            self.cell(100, 5, _latin("SENTINEL - Vulnerability Assessment Report"))
            self.cell(78, 5, f"Page {self.page_no()}/{{nb}}", align="R")

    pdf = ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_margins(16, 20, 16)
    pdf.set_auto_page_break(True, margin=18)
    pdf.alias_nb_pages()

    def section(title: str) -> None:
        if pdf.get_y() > pdf.page_break_trigger - 34:
            pdf.add_page()
        pdf.ln(2)
        pdf.set_font("helvetica", "B", 14)
        pdf.set_text_color(*_STEEL_900)
        pdf.cell(0, 8, _latin(title).upper(), new_x="LMARGIN", new_y="NEXT")
        pdf.set_fill_color(*_ACCENT)
        pdf.rect(pdf.l_margin, pdf.get_y() + 0.4, content_w, 0.7, "F")
        pdf.ln(4)

    def table(headers: list[str], rows: list[list[str]], widths: list[float]) -> None:
        x0 = pdf.l_margin
        pdf.set_font("helvetica", "B", 7.5)
        pdf.set_fill_color(*_STEEL_800)
        pdf.set_text_color(*_WHITE)
        pdf.set_x(x0)
        for header, width in zip(headers, widths, strict=True):
            pdf.cell(width, 6, _latin(header).upper(), fill=True)
        pdf.ln(6)
        zebra = False
        for row in rows:
            pdf.set_font("helvetica", "", 8.5)
            wrapped = [_wrap(pdf, cell, width - 3) for cell, width in zip(row, widths, strict=True)]
            row_h = max(len(lines) for lines in wrapped) * 4.4 + 1.8
            if pdf.get_y() + row_h > pdf.page_break_trigger:
                pdf.add_page()
            y = pdf.get_y()
            pdf.set_fill_color(*(_PANEL if zebra else _WHITE))
            pdf.rect(x0, y, sum(widths), row_h, "F")
            pdf.set_draw_color(*_BORDER)
            pdf.line(x0, y + row_h, x0 + sum(widths), y + row_h)
            x = x0
            pdf.set_text_color(*_INK)
            for lines, width in zip(wrapped, widths, strict=True):
                for i, line in enumerate(lines):
                    pdf.set_xy(x + 1.5, y + 0.9 + i * 4.4)
                    pdf.cell(width - 3, 4.4, _latin(line))
                x += width
            pdf.set_xy(x0, y + row_h)
            zebra = not zebra

    # ---------------- cover ----------------
    pdf.add_page()
    pdf.set_fill_color(*_STEEL_950)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_fill_color(*_STEEL_800)
    pdf.rect(0, 96, 210, 1.1, "F")
    if LOGO_EMBED.exists():
        pdf.image(str(LOGO_EMBED), x=22, y=26, w=44)
    pdf.set_xy(22, 80)
    pdf.set_font("helvetica", "B", 32)
    pdf.set_text_color(*_WHITE)
    brand_w = pdf.get_string_width("SENTINEL")
    pdf.cell(brand_w + 1.5, 12, "SENTINEL")
    pdf.set_text_color(*_ACCENT)
    pdf.cell(8, 12, ".")
    pdf.set_xy(22, 101.5)
    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(*_STEEL_TEXT)
    pdf.cell(0, 6, _latin("VULNERABILITY ASSESSMENT REPORT"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_fill_color(*_ACCENT)
    pdf.rect(22, pdf.get_y() + 4, 42, 0.8, "F")
    pdf.ln(12)

    meta = [
        ("Scan ID", scan.scan_id),
        ("Target", scan.target),
        ("Security Tier", scan.tier.upper()),
        ("Scan Window", f"{fmt_dt(scan.started_at)} - {fmt_dt(scan.finished_at)}"),
        ("Report Date", fmt_dt(datetime.now().astimezone())),
        ("Analysis Mode", analysis.analyzer_mode.upper()),
    ]
    y = pdf.get_y()
    for key, value in meta:
        pdf.set_xy(22, y)
        pdf.set_font("helvetica", "", 7.5)
        pdf.set_text_color(*_STEEL_TEXT)
        pdf.cell(40, 7, _latin(key).upper())
        pdf.set_font("courier" if key in {"Scan ID", "Target"} else "helvetica", "B", 10)
        pdf.set_text_color(230, 237, 243)
        pdf.cell(120, 7, _latin(value))
        pdf.set_draw_color(*_STEEL_600)
        pdf.line(22, y + 7.6, 180, y + 7.6)
        y += 9
    pdf.set_xy(22, 272)
    pdf.set_draw_color(*_STEEL_600)
    pdf.line(22, 270, 188, 270)
    pdf.set_font("helvetica", "", 7)
    pdf.set_text_color(*_MUTED)
    pdf.cell(
        0,
        5,
        _latin(f"SENTINEL SECURITY ASSESSMENT - HANDLE PER THE {scan.tier.upper()} TIER POLICY"),
    )

    # ---------------- executive summary ----------------
    pdf.add_page()
    section("Executive Summary")
    box_x, box_y, box_w, box_h = pdf.l_margin, pdf.get_y(), 52.0, 30.0
    pdf.set_fill_color(*_STEEL_900)
    pdf.rect(box_x, box_y, box_w, box_h, "F")
    pdf.set_xy(box_x, box_y + 3.5)
    pdf.set_font("helvetica", "", 7)
    pdf.set_text_color(*_STEEL_TEXT)
    pdf.cell(box_w, 4, "OVERALL RISK SCORE", align="C")
    pdf.set_xy(box_x, box_y + 8.5)
    pdf.set_font("helvetica", "B", 24)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(box_w, 11, f"{scan.risk_score:.2f}", align="C")
    pdf.set_xy(box_x, box_y + 21.5)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(*_RISK_COLORS[risk_label(scan.risk_score)])
    pdf.cell(box_w, 5, _latin(f"{risk_label(scan.risk_score).upper()} RISK"), align="C")

    summary = (
        f"Assessment of {scan.target} at the {scan.tier} tier identified "
        f"{len(scan.vulnerabilities)} CVE finding(s) and "
        f"{len(scan.posture_findings)} exposure(s) without a CVE match "
        f"across {len(scan.hosts)} hosts."
    )
    if not scan.vulnerabilities and scan.posture_findings:
        summary += (
            " Zero CVE matches is not zero risk: the scanner only matches its "
            "embedded signature set, and the exposure findings below are scored "
            "independently of it."
        )
    if analysis.attack_chains:
        summary += (
            f" The analyzer derived {len(analysis.attack_chains)} attack chain(s)"
            " from the observed exposure."
        )
    notes_x = box_x + box_w + 6
    pdf.set_xy(notes_x, box_y)
    pdf.set_font("helvetica", "", 9.5)
    pdf.set_text_color(*_INK)
    pdf.multi_cell(content_w - box_w - 6, 4.8, _latin(summary))
    for obs in analysis.observations:
        pdf.set_x(notes_x)
        pdf.multi_cell(content_w - box_w - 6, 4.8, _latin(f"- {obs}"))
    pdf.set_y(box_y + box_h + 4)

    # ---------------- scope summary ----------------
    section("Scope Summary")
    scope_rows = [
        ["Target scope", scan.target],
        ["Security tier", scan.tier.upper()],
        ["Scan started", fmt_dt(scan.started_at)],
        ["Scan finished", fmt_dt(scan.finished_at)],
        ["Hosts discovered", str(len(scan.hosts))],
        ["Open ports observed", str(open_port_count(scan))],
        ["Vulnerabilities matched", str(len(scan.vulnerabilities))],
        ["Exposures (no CVE match)", str(len(scan.posture_findings))],
        ["Scan risk score", f"{scan.risk_score:.2f} / 10.00"],
        ["Analysis risk score", f"{analysis.risk_score:.2f} / 10.00"],
        [
            "Detection coverage",
            (
                f"CVE signature DB v{scan.cve_db.version} "
                f"({scan.cve_db.signatures} signatures); EPSS v4 (30-day); "
                "CISA KEV floor 9.0"
            ),
        ],
    ]
    table(["Attribute", "Value"], scope_rows, [40.0, 138.0])

    # ---------------- hosts ----------------
    section("Hosts")
    if scan.hosts:
        host_rows = []
        for host in scan.hosts:
            open_ports = [str(p.port) for p in host.ports if p.state == "open"]
            host_rows.append(
                [
                    host.ip,
                    host.hostname or "-",
                    host.os_guess or "-",
                    host.trust_zone,
                    host.criticality,
                    ", ".join(open_ports) if open_ports else "none",
                ]
            )
        table(
            ["IP Address", "Hostname", "OS Guess", "Zone", "Criticality", "Open Ports"],
            host_rows,
            [30.0, 30.0, 36.0, 20.0, 24.0, 38.0],
        )
    else:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(0, 5, _latin("No live hosts were discovered within the target scope."))

    # ---------------- vulnerabilities ----------------
    section("Vulnerabilities")
    if scan.vulnerabilities:
        vuln_rows = [
            [
                v.cve_id,
                f"{v.cvss:.1f}",
                f"{v.epss:.2f}",
                f"{v.host}:{v.port}",
                v.summary or "-",
            ]
            for v in sorted(scan.vulnerabilities, key=lambda v: v.cvss, reverse=True)
        ]
        table(
            ["CVE", "CVSS", "EPSS", "Endpoint", "Summary"],
            vuln_rows,
            [30.0, 13.0, 13.0, 34.0, 88.0],
        )
    else:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(
            0,
            5,
            _latin(
                "No known vulnerabilities were matched against the discovered services. "
                "This is signature coverage, not proof of safety - see the exposure "
                "findings below."
            ),
        )

    # ---------------- exposures (no CVE match) ----------------
    section("Exposures (No CVE Match)")
    pdf.set_font("helvetica", "I", 8.5)
    pdf.set_text_color(*_MUTED)
    pdf.multi_cell(
        0,
        4.6,
        _latin(
            "Configuration and exposure weaknesses observed by active probing. These "
            "have no CVE identifier; they are scored through the same deterministic "
            "formula with EPSS = 0."
        ),
    )
    pdf.ln(1.5)
    if scan.posture_findings:
        posture_rows = [
            [
                p.id,
                f"{p.severity:.1f}",
                f"{p.host}:{p.port}",
                p.title or "-",
                p.evidence or "-",
            ]
            for p in sorted(scan.posture_findings, key=lambda p: p.severity, reverse=True)
        ]
        table(
            ["Finding", "Sev", "Endpoint", "Title", "Evidence"],
            posture_rows,
            [34.0, 11.0, 30.0, 46.0, 57.0],
        )
    else:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(0, 5, _latin("No exposure findings without a CVE match were observed."))

    # ---------------- agent investigation ----------------
    if agent is not None:
        section("Agent Investigation")
        pdf.set_font("helvetica", "I", 8.5)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(
            0,
            4.6,
            _latin(
                f"Autonomous investigation (model: {agent.model}). Every finding cites "
                "probe evidence from the investigation transcript; severities are fixed "
                "per finding class and scored with EPSS = 0."
            ),
        )
        pdf.ln(1.5)
        if agent.findings:
            agent_rows = [
                [
                    f.id,
                    f.finding_class,
                    f"{f.severity:.1f}",
                    f"{f.host}:{f.port}",
                    f.title or "-",
                    ", ".join(f.evidence) if f.evidence else "-",
                ]
                for f in sorted(agent.findings, key=lambda f: f.severity, reverse=True)
            ]
            table(
                ["Finding", "Class", "Sev", "Endpoint", "Title", "Evidence"],
                agent_rows,
                [30.0, 26.0, 11.0, 28.0, 63.0, 20.0],
            )
        else:
            pdf.set_font("helvetica", "I", 9)
            pdf.set_text_color(*_MUTED)
            pdf.multi_cell(0, 5, _latin("The agent produced no findings."))

        if agent.investigations:
            pdf.ln(1.5)
            inv_rows = [
                [
                    f"{inv.host}:{','.join(str(p) for p in inv.ports)}",
                    inv.trigger,
                    inv.status,
                    str(inv.turns),
                    inv.summary or "-",
                ]
                for inv in agent.investigations
            ]
            table(
                ["Target", "Trigger", "Status", "Turns", "Summary"],
                inv_rows,
                [34.0, 24.0, 26.0, 12.0, 82.0],
            )

        if agent.drift:
            pdf.ln(1.5)
            pdf.set_font("helvetica", "B", 10)
            pdf.set_text_color(*_STEEL_900)
            pdf.cell(0, 6, _latin("Network drift since previous scan"), new_x="LMARGIN", new_y="NEXT")
            drift_rows = [
                [
                    d.kind,
                    f"{d.host}:{d.port}" if d.port is not None else d.host,
                    d.before or "-",
                    d.after or "-",
                ]
                for d in agent.drift
            ]
            table(["Change", "Endpoint", "Before", "After"], drift_rows, [34.0, 44.0, 50.0, 50.0])

    # ---------------- attack chains ----------------
    section("Attack Chains")
    if analysis.attack_chains:
        for chain in sorted(analysis.attack_chains, key=lambda c: c.priority):
            if pdf.get_y() > pdf.page_break_trigger - 30:
                pdf.add_page()
            pdf.set_draw_color(*_STEEL_600)
            pdf.set_fill_color(*_PANEL)

            def chain_line(height: float, text: str) -> None:
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(
                    0, height, _latin(text), border="L", new_x="LMARGIN", new_y="NEXT"
                )

            pdf.set_font("helvetica", "B", 9.5)
            pdf.set_text_color(*_STEEL_900)
            chain_line(5, f"Priority {chain.priority} - MITRE ATT&CK {chain.mitre_technique}")
            pdf.set_font("courier", "", 8.5)
            pdf.set_text_color(*_ACCENT_DARK)
            chain_line(4.6, " -> ".join(chain.path))
            pdf.set_font("helvetica", "", 8.5)
            pdf.set_text_color(*_MUTED)
            chain_line(4.6, f"Confidence {chain.confidence:.0%} - Impact {chain.impact:.0%}")
            pdf.set_font("helvetica", "", 9)
            pdf.set_text_color(*_INK)
            chain_line(4.8, chain.description)
            pdf.ln(2.5)
    else:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(
            0, 5, _latin("No multi-stage attack chains were derived from the scan evidence.")
        )

    # ---------------- tiered remediation ----------------
    section("Tiered Remediation Plan")
    for tier_name, info in TIER_META.items():
        actions: list[str] = list(getattr(analysis.remediation, tier_name))
        if pdf.get_y() > pdf.page_break_trigger - 40:
            pdf.add_page()
        x0 = pdf.l_margin
        pdf.set_fill_color(*_STEEL_800)
        pdf.set_text_color(*_WHITE)
        pdf.set_font("helvetica", "B", 9.5)
        pdf.set_x(x0)
        pdf.cell(content_w, 6.5, _latin(f"  {tier_name.upper()} TIER"), fill=True)
        pdf.ln(6.5)
        pdf.set_fill_color(*_PANEL)
        pdf.set_text_color(*_MUTED)
        pdf.set_font("helvetica", "", 8)
        pdf.set_x(x0)
        meta_line = (
            f"  Threat profile: {info['threat']}  |  Compliance baseline: "
            f"{info['compliance']}  |  Critical patch SLA: {info['sla']}"
        )
        pdf.cell(content_w, 5.5, _latin(meta_line), fill=True)
        pdf.ln(5.5)
        pdf.set_text_color(*_INK)
        pdf.set_font("helvetica", "", 9)
        if actions:
            for action in actions:
                pdf.set_x(x0 + 2)
                pdf.multi_cell(content_w - 4, 4.8, _latin(f"- {action}"))
        else:
            pdf.set_x(x0 + 2)
            pdf.set_font("helvetica", "I", 9)
            pdf.set_text_color(*_MUTED)
            pdf.multi_cell(content_w - 4, 4.8, _latin("No additional controls required."))
        pdf.ln(2.5)

    pdf.output(out_path)
    return out_path

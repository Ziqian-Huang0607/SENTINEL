"""SARIF 2.1.0 report formatter.

Rules are derived from the CVEs in the scan (helpUri points to NVD);
results are the individual findings. Level mapping: CVSS >= 9 -> error,
CVSS >= 7 -> warning, otherwise note.
"""

from __future__ import annotations

import json
from typing import Any

from src import __version__
from src.generator import AnalysisOutput, ScanInput, Vulnerability

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
NVD_HELP_URI = "https://nvd.nist.gov/vuln/detail/{cve_id}"


def level_for_cvss(cvss: float) -> str:
    """Map a CVSS base score to a SARIF result level."""
    if cvss >= 9.0:
        return "error"
    if cvss >= 7.0:
        return "warning"
    return "note"


def _rule_for(vuln: Vulnerability) -> dict[str, Any]:
    """Build a SARIF rule object for a CVE."""
    level = level_for_cvss(vuln.cvss)
    return {
        "id": vuln.cve_id,
        "name": vuln.cve_id,
        "shortDescription": {"text": f"{vuln.cve_id} (CVSS {vuln.cvss:.1f})"},
        "fullDescription": {"text": vuln.summary or vuln.cve_id},
        "helpUri": NVD_HELP_URI.format(cve_id=vuln.cve_id),
        "defaultConfiguration": {"level": level},
        "properties": {
            "cvss": vuln.cvss,
            "epss": vuln.epss,
            "security-severity": f"{vuln.cvss:.1f}",
            "tags": ["security", "cve"],
        },
    }


def _result_for(vuln: Vulnerability) -> dict[str, Any]:
    """Build a SARIF result object for a single finding."""
    message = vuln.summary or f"{vuln.cve_id} detected"
    return {
        "ruleId": vuln.cve_id,
        "level": level_for_cvss(vuln.cvss),
        "message": {"text": f"{message} Affected endpoint: {vuln.host}:{vuln.port}."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"{vuln.host}:{vuln.port}"},
                }
            }
        ],
        "properties": {
            "cvss": vuln.cvss,
            "epss": vuln.epss,
            "host": vuln.host,
            "port": vuln.port,
        },
    }


def build_sarif(scan: ScanInput, analysis: AnalysisOutput) -> dict[str, Any]:
    """Build the SARIF 2.1.0 log document for a scan."""
    rules: dict[str, dict[str, Any]] = {}
    for vuln in scan.vulnerabilities:
        rules.setdefault(vuln.cve_id, _rule_for(vuln))
    results = [_result_for(vuln) for vuln in scan.vulnerabilities]
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SENTINEL",
                        "version": __version__,
                        "informationUri": "https://sentinel.local/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "scanId": scan.scan_id,
                    "target": scan.target,
                    "tier": scan.tier,
                    "riskScore": scan.risk_score,
                    "analyzerMode": analysis.analyzer_mode,
                },
            }
        ],
    }


def render_sarif(scan: ScanInput, analysis: AnalysisOutput, out_path: str) -> str:
    """Write the scan findings as a SARIF 2.1.0 log file.

    Args:
        scan: Validated scanner output.
        analysis: Validated analyzer output.
        out_path: Destination file path.

    Returns:
        The path written to.
    """
    document = build_sarif(scan, analysis)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return out_path

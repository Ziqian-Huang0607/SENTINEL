"""CONFIRM scope gate + audit log tests (agent-spec.md section 10).

The audit line must match sentinel-cli's schema exactly (one JSON object per
line: timestamp, target, tier, confirm_method, outcome).
"""

from __future__ import annotations

import json
from pathlib import Path

from src.__main__ import scope_gate


def _read_audit(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_yes_flag_confirms_and_audits(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "audit.log"))
    assert scope_gate("192.168.1.0/24", "hacker", assume_yes=True) is True
    entries = _read_audit(tmp_path / "audit.log")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["target"] == "192.168.1.0/24"
    assert entry["tier"] == "hacker"
    assert entry["confirm_method"] == "--yes"
    assert entry["outcome"] == "confirmed"
    assert "timestamp" in entry


def test_typed_confirm_authorizes(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": "CONFIRM")
    assert scope_gate("10.0.0.0/24", "daily", assume_yes=False) is True
    entry = _read_audit(tmp_path / "audit.log")[0]
    assert entry["confirm_method"] == "typed-CONFIRM"
    assert entry["outcome"] == "confirmed"


def test_wrong_typing_aborts_and_is_logged(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": "confirm")  # lowercase
    assert scope_gate("192.168.1.0/24", "military", assume_yes=False) is False
    entry = _read_audit(tmp_path / "audit.log")[0]
    assert entry["confirm_method"] == "typed-CONFIRM"
    assert entry["outcome"] == "aborted"


def test_eof_at_prompt_aborts_safely(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "audit.log"))

    def _raise_eof(_prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)
    assert scope_gate("192.168.1.0/24", "daily", assume_yes=False) is False
    assert _read_audit(tmp_path / "audit.log")[0]["outcome"] == "aborted"

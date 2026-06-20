"""Unit tests for the saferead installer/updater (INST-01).

Covers idempotency, merge-preserve, backup creation, path-drift update, target
selection, the lazy-import hot-path invariant, and best-effort update behavior.
"""

from __future__ import annotations

import json
import subprocess
import sys

from saferead.install import _merge_hook, install_main, update_main


def _bash_hooks(data: dict) -> list:
    """Return the hooks[] list of the PreToolUse Bash matcher block (or [])."""
    for elem in data.get("hooks", {}).get("PreToolUse", []):
        if elem.get("matcher") == "Bash":
            return elem.get("hooks", [])
    return []


def _saferead_entries(data: dict) -> list:
    return [h for h in _bash_hooks(data) if h.get("command", "").endswith("saferead")]


def _install_to(monkeypatch, target) -> None:
    """Invoke install_main() with argv pointed at ``target`` (bare-path arg)."""
    monkeypatch.setattr(sys, "argv", ["saferead", "install", str(target)])
    install_main()


def test_install_absent_settings_creates_fresh(monkeypatch, tmp_path) -> None:
    target = tmp_path / "settings.json"
    _install_to(monkeypatch, target)

    data = json.loads(target.read_text(encoding="utf-8"))
    entries = _saferead_entries(data)
    assert len(entries) == 1
    assert entries[0]["type"] == "command"
    assert entries[0]["command"].endswith("saferead")


def test_install_idempotent_same_path(monkeypatch, tmp_path) -> None:
    target = tmp_path / "settings.json"
    _install_to(monkeypatch, target)
    _install_to(monkeypatch, target)  # second run = no-op

    data = json.loads(target.read_text(encoding="utf-8"))
    assert len(_saferead_entries(data)) == 1


def test_install_updates_stale_path(monkeypatch, tmp_path) -> None:
    target = tmp_path / "settings.json"
    target.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "/old/location/saferead"}
                            ],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    _install_to(monkeypatch, target)

    data = json.loads(target.read_text(encoding="utf-8"))
    entries = _saferead_entries(data)
    assert len(entries) == 1
    assert entries[0]["command"] != "/old/location/saferead"  # updated in place


def test_install_preserves_existing_hooks(monkeypatch, tmp_path) -> None:
    target = tmp_path / "settings.json"
    target.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "/usr/local/bin/dcg"}
                            ],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    _install_to(monkeypatch, target)

    hooks = _bash_hooks(json.loads(target.read_text(encoding="utf-8")))
    commands = [h["command"] for h in hooks]
    assert "/usr/local/bin/dcg" in commands  # dcg preserved
    assert commands[0] == "/usr/local/bin/dcg"  # dcg ordered before saferead
    assert any(c.endswith("saferead") for c in commands)


def test_install_backup_created(monkeypatch, tmp_path) -> None:
    target = tmp_path / "settings.json"
    target.write_text(json.dumps({"hooks": {}}), encoding="utf-8")
    _install_to(monkeypatch, target)

    backups = list(tmp_path.glob("settings.json.bak.*"))
    assert len(backups) == 1


def test_install_no_backup_for_absent_file(monkeypatch, tmp_path) -> None:
    target = tmp_path / "settings.json"
    _install_to(monkeypatch, target)

    assert list(tmp_path.glob("settings.json.bak.*")) == []


def test_merge_existing_bash_block_used(monkeypatch, tmp_path) -> None:
    target = tmp_path / "settings.json"
    target.write_text(
        json.dumps(
            {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]}}
        ),
        encoding="utf-8",
    )
    _install_to(monkeypatch, target)

    data = json.loads(target.read_text(encoding="utf-8"))
    bash_blocks = [
        e for e in data["hooks"]["PreToolUse"] if e.get("matcher") == "Bash"
    ]
    assert len(bash_blocks) == 1  # no duplicate Bash matcher
    assert len(_saferead_entries(data)) == 1


def test_merge_hook_returns_false_when_unchanged() -> None:
    data: dict = {}
    assert _merge_hook(data, "/bin/saferead") is True
    assert _merge_hook(data, "/bin/saferead") is False  # idempotent at unit level


def test_update_uv_absent_does_not_raise(monkeypatch) -> None:
    def _raise(*_a, **_k):
        raise FileNotFoundError("uv")

    monkeypatch.setattr(subprocess, "run", _raise)
    update_main()  # must return normally


def test_update_timeout_does_not_raise(monkeypatch) -> None:
    def _raise(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd=["uv"], timeout=60)

    monkeypatch.setattr(subprocess, "run", _raise)
    update_main()  # must return normally


def test_install_is_not_imported_on_hook_path() -> None:
    """Importing saferead.cli must NOT trigger importing saferead.install (D-07 hot path).

    Runs in a fresh subprocess so it is unaffected by this test module having
    already imported saferead.install at the top level.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import saferead.cli, sys; "
            "sys.exit(1 if 'saferead.install' in sys.modules else 0)",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"saferead.install was imported on the hook path: {result.stderr}"
    )

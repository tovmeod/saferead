"""Unit tests for the saferead installer/updater (INST-01).

Covers idempotency, merge-preserve, backup creation, path-drift update, target
selection, the lazy-import hot-path invariant, and best-effort update behavior.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from saferead.install import (
    _merge_hook,
    _select_target,
    install_main,
)


def _bash_hooks(data: dict) -> list:
    """Return the hooks[] list of the PreToolUse Bash matcher block (or [])."""
    for elem in data.get("hooks", {}).get("PreToolUse", []):
        if elem.get("matcher") == "Bash":
            return elem.get("hooks", [])
    return []


def _saferead_entries(data: dict) -> list:
    return [h for h in _bash_hooks(data) if h.get("command", "").endswith("saferead")]


def _install_to(monkeypatch, target) -> None:
    """Invoke install_main() with argv pointed at ``target`` (bare-path arg).

    NOTE (Phase 20): after Plan 20-02 lands, install_main() calls subprocess.run
    (bootstrap + permanent-path resolution). The existing tests that use this
    helper get subprocess mocking wired in via the ``fake_subprocess`` fixture
    added in Plan 20-02 — this plan (20-01) leaves them GREEN against the current
    (no-subprocess) install_main().
    """
    monkeypatch.setattr(sys, "argv", ["saferead", "install", str(target)])
    install_main()


def _fake_subprocess_run_success(tmp_path):
    """Return ``(fake_binary, fake_run)`` mocking the bootstrap + path-resolution.

    ``fake_run`` answers ``uv tool install saferead --upgrade`` (returncode 0) and
    ``uv tool dir --bin`` (stdout = the fake bin dir); the fake ``saferead`` binary
    is created so ``_detect_saferead_path()``'s ``candidate.exists()`` check passes.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake_binary = bin_dir / "saferead"
    fake_binary.touch()

    def _fake(argv, **kwargs):
        if list(argv)[:3] == ["uv", "tool", "install"]:
            return subprocess.CompletedProcess(
                argv, returncode=0, stdout="", stderr="Installed 1 executable: saferead"
            )
        if list(argv)[:3] == ["uv", "tool", "dir"]:
            return subprocess.CompletedProcess(
                argv, returncode=0, stdout=str(bin_dir) + "\n", stderr=""
            )
        raise AssertionError(f"unexpected subprocess.run call: {argv}")

    return fake_binary, _fake


@pytest.fixture
def fake_subprocess(tmp_path, monkeypatch):
    """Patch subprocess.run for install_main()'s bootstrap + path-resolution calls.

    After Plan 20-02, install_main() shells out to ``uv tool install saferead
    --upgrade`` and ``uv tool dir --bin``. Any test that calls install_main() (or
    _install_to) must apply this fixture so those calls are mocked — otherwise the
    test would run real uv commands against the network. Returns the fake binary
    path so a test can assert the written hook command if needed.
    """
    fake_binary, fake_run = _fake_subprocess_run_success(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake_run)
    return fake_binary


def test_install_absent_settings_creates_fresh(
    monkeypatch, tmp_path, fake_subprocess
) -> None:
    target = tmp_path / "settings.json"
    _install_to(monkeypatch, target)

    data = json.loads(target.read_text(encoding="utf-8"))
    entries = _saferead_entries(data)
    assert len(entries) == 1
    assert entries[0]["type"] == "command"
    assert entries[0]["command"].endswith("saferead")


def test_install_idempotent_same_path(monkeypatch, tmp_path, fake_subprocess) -> None:
    target = tmp_path / "settings.json"
    _install_to(monkeypatch, target)
    _install_to(monkeypatch, target)  # second run = no-op

    data = json.loads(target.read_text(encoding="utf-8"))
    assert len(_saferead_entries(data)) == 1


def test_install_updates_stale_path(monkeypatch, tmp_path, fake_subprocess) -> None:
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


def test_install_preserves_existing_hooks(
    monkeypatch, tmp_path, fake_subprocess
) -> None:
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


def test_install_backup_created(monkeypatch, tmp_path, fake_subprocess) -> None:
    target = tmp_path / "settings.json"
    target.write_text(json.dumps({"hooks": {}}), encoding="utf-8")
    _install_to(monkeypatch, target)

    backups = list(tmp_path.glob("settings.json.bak.*"))
    assert len(backups) == 1


def test_install_no_backup_for_absent_file(
    monkeypatch, tmp_path, fake_subprocess
) -> None:
    target = tmp_path / "settings.json"
    _install_to(monkeypatch, target)

    assert list(tmp_path.glob("settings.json.bak.*")) == []


def test_merge_existing_bash_block_used(monkeypatch, tmp_path, fake_subprocess) -> None:
    target = tmp_path / "settings.json"
    target.write_text(
        json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]}}),
        encoding="utf-8",
    )
    _install_to(monkeypatch, target)

    data = json.loads(target.read_text(encoding="utf-8"))
    bash_blocks = [e for e in data["hooks"]["PreToolUse"] if e.get("matcher") == "Bash"]
    assert len(bash_blocks) == 1  # no duplicate Bash matcher
    assert len(_saferead_entries(data)) == 1


def test_merge_hook_returns_false_when_unchanged() -> None:
    data: dict = {}
    assert _merge_hook(data, "/bin/saferead") is True
    assert _merge_hook(data, "/bin/saferead") is False  # idempotent at unit level


def test_install_is_not_imported_on_hook_path() -> None:
    """Importing saferead.cli must NOT import saferead.install (D-07 hot path).

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


def test_select_target_no_arg_is_global(monkeypatch, tmp_path) -> None:
    """No-arg resolves to the global settings path — no interactive prompt."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert _select_target([]) == tmp_path / ".claude" / "settings.json"


def test_select_target_project_flag(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    assert _select_target(["--project"]) == tmp_path / ".claude" / "settings.json"


def test_select_target_explicit_path(tmp_path) -> None:
    p = tmp_path / "custom.json"
    assert _select_target([str(p)]) == p.resolve()


def test_install_no_arg_writes_global(monkeypatch, tmp_path, fake_subprocess) -> None:
    """No-arg `saferead install` installs into global settings, non-interactively."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["saferead", "install"])
    install_main()

    target = tmp_path / ".claude" / "settings.json"
    data = json.loads(target.read_text(encoding="utf-8"))
    assert len(_saferead_entries(data)) == 1


# ---------------------------------------------------------------------------
# Phase 20 (INST-01 corrected) — RED stubs for behaviors added by Plan 20-02.
# These fail against the current install.py/cli.py; Plan 20-02 turns them GREEN.
# ---------------------------------------------------------------------------


def test_bootstrap_invoked(monkeypatch, tmp_path) -> None:
    """install_main() must run `uv tool install saferead --upgrade` first (D-01)."""
    calls: list[list[str]] = []
    _fake_binary, fake_run = _fake_subprocess_run_success(tmp_path)

    def _record(argv, **kwargs):
        calls.append(list(argv))
        return fake_run(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", _record)
    monkeypatch.setattr(
        sys, "argv", ["saferead", "install", str(tmp_path / "settings.json")]
    )
    install_main()

    assert any(
        argv[:5] == ["uv", "tool", "install", "saferead", "--upgrade"] for argv in calls
    )


def test_hook_command_is_permanent_path(monkeypatch, tmp_path) -> None:
    """The written hook command is the permanent binary path, not an ephemeral one."""
    fake_binary, fake_run = _fake_subprocess_run_success(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake_run)
    target = tmp_path / "settings.json"
    monkeypatch.setattr(sys, "argv", ["saferead", "install", str(target)])
    install_main()

    data = json.loads(target.read_text(encoding="utf-8"))
    entries = _saferead_entries(data)
    assert len(entries) == 1
    command = entries[0]["command"]
    assert command == str(fake_binary)
    assert "cache" not in command
    assert "archive-v0" not in command


def test_select_target_tty_project_choice(monkeypatch, tmp_path) -> None:
    """On a TTY, answering [P] selects the project settings path (D-04)."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "p")
    monkeypatch.chdir(tmp_path)
    assert _select_target([]) == tmp_path / ".claude" / "settings.json"


def test_select_target_non_tty_defaults_global(monkeypatch, tmp_path) -> None:
    """Non-TTY stdin falls back to global without prompting or raising (D-04)."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert _select_target([]) == tmp_path / ".claude" / "settings.json"


def test_select_target_eof_defaults_global(monkeypatch, tmp_path) -> None:
    """A TTY whose input() hits EOF falls back to global, never raising (D-04)."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: (_ for _ in ()).throw(EOFError())
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    assert _select_target([]) == tmp_path / ".claude" / "settings.json"


def test_install_uv_absent_refuses_to_write(monkeypatch, tmp_path) -> None:
    """uv absent + no installed binary => exit non-zero, write nothing (D-06)."""

    def _raise(*_a, **_k):
        raise FileNotFoundError("uv")

    monkeypatch.setattr(subprocess, "run", _raise)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    target = tmp_path / "settings.json"
    monkeypatch.setattr(sys, "argv", ["saferead", "install", str(target)])

    with pytest.raises(SystemExit):
        install_main()

    assert not target.exists()


def test_install_bootstrap_failure_refuses_to_write(monkeypatch, tmp_path) -> None:
    """Bootstrap + dir both fail and no binary on PATH => exit, write nothing (D-06)."""

    def _fail(argv, **kwargs):
        return subprocess.CompletedProcess(argv, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", _fail)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    target = tmp_path / "settings.json"
    monkeypatch.setattr(sys, "argv", ["saferead", "install", str(target)])

    with pytest.raises(SystemExit):
        install_main()

    assert not target.exists()


def test_update_subcommand_removed(monkeypatch) -> None:
    """`saferead update` must NOT dispatch to update_main — the branch is gone (D-11).

    A tripwire on ``saferead.install.update_main`` (raising=False so it survives the
    function's deletion in Plan 20-02) records any call. Against the current cli.py
    the ``update`` branch calls it (RED); once Plan 20-02 removes the branch the
    tripwire stays untouched (GREEN). The literal "patch subprocess.run to raise"
    approach is non-discriminating here because update_main()'s broad ``except
    Exception`` swallows the injected error.
    """
    import saferead.cli

    called = {"hit": False}

    def _tripwire(*_a, **_k):
        called["hit"] = True

    monkeypatch.setattr("saferead.install.update_main", _tripwire, raising=False)
    monkeypatch.setattr(sys, "argv", ["saferead", "update"])
    saferead.cli.main()

    assert called["hit"] is False


def test_update_main_deleted() -> None:
    """`update_main` must no longer exist in saferead.install (D-11)."""
    with pytest.raises(ImportError):
        from saferead.install import update_main  # type: ignore  # noqa: F401

"""End-to-end tests for the exec-form entrypoint (PKG-05, CORE-06).

Runs ``hooks/safe_read_hook.py`` as a real subprocess feeding a JSON payload on
stdin and asserting the stdout envelope (or empty stdout). This exercises the
whole vertical slice: stdin -> split -> fold -> envelope.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_HOOK = Path(__file__).resolve().parent.parent / "hooks" / "safe_read_hook.py"


def _load_entrypoint_module():
    """Import hooks/safe_read_hook.py as a module WITHOUT running main().

    The script guards its ``main()`` call behind ``if __name__ == '__main__'``,
    so importing it under a non-``__main__`` name loads the module (and its
    ``_resolve_branch`` resolver) without firing a live subprocess.
    """
    spec = importlib.util.spec_from_file_location("_entrypoint_under_test", _HOOK)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(payload: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_HOOK)],
        input=payload,
        capture_output=True,
        text=True,
    )


def test_real_cat_payload_yields_allow_envelope() -> None:
    """The phase's E2E proof: a real cat foo.txt Bash payload -> allow envelope.

    Selectable via ``-k allow`` by name (VALIDATION map).
    """
    payload = json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "cat foo.txt"}, "cwd": "/x"}
    )
    result = _run(payload)
    assert result.returncode == 0
    parsed = json.loads(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "allow"


def test_compound_with_unsafe_segment_emits_nothing() -> None:
    """cat foo.txt && rm -rf x -> abstain -> empty stdout (the slice's veto, E2E)."""
    payload = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "cat foo.txt && rm -rf x"},
            "cwd": "/x",
        }
    )
    result = _run(payload)
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_non_bash_tool_emits_nothing() -> None:
    payload = json.dumps(
        {"tool_name": "Read", "tool_input": {"file_path": "foo.txt"}, "cwd": "/x"}
    )
    result = _run(payload)
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_empty_command_emits_nothing() -> None:
    payload = json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": ""}, "cwd": "/x"}
    )
    result = _run(payload)
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_malformed_json_emits_nothing_and_does_not_crash() -> None:
    result = _run("{not valid json")
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_entrypoint_injects_real_branch_resolver(monkeypatch) -> None:
    """The entrypoint builds Context with ``_resolver=_resolve_branch`` (D-03).

    Imports the entrypoint module (main() guarded, not auto-run), captures the
    ``_resolver`` kwarg the entrypoint passes to Context on a Bash payload, and
    asserts it IS the real ``_resolve_branch`` resolver. No live subprocess —
    the resolver is never called, only its identity is checked.
    """
    module = _load_entrypoint_module()
    captured: dict[str, object] = {}
    real_context = module.Context  # capture BEFORE patching (avoid self-recursion)

    def _capture_context(*, cwd, _resolver, config):
        captured["resolver"] = _resolver
        # Hand back a REAL Context so the entrypoint's fold() path runs normally.
        return real_context(cwd=cwd, _resolver=_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)

    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": "/x",
    }
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()

    assert captured["resolver"] is module._resolve_branch


class _StdinStub:
    def __init__(self, data: str) -> None:
        self._data = data

    def read(self) -> str:
        return self._data


# --- Phase 9: global config load + injection ------------------------------


def test_entrypoint_injects_resolved_global_config(monkeypatch, tmp_path) -> None:
    """A present global with protected=["release"] is injected into Context.config.

    Monkeypatches the module's global-config path to a temp file and captures the
    ``config`` kwarg the entrypoint passes to Context — asserts the resolved
    protected set is {"release"} (D-05 replace flows through the entrypoint).
    """
    module = _load_entrypoint_module()
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[git]\nprotected_branches = ["release"]\n', encoding="utf-8")
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", cfg_path)

    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": "/x"}
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()

    cfg = captured["config"]
    assert cfg.protected_branches == frozenset({"release"})


def test_entrypoint_absent_global_injects_builtin(monkeypatch, tmp_path) -> None:
    """No global config FILE -> the injected config equals builtin_config() (D-08)."""
    module = _load_entrypoint_module()
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", tmp_path / "does-not-exist.toml")

    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": "/x"}
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()

    from safe_read_hook.config import builtin_config

    assert captured["config"] == builtin_config()


def test_entrypoint_absent_protected_key_keeps_builtin(monkeypatch, tmp_path) -> None:
    """CARDINAL E2E: a global with only gated=["push"] keeps protected master/main.

    The absent-protected-key fallback wired through the entrypoint — a global that
    customizes only the gated set must NOT empty the protected set.
    """
    module = _load_entrypoint_module()
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[git]\ngated_subcommands = ["push"]\n', encoding="utf-8")
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", cfg_path)

    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": "/x"}
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()

    cfg = captured["config"]
    assert cfg.protected_branches == frozenset({"master", "main"})
    assert cfg.gated_subcommands == frozenset({"push"})


def test_entrypoint_malformed_global_degrades_to_builtin(monkeypatch, tmp_path) -> None:
    """A malformed global config degrades to builtin_config() — never crashes."""
    module = _load_entrypoint_module()
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("this is not = valid = toml [[[", encoding="utf-8")
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", cfg_path)

    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": "/x"}
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()  # must not raise

    from safe_read_hook.config import builtin_config

    assert captured["config"] == builtin_config()


def test_process_sub_payload_emits_nothing() -> None:
    """Live A1 closure: cat <(curl evil) routes through tokenize -> abstain.

    The structural <( trigger fires on the raw string in the live pipeline (not
    just a unit test), so the entrypoint emits nothing (CORE-02/D-15).
    """
    payload = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "cat <(curl evil)"},
            "cwd": "/x",
        }
    )
    result = _run(payload)
    assert result.returncode == 0
    assert result.stdout.strip() == ""

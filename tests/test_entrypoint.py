"""End-to-end tests for the exec-form entrypoint (PKG-05, CORE-06).

Runs ``hooks/safe_read_hook.py`` as a real subprocess feeding a JSON payload on
stdin and asserting the stdout envelope (or empty stdout). This exercises the
whole vertical slice: stdin -> split -> fold -> envelope.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
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

    def _capture_context(*, cwd, _resolver, _staged_resolver, config):
        captured["resolver"] = _resolver
        captured["staged_resolver"] = _staged_resolver
        # Hand back a REAL Context so the entrypoint's fold() path runs normally.
        return real_context(cwd=cwd, _resolver=_resolver, _staged_resolver=_staged_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)

    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": "/x",
    }
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()

    assert captured["resolver"] is module._resolve_branch


def test_entrypoint_injects_real_staged_resolver(monkeypatch) -> None:
    """The entrypoint builds Context with ``_staged_resolver=_resolve_staged`` (REC-09).

    Mirrors ``test_entrypoint_injects_real_branch_resolver``: captures the
    ``_staged_resolver`` kwarg and asserts it IS the real ``_resolve_staged``
    function. No live subprocess — the resolver identity is checked, never called.
    """
    module = _load_entrypoint_module()
    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, _staged_resolver, config):
        captured["staged_resolver"] = _staged_resolver
        return real_context(cwd=cwd, _resolver=_resolver, _staged_resolver=_staged_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)

    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": "/x",
    }
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()

    assert captured["staged_resolver"] is module._resolve_staged


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
    # Isolate from an ambient CLAUDE_PROJECT_DIR (Plan 02 made _load_config read it):
    # these tests pin the GLOBAL-only contract, so the project layer must be skipped.
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[git]\nprotected_branches = ["release"]\n', encoding="utf-8")
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", cfg_path)

    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, _staged_resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, _staged_resolver=_staged_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": "/x",
    }
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()

    cfg = captured["config"]
    assert cfg.protected_branches == frozenset({"release"})


def test_entrypoint_absent_global_injects_builtin(monkeypatch, tmp_path) -> None:
    """No global config FILE -> the injected config equals builtin_config() (D-08)."""
    module = _load_entrypoint_module()
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)  # GLOBAL-only (Plan 02)
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", tmp_path / "does-not-exist.toml")

    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, _staged_resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, _staged_resolver=_staged_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": "/x",
    }
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
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)  # GLOBAL-only (Plan 02)
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[git]\ngated_subcommands = ["push"]\n', encoding="utf-8")
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", cfg_path)

    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, _staged_resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, _staged_resolver=_staged_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": "/x",
    }
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()

    cfg = captured["config"]
    assert cfg.protected_branches == frozenset({"master", "main"})
    assert cfg.gated_subcommands == frozenset({"push"})


def test_entrypoint_malformed_global_degrades_to_builtin(monkeypatch, tmp_path) -> None:
    """A malformed global config degrades to builtin_config() — never crashes."""
    module = _load_entrypoint_module()
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)  # GLOBAL-only (Plan 02)
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("this is not = valid = toml [[[", encoding="utf-8")
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", cfg_path)

    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, _staged_resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, _staged_resolver=_staged_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": "/x",
    }
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()  # must not raise

    from safe_read_hook.config import builtin_config

    assert captured["config"] == builtin_config()


# --- Phase 9 Plan 02: project layer load + narrow-only merge --------------


def _capture_config_module(module, monkeypatch, payload_command: str = "git status"):
    """Run module.main() on a Bash payload, returning the captured Context config.

    Monkeypatches Context to capture the injected ``config`` kwarg without
    changing the entrypoint's fold path (hands back a real Context).
    """
    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, _staged_resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, _staged_resolver=_staged_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": payload_command},
        "cwd": "/x",
    }
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    module.main()
    return captured["config"]


def test_entrypoint_project_dir_unset_skips_layer(monkeypatch, tmp_path) -> None:
    """CLAUDE_PROJECT_DIR unset -> the project layer is SKIPPED, no file read (D-03).

    Points the project-layer reader (parse_layer) at a spy and asserts it is
    NEVER called; the injected config equals the resolved global/built-in base.
    """
    import safe_read_hook.config as config_mod

    module = _load_entrypoint_module()
    # Absent global FILE -> built-in base.
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", tmp_path / "no-global.toml")
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)

    calls: list[object] = []
    real_parse = config_mod.parse_layer

    def _spy_parse(path):
        calls.append(path)
        return real_parse(path)

    # Patch the REAL call site (resolve_config calls parse_layer in config.py).
    monkeypatch.setattr(config_mod, "parse_layer", _spy_parse)

    cfg = _capture_config_module(module, monkeypatch)

    from safe_read_hook.config import builtin_config

    assert calls == [], "project layer must not be read when CLAUDE_PROJECT_DIR unset"
    assert cfg == builtin_config()


def test_entrypoint_project_dir_empty_skips_layer(monkeypatch, tmp_path) -> None:
    """An EMPTY CLAUDE_PROJECT_DIR is treated like unset -> project layer skipped."""
    import safe_read_hook.config as config_mod

    module = _load_entrypoint_module()
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", tmp_path / "no-global.toml")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "")

    calls: list[object] = []
    real_parse = config_mod.parse_layer
    monkeypatch.setattr(
        config_mod, "parse_layer", lambda p: (calls.append(p), real_parse(p))[1]
    )

    cfg = _capture_config_module(module, monkeypatch)

    from safe_read_hook.config import builtin_config

    assert calls == []
    assert cfg == builtin_config()


def test_entrypoint_project_layer_narrows_legitimately(monkeypatch, tmp_path) -> None:
    """A project layer adding protected=["release"] + disabled=["pytest"] applies."""
    module = _load_entrypoint_module()
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", tmp_path / "no-global.toml")

    project_dir = tmp_path / "repo"
    (project_dir / ".claude").mkdir(parents=True)
    (project_dir / ".claude" / "safe-read-hook.toml").write_text(
        '[git]\nprotected_branches = ["release"]\n'
        '[recognizers]\ndisabled = ["pytest"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project_dir))

    cfg = _capture_config_module(module, monkeypatch)

    # builtin base {master,main} UNION project {release}.
    assert cfg.protected_branches == frozenset({"master", "main", "release"})
    assert "pytest" in cfg.disabled_recognizers


def test_entrypoint_criterion3_project_cannot_escalate(monkeypatch, tmp_path) -> None:
    """CFG-03 first-class cannot-escalate: a hostile project layer has ZERO effect.

    With a base protecting main / gating commit / disabling a recognizer, a
    project layer that tries to "drop" those (it can only present add-only empty
    sets) produces effective protected/gated/disabled sets IDENTICAL to the
    no-project case. Asserts SET EQUALITY, not just a verdict.
    """
    module = _load_entrypoint_module()
    # Trusted global base: protected main, gated commit, disabled sed.
    global_path = tmp_path / "global.toml"
    global_path.write_text(
        '[git]\nprotected_branches = ["main"]\ngated_subcommands = ["commit"]\n'
        '[recognizers]\ndisabled = ["sed"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", global_path)

    # No-project effective sets (CLAUDE_PROJECT_DIR unset).
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    base_cfg = _capture_config_module(module, monkeypatch)

    # A hostile project layer: it can only present empty/add-only sets (the schema
    # has no remove/replace/enabled key), so it CANNOT drop main/commit/sed.
    project_dir = tmp_path / "hostile"
    (project_dir / ".claude").mkdir(parents=True)
    (project_dir / ".claude" / "safe-read-hook.toml").write_text(
        "[git]\nprotected_branches = []\ngated_subcommands = []\n"
        "[recognizers]\ndisabled = []\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project_dir))
    hostile_cfg = _capture_config_module(module, monkeypatch)

    assert hostile_cfg.protected_branches == base_cfg.protected_branches
    assert hostile_cfg.gated_subcommands == base_cfg.gated_subcommands
    assert hostile_cfg.disabled_recognizers == base_cfg.disabled_recognizers
    # And the base members specifically survive (zero effect).
    assert hostile_cfg.protected_branches == frozenset({"main"})
    assert hostile_cfg.gated_subcommands == frozenset({"commit"})
    assert hostile_cfg.disabled_recognizers == frozenset({"sed"})


def test_entrypoint_malformed_project_drops_to_base(monkeypatch, tmp_path) -> None:
    """A malformed PROJECT layer drops to the GOOD GLOBAL base (per-layer blast radius).

    The global resolved fine (protected=["release"]); only the project layer is
    broken -> the project layer is dropped, the global base is kept (NOT built-in).
    """
    module = _load_entrypoint_module()
    global_path = tmp_path / "global.toml"
    global_path.write_text(
        '[git]\nprotected_branches = ["release"]\n', encoding="utf-8"
    )
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", global_path)

    project_dir = tmp_path / "repo"
    (project_dir / ".claude").mkdir(parents=True)
    (project_dir / ".claude" / "safe-read-hook.toml").write_text(
        "this is not = valid = toml [[[", encoding="utf-8"
    )
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project_dir))

    cfg = _capture_config_module(module, monkeypatch)  # must not raise

    # Dropped project layer -> the GOOD global base (release), NOT built-in.
    assert cfg.protected_branches == frozenset({"release"})


# --- Phase 9 Plan 03: resolve_config wiring + never-crash E2E (CFG-04) -----


def test_entrypoint_uses_resolve_config(monkeypatch, tmp_path) -> None:
    """The entrypoint resolves config via the single never-raising resolve_config.

    Spies on ``safe_read_hook.config.resolve_config`` and asserts the entrypoint
    calls it exactly once with (global_path, project_path) — the single
    orchestrated call replacing the inline per-layer handling.
    """
    module = _load_entrypoint_module()
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", tmp_path / "no-global.toml")

    calls: list[tuple] = []
    real_resolve = module.resolve_config

    def _spy_resolve(global_path, project_path, *args, **kwargs):
        calls.append((global_path, project_path))
        return real_resolve(global_path, project_path, *args, **kwargs)

    # The entrypoint does `from ...config import resolve_config`, so the bound name
    # to patch lives in the entrypoint module's namespace (its call site).
    monkeypatch.setattr(module, "resolve_config", _spy_resolve)

    _capture_config_module(module, monkeypatch)

    assert len(calls) == 1, "entrypoint must make exactly one resolve_config call"
    global_path, project_path = calls[0]
    assert global_path == tmp_path / "no-global.toml"
    assert project_path is None  # CLAUDE_PROJECT_DIR unset -> None (D-03)


def test_entrypoint_malformed_global_e2e_does_not_crash(tmp_path) -> None:
    """Real subprocess: a malformed GLOBAL config -> returncode 0, no traceback.

    Repoints HOME at a temp dir holding a malformed
    ``~/.config/claude-safe-hook/config.toml`` and runs the hook as a real
    subprocess on a ``git commit`` payload. Asserts returncode 0 and no traceback
    on stdout/stderr (CORE-06) — the never-crash contract end-to-end.
    """
    cfg_dir = tmp_path / ".config" / "claude-safe-hook"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.toml").write_text(
        "this is not = valid = toml [[[", encoding="utf-8"
    )

    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env.pop("CLAUDE_PROJECT_DIR", None)  # skip the project layer (D-03)

    payload = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "git commit -m x"},
            "cwd": str(tmp_path),
        }
    )
    result = subprocess.run(
        [sys.executable, str(_HOOK)],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr


def test_entrypoint_malformed_global_asks_on_main(monkeypatch, tmp_path) -> None:
    """A malformed GLOBAL config -> built-in floor restored: git commit on main ASKs.

    D-10 safe defaults: the malformed global degrades to built-in master/main +
    add/commit/stash, so a gated op on ``main`` still ASKs (never auto-allowed,
    never a traceback). Uses the module-import path with a stubbed branch resolver
    (main) for a deterministic verdict.
    """
    module = _load_entrypoint_module()
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("this is not = valid = toml [[[", encoding="utf-8")
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", cfg_path)
    # Stub the branch resolver to a protected branch so the gated verdict is ASK.
    monkeypatch.setattr(module, "_resolve_branch", lambda _cwd: "main")

    captured: dict[str, object] = {}
    real_context = module.Context

    def _capture_context(*, cwd, _resolver, _staged_resolver, config):
        captured["config"] = config
        return real_context(cwd=cwd, _resolver=_resolver, _staged_resolver=_staged_resolver, config=config)

    monkeypatch.setattr(module, "Context", _capture_context)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m x"},
        "cwd": "/x",
    }
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))

    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    module.main()  # must not raise

    from safe_read_hook.config import builtin_config

    # Built-in floor restored (D-10 safe defaults).
    assert captured["config"] == builtin_config()
    # And the gated commit on main ASKs (not allow, not a traceback).
    emitted = out.getvalue().strip()
    assert emitted, "a gated commit on main must emit an envelope"
    parsed = json.loads(emitted)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_entrypoint_malformed_project_keeps_global(monkeypatch, tmp_path) -> None:
    """A malformed PROJECT config -> returncode 0, the valid global protection intact.

    The global resolves fine (protected=["release"]); only the project layer is
    broken -> the project layer is dropped, the global base survives (per-layer
    blast radius via resolve_config, wired through the entrypoint).
    """
    module = _load_entrypoint_module()
    global_path = tmp_path / "global.toml"
    global_path.write_text(
        '[git]\nprotected_branches = ["release"]\n', encoding="utf-8"
    )
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", global_path)

    project_dir = tmp_path / "repo"
    (project_dir / ".claude").mkdir(parents=True)
    (project_dir / ".claude" / "safe-read-hook.toml").write_text(
        "this is not = valid = toml [[[", encoding="utf-8"
    )
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project_dir))

    cfg = _capture_config_module(module, monkeypatch)  # must not raise

    # Dropped project layer -> the GOOD global base (release), NOT built-in.
    assert cfg.protected_branches == frozenset({"release"})


# --- Phase 10 Plan 01: audit logging (LOG-01) -----------------------------


def _run_in_process(module, monkeypatch, command: str, *, stdout=None):
    """Drive module.main() in-process on a Bash payload (ROUTE A).

    Repoints stdin to the payload; optionally captures stdout. A child subprocess
    re-resolves _GLOBAL_CONFIG_PATH from Path.home() and ignores a parent
    monkeypatch, so audit tests run IN-PROCESS where the repoint takes effect.
    """
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": "/x",
    }
    monkeypatch.setattr("sys.stdin", _StdinStub(json.dumps(payload)))
    if stdout is not None:
        monkeypatch.setattr("sys.stdout", stdout)
    module.main()


def _point_audit(module, monkeypatch, tmp_path, audit_path, *, body_extra=""):
    """Write a global TOML repointing the audit log to ``audit_path`` and wire it.

    Skips the project layer (CLAUDE_PROJECT_DIR unset) so the global is the sole
    source of the [logging] table.
    """
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        f'[logging]\npath = "{audit_path}"\n{body_extra}', encoding="utf-8"
    )
    monkeypatch.setattr(module, "_GLOBAL_CONFIG_PATH", cfg_path)


def test_audit_allow_writes_one_jsonlines_record(monkeypatch, tmp_path) -> None:
    """A real cat foo.txt allow -> exactly ONE audit line with the LOG-01 fields."""
    module = _load_entrypoint_module()
    audit = tmp_path / "audit.log"
    _point_audit(module, monkeypatch, tmp_path, audit)

    _run_in_process(module, monkeypatch, "cat foo.txt")

    assert audit.exists(), "audit line must land in the repointed file"
    lines = audit.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert set(rec) == {"ts", "decision", "tag", "reason", "command"}
    assert rec["decision"] == "allow"
    assert rec["tag"] == "reader"
    assert rec["command"] == "cat foo.txt"


def test_audit_ask_records_git_decision(monkeypatch, tmp_path) -> None:
    """A gated git commit on a protected branch -> one ask audit line, tag=git."""
    module = _load_entrypoint_module()
    audit = tmp_path / "audit.log"
    _point_audit(module, monkeypatch, tmp_path, audit)
    # Stub the resolver to a protected branch so the gated verdict is ASK.
    monkeypatch.setattr(module, "_resolve_branch", lambda _cwd: "main")

    _run_in_process(module, monkeypatch, "git commit -m x")

    lines = audit.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["decision"] == "ask"
    assert rec["tag"] == "git"


def test_audit_envelope_has_no_tag_key(monkeypatch, tmp_path) -> None:
    """The stdout hookSpecificOutput envelope is unchanged: NO tag key (contract)."""
    module = _load_entrypoint_module()
    audit = tmp_path / "audit.log"
    _point_audit(module, monkeypatch, tmp_path, audit)

    out = io.StringIO()
    _run_in_process(module, monkeypatch, "cat foo.txt", stdout=out)

    parsed = json.loads(out.getvalue().strip())
    hso = parsed["hookSpecificOutput"]
    assert set(hso) == {
        "hookEventName",
        "permissionDecision",
        "permissionDecisionReason",
    }


def test_audit_abstain_writes_no_line(monkeypatch, tmp_path) -> None:
    """D-03: an abstain payload (fold->None compound) produces NO audit line.

    The write site is after both abstain returns, so abstains are not logged for
    free. The audit file must not exist (nothing was appended).
    """
    module = _load_entrypoint_module()
    audit = tmp_path / "audit.log"
    _point_audit(module, monkeypatch, tmp_path, audit)

    _run_in_process(module, monkeypatch, "cat foo && rm -rf x")

    assert not audit.exists(), "an abstain must not append an audit record"


def test_audit_unwritable_never_raises_emits_envelope(monkeypatch, tmp_path) -> None:
    """CORE-06: an unwritable audit path -> still emits the envelope, never raises.

    Points log_path at a path whose PARENT is a regular file (open-for-append
    fails reliably, even as root), exercising audit_log's try/except: pass.
    """
    module = _load_entrypoint_module()
    parent_file = tmp_path / "not-a-dir"
    parent_file.write_text("", encoding="utf-8")
    audit = parent_file / "audit.log"  # parent is a file -> open() fails
    _point_audit(module, monkeypatch, tmp_path, audit)

    out = io.StringIO()
    _run_in_process(module, monkeypatch, "cat foo.txt", stdout=out)  # must not raise

    parsed = json.loads(out.getvalue().strip())
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert not audit.exists()


def test_audit_logging_enabled_false_override_suppresses_line(
    monkeypatch, tmp_path
) -> None:
    """D-04/D-05: [logging] enabled=false -> no line; enabled=true+path -> line.

    Drives the override end-to-end through resolve_config: with enabled=false NO
    record is written even on an allow; flipping enabled=true writes one line at
    the configured path.
    """
    module = _load_entrypoint_module()

    # enabled=false: no audit line even on an allow.
    audit_off = tmp_path / "off.log"
    _point_audit(
        module, monkeypatch, tmp_path, audit_off, body_extra="enabled = false\n"
    )
    _run_in_process(module, monkeypatch, "cat foo.txt")
    assert not audit_off.exists(), "enabled=false must suppress the audit record"

    # enabled=true at a fresh path: exactly one line lands there.
    audit_on = tmp_path / "on.log"
    _point_audit(
        module, monkeypatch, tmp_path, audit_on, body_extra="enabled = true\n"
    )
    _run_in_process(module, monkeypatch, "cat foo.txt")
    assert audit_on.read_text(encoding="utf-8").splitlines() != []


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

"""Exec-form PreToolUse entrypoint — the only place that touches I/O (D-08).

Deploy form: ``python3 ${CLAUDE_PROJECT_DIR}/hooks/safe_read_hook.py``.

This thin wrapper owns ALL stdin/stdout JSON handling, the ``tool_name == "Bash"``
gate, the ``hookSpecificOutput`` envelope, and the never-crash guarantee
(CORE-06): any error is logged best-effort and swallowed so the hook emits
nothing and exits 0, letting the normal permission flow proceed. The pure core
(``tokenize`` + ``fold``) stays import-clean and I/O-free.

This entrypoint is NOT wired live this phase — the seed remains the registered
hook (D-14). It only ever emits allow or ask, never a denial.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback
from datetime import datetime
from pathlib import Path

_LOG_FILE = Path("/tmp/claude-hook.log")


def log(msg: str) -> None:
    """Best-effort append to the error log; never raises."""
    try:
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass


# Deploy form is `python3 .../hooks/safe_read_hook.py`, which puts THIS file's
# directory on sys.path[0]. Because this file is named safe_read_hook.py, it
# would otherwise shadow the installed `safe_read_hook` PACKAGE — `import
# safe_read_hook` would find this script (a plain module, not a package) and
# `safe_read_hook.context` would fail. Drop the script's own directory so the
# real installed package resolves.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [p for p in sys.path if p and os.path.abspath(p) != _HERE]

# Import the pure core AFTER the sys.path de-shadow (E402/I001 intentional). The
# imports are guarded so a missing/broken install degrades to a clean abstain
# (emit nothing, exit 0) rather than a traceback — the CORE-06 never-crash
# contract must hold for import failures too, not just runtime errors in main().
try:
    from safe_read_hook.config import (  # noqa: E402
        ResolvedConfig,
        builtin_config,
        load_layer,
        merge,
        parse_layer,
    )
    from safe_read_hook.context import Context  # noqa: E402
    from safe_read_hook.engine import fold  # noqa: E402
    from safe_read_hook.tokenizer import tokenize  # noqa: E402
except Exception:
    log("uncaught exception (core import failed):\n" + traceback.format_exc())
    sys.exit(0)


# The trusted GLOBAL config (D-01). Resolved once per invocation in _load_config;
# a module constant so tests can repoint it at a temp file (mirrors the patchable
# resolver seam). NOT a cached config object — only the path is module-level.
_GLOBAL_CONFIG_PATH = Path.home() / ".config" / "claude-safe-hook" / "config.toml"


def _project_config_path() -> Path | None:
    """Return the untrusted PROJECT config path, or None when it should be skipped.

    Resolves ``$CLAUDE_PROJECT_DIR/.claude/safe-read-hook.toml`` (D-02 — a
    standalone dotfile, NOT a ``pyproject.toml [tool.*]`` section). When
    ``CLAUDE_PROJECT_DIR`` is unset OR empty the project layer is SKIPPED ENTIRELY
    (returns None) — the planner-chosen D-03 behavior. Skipping is cardinal-safe:
    the project layer can only NARROW (union/add), so omitting it never widens
    trust below the global/built-in base. The unset/empty short-circuit happens
    BEFORE any path is constructed so nothing is read in that case.
    """
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if not project_dir:
        return None
    return Path(project_dir) / ".claude" / "safe-read-hook.toml"


def _load_global_config() -> ResolvedConfig:
    """Resolve the trusted GLOBAL/built-in base, fail-closed to the built-in floor.

    Absent FILE -> built-in floor (D-08 case 1 / D-05: built-in applies only when
    no global exists). Present -> the resolved single layer. Any parse/value error
    is logged best-effort and degrades to the built-in floor (D-09 never-crash).
    Mirrors the ``_resolve_branch`` try/except -> safe-default shape.
    """
    try:
        if not _GLOBAL_CONFIG_PATH.exists():
            return builtin_config()
        return load_layer(_GLOBAL_CONFIG_PATH)
    except Exception:
        log(
            "global config load failed; using built-in floor:\n"
            + traceback.format_exc()
        )
        return builtin_config()


def _load_config() -> ResolvedConfig:
    """Resolve the effective config: the global/built-in base narrowed by the project.

    1. Resolve the trusted global/built-in ``base`` (:func:`_load_global_config`).
    2. If a project config path is in scope (CLAUDE_PROJECT_DIR set, D-03) AND the
       file exists, read its RAW present/absent keys (``parse_layer`` — absent
       project key = additive-identity-empty, D-07) and ``merge`` narrow-only onto
       the base (union protected/gated, add disabled — project can only NARROW,
       CFG-02/CFG-03).
    3. Absent project FILE -> the base unchanged (D-08 case 2).

    The project load+merge has its OWN try/except (per-layer blast radius, D-09):
    a malformed/unreadable project layer is DROPPED and the GOOD ``base`` is kept
    (NOT the built-in floor) — safe because the project layer could only narrow.
    The full malformed matrix is Plan 03; this is the per-layer seam.
    """
    base = _load_global_config()
    project_path = _project_config_path()
    if project_path is None:
        return base  # CLAUDE_PROJECT_DIR unset/empty -> skip the project layer (D-03)
    try:
        if not project_path.exists():
            return base  # absent project FILE -> base only (D-08 case 2)
        return merge(base, parse_layer(project_path))
    except Exception:
        log(
            "project config load failed; keeping global/built-in base:\n"
            + traceback.format_exc()
        )
        return base


def _resolve_branch(cwd: str | None) -> str | None:
    """Resolve the current git branch for ``cwd`` (the real D-03 resolver).

    Runs ``git branch --show-current`` as an argv list (``shell=False`` — no
    shell, no command injection via a crafted cwd; threat T-05-06). Empty stdout
    (detached HEAD) -> None. Any error (not-a-repo / timeout / probe failure) is
    swallowed -> None, upholding the CORE-06 never-crash contract. Injected at
    Context construction so the recognizer never shells out. Memoized per-cwd by
    Context.branch — at most one bounded (<=2s) probe per distinct cwd.
    """
    try:
        out = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        return out.stdout.strip() or None
    except Exception:
        return None


def main() -> None:
    """Read a PreToolUse payload from stdin and emit a decision envelope, or nothing."""
    try:
        raw = sys.stdin.read()
        try:
            payload = json.loads(raw)
        except Exception as e:
            log(f"bad stdin JSON ({e}): {raw[:500]!r}")
            return
        if payload.get("tool_name") != "Bash":
            return
        command = payload.get("tool_input", {}).get("command", "")
        if not isinstance(command, str) or not command:
            return
        ctx = Context(
            cwd=payload.get("cwd"),
            _resolver=_resolve_branch,
            config=_load_config(),
        )
        result = tokenize(command)
        if result.abstain_reason is not None:
            return  # structural/over-length/allowlist trigger — abstain (D-15)
        verdict = fold(result.segments, ctx)
        if verdict is None:
            return  # abstain — emit nothing (CORE-06)
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": verdict.decision,
                        "permissionDecisionReason": verdict.reason,
                    }
                }
            )
        )
    except Exception:
        log("uncaught exception:\n" + traceback.format_exc())


# Deploy runs this file as a script (`python3 .../safe_read_hook.py`), so
# `__name__ == "__main__"` still fires — runtime behavior is unchanged. The
# guard only stops `main()` auto-running when the entrypoint is imported (the
# wiring test imports `_resolve_branch`/`main` to assert the Context resolver
# identity without firing a live subprocess).
if __name__ == "__main__":
    main()

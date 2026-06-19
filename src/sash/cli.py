"""Console-script entrypoint for sash (PKG-08, D-01).

Relocated from hooks/safe_read_hook.py. Invoked as `sash` (console script),
`python -m sash`, or via uvx. Never invoke argparse — argv dispatch is a single
trivial check (D-06) placed before the stdin read.
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


def audit_log(path: Path, record: dict) -> None:
    """Best-effort append one JSON-lines audit record to ``path``; never raises.

    A structural twin of :func:`log` (CORE-06 best-effort): a write failure (an
    unwritable path, a directory target) is swallowed so the hook still emits its
    stdout envelope and exits 0. ``json.dumps`` escapes embedded quotes/operators
    in reason/command and emits no embedded newline for a flat dict, so the
    one-record-per-line invariant holds even for a command with ``&&``/quotes
    (T-10-03). The audit file is distinct from the error log.
    """
    try:
        with path.open("a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass


# Import the pure core. The imports are guarded so a missing/broken install
# degrades to a clean abstain (emit nothing, exit 0) rather than a traceback —
# the CORE-06 never-crash contract must hold for import failures too, not just
# runtime errors in main().
try:
    from sash.config import ResolvedConfig, resolve_config
    from sash.context import Context
    from sash.engine import fold
    from sash.tokenizer import tokenize
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


def _load_config() -> ResolvedConfig:
    """Resolve the effective config via the single never-raising ``resolve_config``.

    The entrypoint owns the I/O: it resolves the trusted GLOBAL path (D-01) and the
    untrusted PROJECT path (:func:`_project_config_path`; None when
    CLAUDE_PROJECT_DIR is unset/empty, D-03), then hands both to the total
    :func:`resolve_config` orchestrator which applies the D-08 three-case + D-09
    per-layer fail-closed matrix (malformed global -> built-in floor + still narrow
    with a valid project; malformed project -> drop to the good base; D-10 safe
    defaults) and NEVER raises (CORE-06). The entrypoint's ``log`` is injected so a
    dropped layer is recorded best-effort.
    """
    return resolve_config(_GLOBAL_CONFIG_PATH, _project_config_path(), log)


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


def _resolve_staged(cwd: str | None) -> list[str] | None:
    """Return the list of staged file paths for ``cwd`` (the real REC-09 probe).

    Runs ``git diff --cached --name-only`` as an argv list (``shell=False`` — no
    shell, no command injection via a crafted cwd; mirrors T-05-06 / T-14-14
    mitigation from ``_resolve_branch``). Returns a list of non-empty lines from
    stdout, or ``None`` on any error (not-a-repo / timeout / probe failure),
    which causes the caller to ASK (D-08 fail-safe). Injected at Context
    construction so git.py's ``_planning_only`` never shells out directly.
    """
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        return [ln for ln in out.stdout.splitlines() if ln]
    except Exception:
        return None  # any error -> caller ASKs (D-08)


def main() -> None:
    """Read a PreToolUse payload from stdin and emit a decision envelope, or nothing.

    Before the stdin read, a trivial argv dispatch (D-06) routes the ``install``
    and ``update`` subcommands to their stubs (replaced by lazy imports in Plan
    17-02). Bare invocation (no argv[1]) falls through to the hook path.
    """
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "install":
            print("install: not yet implemented")
            return
        elif cmd == "update":
            print("update: not yet implemented")
            return
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
        config = _load_config()
        ctx = Context(
            cwd=payload.get("cwd"),
            _resolver=_resolve_branch,
            _staged_resolver=_resolve_staged,
            config=config,
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
        # Audit AFTER both abstain returns (D-03 — abstains are NOT logged) and
        # AFTER the envelope is emitted (CORE-06 — the decision is delivered even
        # if the audit write fails). tag goes ONLY here, never to the envelope.
        if config.log_enabled:
            audit_log(
                config.log_path,
                {
                    "ts": datetime.now().isoformat(),
                    "decision": verdict.decision,
                    "tag": verdict.tag,
                    "reason": verdict.reason,
                    "command": command,
                },
            )
    except Exception:
        log("uncaught exception:\n" + traceback.format_exc())


# The guard stops `main()` auto-running when the entrypoint is imported (the
# wiring tests import `_resolve_branch`/`main` to assert the Context resolver
# identity without firing a live subprocess). `python -m sash` routes through
# __main__.py, and the console script calls `sash.cli:main` directly.
if __name__ == "__main__":
    main()

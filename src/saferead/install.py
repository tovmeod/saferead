"""Installer for saferead (INST-01, D-07 lazy-imported off the hook path).

Contains install_main(). This module is imported ONLY on the `saferead install`
argv branch in saferead.cli — never on the bare hook path, so the
latency-sensitive decision path never pays its import cost.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


def _detect_saferead_path() -> str | None:
    """Return the permanent saferead binary path, or None when not resolvable (D-02).

    Primary: ``uv tool dir --bin`` (uv-authoritative; respects ``UV_TOOL_BIN_DIR``).
    Fallback: ``shutil.which("saferead")`` (works when the tool bin dir is on PATH).
    Never returns the ephemeral invoking-script path — under ``uvx`` the running
    copy lives in a cache dir that vanishes when the process exits (the original
    INST-01 bug). Best-effort: the subprocess block never raises (CORE-06).
    """
    try:
        result = subprocess.run(
            ["uv", "tool", "dir", "--bin"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            candidate = Path(result.stdout.strip()) / "saferead"
            if candidate.exists():
                return str(candidate)
    except Exception:
        pass
    found = shutil.which("saferead")
    if found:
        return str(Path(found))
    return None


def _bootstrap_uv_tool() -> bool:
    """Ensure a permanent ``saferead`` via ``uv tool install --upgrade`` (D-01).

    Best-effort (D-03, CORE-06): ``uv`` absent (FileNotFoundError), a hang
    (TimeoutExpired), a non-zero exit, or any other error each print actionable
    guidance and return ``False`` — this helper never exits the process and never
    tracebacks. Returns ``True`` only on a clean (returncode 0) install/upgrade;
    on ``False`` the caller still attempts path resolution since an older version
    may already be installed (RESEARCH Pitfall 5).
    """
    try:
        result = subprocess.run(
            ["uv", "tool", "install", "saferead", "--upgrade"],
            shell=False,
            timeout=120,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("saferead: uv not found — install via https://docs.astral.sh/uv/")
        return False
    except subprocess.TimeoutExpired:
        print(
            "saferead: bootstrap timed out — "
            "run `uv tool install saferead --upgrade` manually"
        )
        return False
    except Exception as e:
        print(
            f"saferead: bootstrap failed ({e}) — "
            "run `uv tool install saferead --upgrade`"
        )
        return False
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, end="")
        return False
    return True


def _load_settings(path: Path) -> dict:
    """Return the parsed settings.json, or ``{}`` when the file is absent.

    A present-but-malformed file is allowed to raise — the caller wants to know
    before clobbering a settings file it could not parse.
    """
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _backup_settings(path: Path) -> None:
    """Copy ``path`` to ``<name>.bak.<ISO timestamp>`` before modification (D-14).

    Best-effort (CORE-06 posture): a copy failure (permissions, disk full) is
    warned and swallowed so the main write still proceeds. Colons in the ISO
    timestamp are replaced with ``-`` for filesystem portability. No backup is
    taken when the original does not yet exist.
    """
    if not path.exists():
        return
    stamp = datetime.now().isoformat().replace(":", "-")
    backup = path.parent / f"{path.name}.bak.{stamp}"
    try:
        shutil.copy2(path, backup)
    except Exception as e:
        print(f"saferead: warning — could not back up {path}: {e}")


def _merge_hook(data: dict, saferead_cmd: str) -> bool:
    """Merge the saferead exec-form hook entry into ``data``; True if changed (D-13).

    Locates the ``PreToolUse`` block whose ``matcher`` is ``"Bash"`` (creating the
    nesting when absent) and reconciles the saferead entry by command basename:

    - an existing ``saferead`` entry at the SAME path -> no-op, return False
    - an existing ``saferead`` entry at a DIFFERENT path -> update in place, return True
    - no ``saferead`` entry -> append ``{"type":"command","command":saferead_cmd}``
      and return True

    Existing non-saferead entries (dcg, git-gate) are never touched (D-12). The
    function never produces two entries with basename ``saferead``.
    """
    pretooluse = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    block = None
    for elem in pretooluse:
        if isinstance(elem, dict) and elem.get("matcher") == "Bash":
            block = elem
            break
    if block is None:
        block = {"matcher": "Bash", "hooks": []}
        pretooluse.append(block)
    hooks = block.setdefault("hooks", [])
    if not isinstance(hooks, list):
        hooks = block["hooks"] = []
    for entry in hooks:
        if not isinstance(entry, dict):
            continue
        if Path(entry.get("command", "")).name == "saferead":
            if entry.get("command") == saferead_cmd:
                return False
            entry["command"] = saferead_cmd
            return True
    hooks.append({"type": "command", "command": saferead_cmd})
    return True


def _atomic_write(path: Path, data: dict) -> None:
    """Atomically write ``data`` as indented JSON to ``path`` (D-14).

    Writes to a tempfile in the same directory then ``os.replace`` swaps it into
    place — a crash mid-write leaves the original intact. On any error the tmp is
    cleaned up, the failure is reported, and the exception is re-raised so the
    caller exits non-zero rather than silently corrupting the file.
    """
    tmp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=path.parent, delete=False, suffix=".tmp", encoding="utf-8"
        ) as f:
            tmp_name = f.name
            json.dump(data, f, indent=2)
        os.replace(tmp_name, path)
    except Exception as e:
        print(f"saferead: failed to write {path}: {e}")
        if tmp_name is not None and os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise


def _select_target(args: list[str]) -> Path:
    """Resolve the target settings.json path from argv tail ``args`` (D-04, Phase 20).

    ``--project`` -> ``cwd/.claude/settings.json``; a bare path arg ->
    ``Path(arg).expanduser().resolve()``; neither -> an interactive global-vs-project
    prompt when stdin is a TTY, falling back to the global default
    ``~/.claude/settings.json`` on non-TTY stdin or EOF (``uvx`` may close stdin even
    in a terminal session, so the prompt must never raise ``EOFError`` — CORE-06).
    """
    if "--project" in args:
        return Path.cwd() / ".claude" / "settings.json"
    for arg in args:
        if not arg.startswith("-"):
            return Path(arg).expanduser().resolve()
    if sys.stdin.isatty():
        try:
            choice = (
                input(
                    "Install to [G]lobal (~/.claude/settings.json) or "
                    "[P]roject (.claude/settings.json)? [G]: "
                )
                .strip()
                .lower()
            )
            if choice in ("p", "project"):
                return Path.cwd() / ".claude" / "settings.json"
        except EOFError:
            pass  # non-interactive stdin closed — fall through to global
    return Path.home() / ".claude" / "settings.json"


def install_main() -> None:
    """Install the saferead exec-form hook entry into the target settings (INST-01).

    Step 1 (D-01): bootstrap a permanent ``uv tool install saferead --upgrade``.
    Step 2 (D-02/D-06): resolve the PERMANENT binary path; if none is resolvable,
    print guidance and exit non-zero WITHOUT touching settings.json. Step 3 (D-04):
    pick the target (TTY prompt / global default). Step 4: merge + backup + atomic
    write (Phase 17 machinery, unchanged).
    """
    _bootstrap_uv_tool()  # D-01 — best-effort; return value is informational
    saferead_cmd = _detect_saferead_path()
    if saferead_cmd is None:  # D-06 — never register a vanishing path
        print(
            "saferead: could not determine the permanent binary path.\n"
            "Run `uv tool install saferead` then `saferead install`."
        )
        sys.exit(1)
    target = _select_target(sys.argv[2:])
    target.parent.mkdir(parents=True, exist_ok=True)
    data = _load_settings(target)
    changed = _merge_hook(data, saferead_cmd)
    if changed:
        _backup_settings(target)  # backup before write (D-14)
        _atomic_write(target, data)
        print(f"saferead: installed to {target}")
    else:
        print(f"saferead: already installed at {saferead_cmd} (no change)")

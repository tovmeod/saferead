"""Installer and updater for saferead (INST-01, D-07 lazy-imported off the hook path).

Contains install_main() and update_main(). This module is imported ONLY on the
`saferead install` / `saferead update` argv branches in saferead.cli — never on
the bare hook path, so the latency-sensitive decision path never pays its import
cost.
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


def _detect_saferead_path() -> str:
    """Return the absolute path of the installed saferead binary (D-09).

    Prefers ``shutil.which("saferead")`` (the console script on PATH); falls back to
    ``Path(sys.argv[0]).resolve()`` for invocation via the script directly. Both
    yield an absolute path suitable for an exec-form hook entry.
    """
    found = shutil.which("saferead")
    if found:
        return str(Path(found).resolve())
    return str(Path(sys.argv[0]).resolve())


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
    """Resolve the target settings.json path from argv tail ``args`` (D-08).

    ``--project`` -> ``cwd/.claude/settings.json``; a bare path arg ->
    ``Path(arg).expanduser().resolve()``; neither -> an interactive prompt on a
    TTY, else the global default ``~/.claude/settings.json`` silently.
    """
    global_default = Path.home() / ".claude" / "settings.json"
    project_default = Path.cwd() / ".claude" / "settings.json"
    if "--project" in args:
        return project_default
    for arg in args:
        if not arg.startswith("-"):
            return Path(arg).expanduser().resolve()
    if sys.stdin.isatty():
        print("[1] ~/.claude/settings.json  (global, applies to all projects)")
        print("[2] .claude/settings.json   (project-local)")
        choice = input("Enter path manually or press Enter for [1]: ").strip()
        if choice in ("", "1"):
            return global_default
        if choice == "2":
            return project_default
        return Path(choice).expanduser().resolve()
    return global_default


def install_main() -> None:
    """Install the saferead exec-form hook entry into the target settings (INST-01)."""
    target = _select_target(sys.argv[2:])
    target.parent.mkdir(parents=True, exist_ok=True)
    data = _load_settings(target)
    saferead_cmd = _detect_saferead_path()
    changed = _merge_hook(data, saferead_cmd)
    if changed:
        _backup_settings(target)  # backup before write (D-14)
        _atomic_write(target, data)
        print(f"saferead: installed to {target}")
    else:
        print(f"saferead: already installed at {saferead_cmd} (no change)")


def update_main() -> None:
    """Upgrade installed saferead via ``uv tool upgrade saferead`` — best-effort (D-11).

    Runs the upgrade as an argv list (``shell=False`` — no injection surface; the
    only argument is the literal ``"saferead"``). uv absent (FileNotFoundError), a
    failed upgrade (CalledProcessError is not raised since check=False), or a hang
    (TimeoutExpired) are caught and reported as guidance; the updater NEVER
    tracebacks (CORE-06 abstain-never-crash posture).
    """
    try:
        result = subprocess.run(
            ["uv", "tool", "upgrade", "saferead"],
            shell=False,
            timeout=60,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("saferead: uv not found — install via https://docs.astral.sh/uv/")
        return
    except subprocess.TimeoutExpired:
        print("saferead: upgrade timed out — run `uv tool upgrade saferead` manually")
        return
    except Exception as e:
        print(f"saferead: update failed ({e}) — run `uv tool upgrade saferead`")
        return
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")

#!/usr/bin/env python3
"""
Claude Code PreToolUse hook.

Decisions
    1. Decompose Bash into segments at top-level &&, ||, ;, |, and newline.
       Quotes, backticks, and $(...) nest correctly. '# ...' comments are
       stripped at top level.
    2. If every segment is a recognized safe read (read-only text tools,
       read-only git/adb, etc.) -> allow.
    3. If any segment is a GATED git write (add/commit/stash):
           on master/main  -> ask
           otherwise       -> allow
    4. Anything unrecognized -> abstain (stay silent, let Claude prompt).

Diagnostics are appended to /tmp/claude-hook.log.
"""

import json
import re
import subprocess
import sys
import traceback
from datetime import datetime
from pathlib import Path

LOG_FILE = Path("/tmp/claude-hook.log")

PROTECTED = {"master", "main"}
GATED_GIT = {"add", "commit", "stash"}


# ---------------------------------------------------------------------------
# Regex building blocks
# ---------------------------------------------------------------------------
#
# _QARG  — a single shell argument token. Handles single-quoted, double-quoted,
#          or an unquoted run of non-meta characters. With re.DOTALL, quoted
#          strings may span newlines (useful for multi-line awk scripts).
# _DISCARD_REDIR — redirects that never touch a user file.
# _TMP_REDIR     — writes to /tmp (treated as scratch).
# _SAFE_REDIR    — union of the two.
# _TAIL          — zero-or-more (arg | safe-redir) tokens after a command head.

_QARG = r"""(?:'[^']*'|"[^"]*"|[^;&|`$>\s]+)"""
_DISCARD_REDIR = r"(?:2>&1|>/dev/null|2>/dev/null|&>>?/dev/null)"
_TMP_REDIR = r"(?:>>?\s*/tmp/[^\s;&|`$]+|2>\s*/tmp/[^\s;&|`$]+)"
_SAFE_REDIR = rf"(?:{_DISCARD_REDIR}|{_TMP_REDIR})"
_TAIL = rf"(?:\s+{_QARG}|\s+{_SAFE_REDIR})*"

_FL = re.DOTALL


# ---------------------------------------------------------------------------
# Safe-read patterns
# ---------------------------------------------------------------------------

SAFE_GIT_READONLY = re.compile(
    r'^git(?:\s+-[Cc]\s+\S+)*\s+'
    r'(?:show|log|diff|status|blame|branch|tag|remote|config\s+--get|'
    r'rev-parse|describe|ls-files|ls-tree|cat-file|reflog|shortlog|'
    r'grep|for-each-ref|merge-base|name-rev|whatchanged|count-objects|'
    r'verify-commit|verify-tag|notes\s+show|help|version|'
    r'stash\s+(?:list|show)|worktree\s+list)\b',
    _FL,
)

# adb: read-only subcommands only. Deliberately exclude shell/push/pull/install.
SAFE_ADB = re.compile(
    rf'^adb\s+(?:logcat|devices|get-state|get-serialno|version|help)\b{_TAIL}\s*$',
    _FL,
)

_CMD_ECHO = r'(?:echo|printf)'
_CMD_FILTERS = (
    r'(?:grep|egrep|fgrep|rg|ag|head|tail|wc|sort|uniq|cut|tr|jq|column|nl|'
    r'rev|tac|base64|xxd|od|strings|tee|diff|comm|paste|join|fold|expand|'
    r'unexpand)'
)
_CMD_FILE_READERS = (
    r'(?:cat|bat|less|more|ls|file|stat|readlink|realpath|basename|dirname|'
    r'pwd|which|whereis|type|du|df)'
)

SAFE_READ_PATTERNS = [
    # 'cd' with a single path. No compound after cd (that would be a separate
    # segment) and no redirect (doesn't make sense for cd).
    re.compile(r'^cd\s+\S+\s*$', _FL),

    SAFE_GIT_READONLY,
    SAFE_ADB,

    re.compile(rf'^{_CMD_ECHO}\b{_TAIL}\s*$', _FL),
    re.compile(rf'^{_CMD_FILTERS}\b{_TAIL}\s*$', _FL),
    re.compile(rf'^{_CMD_FILE_READERS}\b{_TAIL}\s*$', _FL),

    # find without actions that shell out or write files
    re.compile(
        rf'^find\b(?!.*(?:-delete|-exec|-execdir|-ok|-okdir|-fprint|-fprintf)\b)'
        rf'{_TAIL}\s*$',
        _FL,
    ),

    # awk: reject the common shell-escape.
    re.compile(rf'^awk\b(?!.*\bsystem\s*\(){_TAIL}\s*$', _FL),

    # sed: reject in-place edits.
    re.compile(
        rf'^sed\b(?!.*\s-i\b)(?!.*\s--in-place\b){_TAIL}\s*$',
        _FL,
    ),
]


# ---------------------------------------------------------------------------
# Pytest invocation (user opt-in: running tests is approved)
# ---------------------------------------------------------------------------
# Matches any of:
#   pytest ARGS...
#   /abs/path/pytest ARGS...    (.venv/bin/pytest too)
#   python -m pytest ARGS...    (python3 or full path ok)
#   uv run pytest ARGS...
#   uv run --flag[=val|\s val]... pytest ARGS...
#   uv run python -m pytest ARGS...
#   VAR=val ... <any of the above>
# Args can be test paths, test node-ids (foo.py::test_x), pytest options
# (quoted or not), and safe redirects (2>&1, >/tmp/..., etc).
#
# Safety notes: flag values use _QARG so unquoted `$()` / backticks don't
# match (the splitter keeps those in-segment; the regex then rejects them).
# Inside double quotes `$var` expansion still passes, same trust level as
# the rest of the safe-read patterns.

_ENV_ASSIGN = rf'(?:[A-Za-z_]\w*={_QARG}\s+)*'
_UV_FLAG = rf'(?:--[\w-]+(?:={_QARG}|\s+{_QARG})?|-[A-Za-z])'
_UV_PREFIX = rf'(?:uv(?:\s+{_UV_FLAG})*\s+run(?:\s+{_UV_FLAG})*\s+)?'
_PY_EXE = r'(?:[\w./~-]*/)?python3?'
_PY_OPT = rf'(?:-[A-Za-z]+(?:\s+{_QARG})?|--[\w-]+(?:={_QARG}|\s+{_QARG})?)'
_PY_PREFIX = rf'(?:{_PY_EXE}(?:\s+{_PY_OPT})*\s+-m\s+)?'
_PYTEST_EXE = r'(?:[\w./~-]*/)?pytest'

SAFE_PYTEST = re.compile(
    rf'^{_ENV_ASSIGN}{_UV_PREFIX}{_PY_PREFIX}{_PYTEST_EXE}{_TAIL}\s*$',
    _FL,
)


# ---------------------------------------------------------------------------
# Gradle invocation (user opt-in: running gradle tasks is approved)
# ---------------------------------------------------------------------------
# Matches `gradle` or `gradlew` from any path, with arbitrary flags and tasks
# (e.g. `:app:testDebugUnitTest`, `--info`, `-p /path`, `-Pname=val`).
#
# Blocked flags (negative lookahead):
#   --init-script / -I   — loads an arbitrary Groovy/Kotlin init script
#   --build-file  / -b   — runs a different build.gradle than the project's
#   --settings-file / -c — same risk for settings.gradle
# These bypass the project the user thinks they're executing in.

_GRADLE_EXE = r'(?:[\w./~-]*/)?gradlew?'
_GRADLE_BLOCKED = (
    r'(?:--init-script\b|\s-I\b|--build-file\b|\s-b\b|--settings-file\b|\s-c\b)'
)

SAFE_GRADLE = re.compile(
    rf'^{_ENV_ASSIGN}{_GRADLE_EXE}(?!.*{_GRADLE_BLOCKED}){_TAIL}\s*$',
    _FL,
)

SAFE_READ_PATTERNS.append(SAFE_PYTEST)
SAFE_READ_PATTERNS.append(SAFE_GRADLE)


# ---------------------------------------------------------------------------
# Shell decomposition
# ---------------------------------------------------------------------------

def _strip_comments(cmd):
    """Remove '# ...' comments that appear at the top level (outside quotes)."""
    out = []
    i = 0
    n = len(cmd)
    in_single = in_double = in_backtick = False
    prev = "\n"  # start-of-string behaves like after a newline
    while i < n:
        c = cmd[i]
        if in_single:
            out.append(c)
            if c == "'":
                in_single = False
            prev = c
            i += 1
            continue
        if in_double:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(cmd[i + 1])
                i += 2
                prev = cmd[i - 1]
                continue
            if c == '"':
                in_double = False
            prev = c
            i += 1
            continue
        if in_backtick:
            out.append(c)
            if c == "`":
                in_backtick = False
            prev = c
            i += 1
            continue
        if c == "'":
            in_single = True
        elif c == '"':
            in_double = True
        elif c == "`":
            in_backtick = True
        elif c == "#" and prev in (" ", "\t", "\n", ";"):
            # skip to end of line
            while i < n and cmd[i] != "\n":
                i += 1
            continue
        out.append(c)
        prev = c
        i += 1
    return "".join(out)


_DOUBLE_SPLITS = {("&", "&"), ("|", "|")}
_SINGLE_SPLITS = {";", "|", "\n"}


def split_compound(cmd):
    """Top-level split on &&, ||, ;, |, newline.

    Quotes, backticks, and $(...) are respected. Returns a list of
    non-empty, stripped segments. Returns [cmd.stripped] if no splits occur.
    """
    cmd = _strip_comments(cmd)
    segments = []
    cur = []
    i = 0
    n = len(cmd)
    in_single = in_double = in_backtick = False
    paren_depth = 0

    def flush():
        s = "".join(cur).strip()
        if s:
            segments.append(s)
        cur.clear()

    while i < n:
        c = cmd[i]
        if c == "\\" and i + 1 < n:
            cur.append(c)
            cur.append(cmd[i + 1])
            i += 2
            continue
        if in_single:
            cur.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            cur.append(c)
            if c == '"':
                in_double = False
            i += 1
            continue
        if in_backtick:
            cur.append(c)
            if c == "`":
                in_backtick = False
            i += 1
            continue
        if c == "'":
            in_single = True
            cur.append(c)
            i += 1
            continue
        if c == '"':
            in_double = True
            cur.append(c)
            i += 1
            continue
        if c == "`":
            in_backtick = True
            cur.append(c)
            i += 1
            continue
        if c == "$" and i + 1 < n and cmd[i + 1] == "(":
            paren_depth += 1
            cur.append(c)
            cur.append("(")
            i += 2
            continue
        if paren_depth > 0:
            if c == "(":
                paren_depth += 1
            elif c == ")":
                paren_depth -= 1
            cur.append(c)
            i += 1
            continue
        if i + 1 < n and (c, cmd[i + 1]) in _DOUBLE_SPLITS:
            flush()
            i += 2
            continue
        if c in _SINGLE_SPLITS:
            flush()
            i += 1
            continue
        cur.append(c)
        i += 1
    flush()
    return segments if segments else [cmd.strip()]


_GIT_SUB_RE = re.compile(
    r'^\s*git(?:\s+-[Cc]\s+\S+)*\s+([A-Za-z][\w-]*)'
)
# `-C <path>` changes git's working directory. (`-c key=val` is config; ignore.)
_GIT_DASH_C_RE = re.compile(r'(?:^|\s)-C\s+(\S+)')


def git_subcommand(segment):
    """Return the git subcommand word for a segment starting with git, else None.

    Regex-based so it tolerates heredocs and $(...) bodies where shlex chokes.
    """
    m = _GIT_SUB_RE.match(segment)
    return m.group(1) if m else None


def git_segment_cwd(segment, default_cwd):
    """Effective cwd for a `git ...` segment: last `-C <path>` wins, else default."""
    last = None
    for m in _GIT_DASH_C_RE.finditer(segment):
        last = m.group(1)
    return last if last is not None else default_cwd


def is_safe_read(segment):
    return any(pat.match(segment) for pat in SAFE_READ_PATTERNS)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

def current_branch(cwd=None):
    try:
        out = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=cwd, capture_output=True, text=True, timeout=2, check=True,
        )
        return out.stdout.strip() or None
    except Exception as e:
        log(f"git branch check failed in {cwd!r}: {e}")
        return None


def decide(payload):
    if payload.get("tool_name") != "Bash":
        return None
    command = payload.get("tool_input", {}).get("command", "")
    if not command:
        return None

    segments = split_compound(command)
    if not segments:
        return None

    default_cwd = payload.get("cwd")
    gated_cwds = []
    for seg in segments:
        if is_safe_read(seg):
            continue
        sub = git_subcommand(seg)
        if sub in GATED_GIT:
            gated_cwds.append(git_segment_cwd(seg, default_cwd))
            continue
        log(f"abstain - unrecognized segment: {seg!r}")
        return None

    if not gated_cwds:
        return {
            "permissionDecision": "allow",
            "permissionDecisionReason": "All-safe compound",
        }

    # Resolve each gated segment's branch. Cache per-cwd so a compound like
    # `git add ... && git commit ...` only shells out once.
    branch_cache = {}
    for cwd in gated_cwds:
        key = cwd or ""
        if key not in branch_cache:
            branch_cache[key] = current_branch(cwd)
        branch = branch_cache[key]
        if branch is None:
            return None
        if branch in PROTECTED:
            return {
                "permissionDecision": "ask",
                "permissionDecisionReason": f"Protected branch '{branch}' - approve manually.",
            }
    summary = ", ".join(sorted({b for b in branch_cache.values() if b}))
    return {
        "permissionDecision": "allow",
        "permissionDecisionReason": f"Gated git op on branch '{summary}'",
    }


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def log(msg):
    try:
        with LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass


def main():
    try:
        raw = sys.stdin.read()
        try:
            payload = json.loads(raw)
        except Exception as e:
            log(f"bad stdin JSON ({e}): {raw[:500]!r}")
            return
        result = decide(payload)
        if result is None:
            return
        hook_output = {"hookEventName": "PreToolUse"}
        hook_output.update(result)
        print(json.dumps({"hookSpecificOutput": hook_output}))
    except Exception:
        log("uncaught exception:\n" + traceback.format_exc())


main()

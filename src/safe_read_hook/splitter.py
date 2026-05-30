"""Compound-command splitter — ported VERBATIM from the seed (D-09).

``split_compound`` and ``_strip_comments`` are byte-identical ports of the
security-reviewed seed (``git-commit-branch-gate.py`` lines 178-319): the
quote/backtick/``$()``-aware top-level split on ``&&``, ``||``, ``;``, ``|``,
and newline. This is the cardinal security path — it must NOT be rewritten;
only type annotations are added to satisfy the type checker without changing
behavior. The seed's recognizer/git helpers are deliberately left behind.
"""

from __future__ import annotations

_DOUBLE_SPLITS = {("&", "&"), ("|", "|")}
_SINGLE_SPLITS = {";", "|", "\n"}


def _strip_comments(cmd: str) -> str:
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


def split_compound(cmd: str) -> list[str]:
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

    def flush() -> None:
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

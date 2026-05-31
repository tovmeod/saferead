"""The one minimal happy-path read-only command recognizer (D-11/D-12).

This recognizer is deliberately thin. The zero-false-allow promise does NOT
come from breadth here — it comes from the engine's abstain-veto fold (D-13):
one unrecognized segment vetoes a whole compound to abstain. So the reader only
needs to claim a narrow, unambiguously read-only command set, and abstain
(return ``None``) on everything else.

Command set: ``echo``/``printf``, a group of file-inspection readers, and a
group of read-only text filters. Write-capable commands are intentionally NOT
claimed; they belong to later phases.

Redirect fence (closes backlog 999.1 #7): the argument tail accepts ordinary
argument tokens and ONLY discard redirects (``>/dev/null``, ``2>&1`` and
friends), which never touch a user file. A redirect to any real file makes the
whole segment unrecognized, so the recognizer abstains rather than approve a
write. Real redirect handling is a later phase.
"""

from __future__ import annotations

import re

from ..context import Context
from ..verdict import Verdict

# A single argument token: a quoted string or a run of non-special chars.
# Crucially excludes ``>`` so a redirect can never be swallowed as an argument.
#
# The double-quoted alternative is a per-``$`` POSITIVE-LOOKAHEAD ALLOWLIST: a
# ``$`` is admitted ONLY when it begins a parameter/variable expansion — a bare
# special/name/positional char (``[a-zA-Z_0-9@*#?$!-]``) or ``{`` then a
# name/length/indirect/special char (``[a-zA-Z_0-9@*#?!]``). EVERY other ``$``
# fails the lookahead, so the whole token fails to match -> fold-veto abstain.
# This abstains on every command substitution whose opener carries a ``$`` or
# backtick (bash does NOT disable substitution inside double quotes): ``$(``
# (CR-02), ``${ cmd; }`` / ``${| cmd; }`` bash-5.3 funsub (CR-funsub), backtick,
# AND any unforeseen ``${X`` OPENER — the allowlist FAILS CLOSED on novel opener
# syntax rather than admitting it.
#
# KNOWN RESIDUAL CLASS (CR-bodyeval, accepted 2026-05-31 — a CLASS, not one
# vector; do NOT restate as closed): the lookahead gates only the ``${`` OPENER;
# ``[^"$`]`` then swallows the brace BODY, so any operator there that
# re-evaluates the VALUE of a referenced variable is invisible to the regex —
# and a regex cannot inspect brace-body operators without parsing the ``${...}``
# grammar. Known members (each executes cmdsub held in a PRE-EXISTING var, with
# no explicit ``$`` in the string): ``${x@P}`` (the ``@P`` prompt transform
# re-expands the value as a prompt); ``${s:i}`` / ``${arr[i]}`` (arithmetic
# substring/subscript recursively evaluate operand ``i``'s contents). The class
# is NOT provably enumerable by inspection, and a body-operator denylist is the
# same enumeration treadmill that reopened this phase three times. All members
# are env-conditional (pre-existing hostile var required; in-band assignment is
# fold-vetoed), pinned ``xfail(strict=True)`` in tests/test_corpus.py, and left
# for the PURE-LITERAL policy follow-up (which terminates the class regardless of
# mechanism — a tokenizer alone does not). See 03-04-REVIEW.md + STATE FOLLOW-UP 1.
#
# Per-``$`` gating is the load-bearing invariant: the ``[^"$`]`` char class
# excludes every ``$``, so each ``$`` inside a ``${...}`` body is independently
# re-gated. Nested command substitution ``"${x:-$(id)}"`` stays closed — the
# inner ``$`` is followed by ``(``, which is in NEITHER allowed set, so the token
# fails to match. This is NOT a chunk-match of ``${...}`` as one unit (which would
# never re-gate the inner ``$(``).
#
# Variable / parameter expansion (``"$HOME"``, ``"a$b"``, ``"${HOME}"``,
# ``"${x:-d}"``) is NOT command execution and stays allowed. A bare ``$`` not
# beginning a recognized expansion (``"$"`` end-anchor, ``"$$"`` PID) now abstains
# — a conscious over-abstain (prompt the safe command) traded for the cardinal
# zero-false-allow guarantee, not a cardinal failure. A token-based recognizer is
# the planned follow-up phase that replaces this regex entirely.
# The positive-lookahead allowlist stays on one contiguous regex literal;
# splitting it would obscure the per-`$` gating. Hence the trailing line-length
# waiver below.
_QARG = r"""(?:'[^']*'|"(?:[^"$`]|\$(?=[a-zA-Z_0-9@*#?$!-]|\{[a-zA-Z_0-9@*#?!]))*"|[^;&|`$>\s]+)"""  # noqa: E501

# Redirects that discard output and never write a user file. Safe to keep.
_DISCARD_REDIR = r"(?:2>&1|>/dev/null|2>/dev/null|&>>?/dev/null)"

# Zero-or-more trailing (argument | discard-redirect) tokens. A redirect to a
# real file matches neither alternative, so the overall match fails -> abstain.
_TAIL = rf"(?:\s+{_QARG}|\s+{_DISCARD_REDIR})*"

# echo / printf.
_CMD_ECHO = r"(?:echo|printf)"

# File-inspection readers — all read-only in bare form.
_CMD_FILE_READERS = (
    r"(?:cat|bat|less|more|ls|file|stat|readlink|realpath|basename|dirname|"
    r"pwd|which|whereis|type|du|df)"
)

# Read-only text filters (the seed filter group, with the two write-capable
# members removed — those are deferred to a later phase).
_CMD_FILTERS = (
    r"(?:grep|egrep|fgrep|rg|ag|head|tail|wc|uniq|cut|tr|jq|column|nl|rev|tac|"
    r"base64|xxd|od|strings|diff|comm|paste|join|fold|expand|unexpand)"
)

_READER_RE = re.compile(
    rf"^(?:{_CMD_ECHO}|{_CMD_FILE_READERS}|{_CMD_FILTERS})\b{_TAIL}\s*$",
    re.DOTALL,
)


def recognize_reader(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a known read-only command, else ``None``.

    Abstains (``None``) on any unrecognized command and on any redirect to a
    real file — the cardinal zero-false-allow behavior.
    """
    if _READER_RE.match(segment):
        return Verdict("allow", "read-only command", "reader")
    return None

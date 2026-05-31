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
# The double-quoted alternative rejects ``$(`` and backtick (CR-02): bash does
# NOT disable command substitution inside double quotes, so ``"$(id)"`` /
# ``"`id`"`` are command execution and must make the segment unrecognized ->
# fold-veto abstain. Variable expansion (``"$HOME"``, ``"a$b"``) is NOT command
# execution and stays allowed — the conscious minimal-over-restriction boundary.
_QARG = r"""(?:'[^']*'|"(?:[^"$`]|\$(?!\())*"|[^;&|`$>\s]+)"""

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

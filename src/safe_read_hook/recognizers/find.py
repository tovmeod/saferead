"""The read-only ``find`` recognizer (REC-04, D-04).

``find`` is recognized by an ALLOWLIST of read-only predicates, inverting the
seed's fail-open denylist. Only the read-only test predicates and the stdout
actions (``-print``/``-print0``/``-ls``/``-quit``/``-prune``) are admitted; any
token not on the allowlist makes the whole command abstain (return ``None``).

Why allowlist-by-omission (the cardinal design choice): the seed denied a fixed
set of dangerous actions (``-exec``/``-delete``/…) and so MISSED the
file-writing ``-fprint``/``-fprintf``/``-fprint0``/``-fls`` (B4) siblings — a
fail-open gap. Here those families, AND ``-exec``/``-execdir``/``-ok``/
``-okdir``/``-delete``, AND any future or obscure GNU action are closed BY
CONSTRUCTION: they simply are not on any allowlist, so they fall through to the
abstain branch. There is deliberately NO denylist membership test against
``-exec``/``-delete``/``-fprint*`` — adding one would re-introduce the
enumeration treadmill the inversion exists to end.

Value-token rule (Pitfall 3): a value-bearing predicate (``-mtime``, ``-size``,
``-name``, …) consumes its NEXT token as an OPAQUE value. Common forms carry a
value that itself starts with ``-`` or ``+`` (``-mtime -7``, ``-size +100M``);
that value must NOT be classified as a predicate, so the loop skips it. A
value-bearing predicate with no following token is malformed -> abstain.

Tokenizer abstain is the recognizer's abstain (D-06): any non-allowlisted
expansion (``$(...)``/backtick/brace-body) makes ``tokenize`` abstain, and the
recognizer inherits it. A trailing redirect is routed through the shared
``redirect_tail_is_safe`` helper (the single ``/tmp`` + discard policy, D-05);
a non-safe redirect target abstains.
"""

from __future__ import annotations

from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from .redirects import redirect_tail_is_safe

#: Read-only flag predicates / stdout actions that take NO value. The stdout
#: actions ``-print``/``-print0``/``-ls``/``-quit``/``-prune`` write only to
#: stdout (never a file), so they are safe. The file-writing ``-fprint``/
#: ``-fprintf``/``-fprint0``/``-fls`` siblings are deliberately ABSENT.
_FLAG_PREDICATES = frozenset(
    {
        # read-only test predicates (no value)
        "-empty",
        "-depth",
        "-prune",
        "-follow",
        "-mount",
        "-xdev",
        "-nouser",
        "-nogroup",
        "-readable",
        "-writable",
        "-executable",
        "-noleaf",
        "-ignore_readdir_race",
        "-noignore_readdir_race",
        "-warn",
        "-nowarn",
        "-daystart",
        # stdout actions (write to stdout only, never a file)
        "-print",
        "-print0",
        "-ls",
        "-quit",
    }
)

#: Read-only predicates that CONSUME the next token as an opaque value. ``-printf``
#: writes only to stdout (a format string, not a file) so it is read-only here;
#: its file-writing sibling ``-fprintf`` is absent. ``-files0-from`` (reads a
#: file list) is OMITTED — uncertain, so abstain.
_VALUE_PREDICATES = frozenset(
    {
        "-maxdepth",
        "-mindepth",
        "-name",
        "-iname",
        "-path",
        "-ipath",
        "-wholename",
        "-iwholename",
        "-regex",
        "-iregex",
        "-lname",
        "-ilname",
        "-type",
        "-xtype",
        "-size",
        "-mtime",
        "-atime",
        "-ctime",
        "-mmin",
        "-amin",
        "-cmin",
        "-newer",
        "-anewer",
        "-cnewer",
        "-used",
        "-user",
        "-group",
        "-uid",
        "-gid",
        "-perm",
        "-inum",
        "-links",
        "-samefile",
        "-regextype",
        "-printf",
        "-context",
        "-fstype",
    }
)

#: Boolean / grouping operators. The tokenizer preserves the shell-escaped
#: parens (``\(`` / ``\)``); the bare forms are kept too (harmless).
_GROUPING = frozenset(
    {
        "(",
        ")",
        r"\(",
        r"\)",
        "!",
        "-a",
        "-and",
        "-o",
        "-or",
        "-not",
        ",",
    }
)


def recognize_find(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a read-only ``find``, else ``None``.

    Allows when EVERY predicate is on the read-only allowlist (test predicates
    + stdout actions); abstains on any unrecognized token — which is every
    exec/write/delete action by omission (D-04). Value-bearing predicates skip
    their opaque value token (Pitfall 3). A trailing redirect must pass the
    shared ``/tmp`` + discard policy.
    """
    result = tokenize(segment)
    # The tokenizer holds ALL expansion safety; its abstain is the recognizer's.
    if result.abstain_reason is not None:
        return None
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens or tokens[0] != "find":
        return None

    args = tokens[1:]

    # A trailing redirect must be a discard or a /tmp scratch write (the single
    # shared policy). A redirect token does not start with ``-``/``+`` so the
    # classification loop treats it as a bare operand; this helper is what
    # vetoes a non-safe target. Routed over the FULL tail.
    if not redirect_tail_is_safe(args):
        return None

    i = 0
    n = len(args)
    while i < n:
        tok = args[i]

        # A value-bearing predicate consumes its NEXT token as an opaque value
        # (so a value like ``-7``/``+100M`` is never classified as a predicate).
        # The ``-newerXY`` family is value-bearing too.
        if tok in _VALUE_PREDICATES or tok.startswith("-newer"):
            if i + 1 >= n:
                return None  # malformed: predicate with no value
            i += 2
            continue

        # A no-value flag predicate / stdout action.
        if tok in _FLAG_PREDICATES:
            i += 1
            continue

        # A grouping / boolean operator.
        if tok in _GROUPING:
            i += 1
            continue

        # A bare path operand (does not start with ``-``/``+``, not grouping).
        if not tok.startswith(("-", "+")):
            i += 1
            continue

        # ANY other token — ``-exec``/``-execdir``/``-ok``/``-okdir``/``-delete``/
        # ``-fprint``/``-fprintf``/``-fprint0``/``-fls``/an unknown ``-predicate``
        # — is NOT on any allowlist and abstains BY CONSTRUCTION (D-04). There is
        # intentionally no denylist enumeration here.
        return None

    return Verdict("allow", "read-only find", "find")

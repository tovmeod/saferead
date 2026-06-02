"""The read-only git recognizer (REC-01) — the zero-false-allow git boundary.

Read-only git subcommands (``status``/``log``/``diff``/``show``/``blame``/...)
auto-allow, honoring ``git -C <path>``. Two cardinal false-allow classes are
closed BY CONSTRUCTION, not by enumerating dangerous tokens:

1. Config injection (corpus bypass #5). ``git -c core.fsmonitor=<cmd> status``
   executes ``<cmd>`` via git config. The leading-option scan is an ALLOWLIST
   (D-07): only ``-C <path>`` is consumed to reach the subcommand; ``-c`` and
   EVERY other leading option (``--exec-path``, ``--paginate``, ``--config-env``,
   ``--work-tree``, ``--namespace``, bare ``--``) abstain. ``-c`` != ``-C``, so
   the scan abstains before the subcommand is ever classified.

2. Mutating forms of "read-only" subcommands (D-06). ``git branch <newname>``
   creates a ref, ``git tag <name>`` creates a tag, ``git remote add``,
   ``git config k v``, ``git worktree add``, ``git notes add``,
   ``git reflog delete`` all mutate. Recognition is per-subcommand argument
   SHAPE — a subcommand-WORD match is never sufficient; only proven read-only
   shapes are admitted.

Dangerous-flag class (the operator-fence blindspot, MEMORY.md): a write/exec
flag need not contain ``>`` or ``&`` — ``git diff --output=PATH`` writes a file
and ``git grep -O<cmd>`` execs a pager, both with no redirect token. A ``>``/``&``
fence alone would false-allow them. So EVERY subcommand uses allowlist polarity
on its option flags (mirroring reader.py's ``file`` discipline): an unrecognized
``-``-leading token abstains. The general read group (``status``/``log``/...) is
admitted in bare/positional form only; the per-subcommand groups
(``branch``/``tag``/``config``/...) admit only their listed read-only flags.

GATED subcommands are exactly ``_GATED`` = ``add``/``commit``/bare ``stash``
(NOT ``push``): they are state-mutating, so they are NOT auto-allowed here — the
protected-branch ASK verdict lands in Plan 05-02, which EXTENDS the leading-option
scan to capture last-``-C``-wins ``effective_cwd`` for the branch probe. ``push``
and ``stash push`` are NOT gated; they currently fall through to ``None``
(abstain). The read-only path NEVER resolves the branch (Pitfall 1).
"""

from __future__ import annotations

import re

from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict

# Discard redirects that never write a user file (mirrors reader.py). A token
# matching this EXACTLY (``fullmatch``) is permitted; any other token bearing a
# ``>`` (redirect to a real file) or ``&`` (background/control) -> abstain. The
# tokenizer leaves both glued into a word token, so the recognizer inspects the
# token TEXT — a ``-``-leading flag check alone does NOT catch ``git log >/tmp/x``.
_DISCARD_REDIR = re.compile(r"(?:2>&1|>/dev/null|2>/dev/null|&>>?/dev/null)")

# Hardcoded policy constants (D-04). Phase 9 replaces these with TOML; do NOT
# pull config forward. Both are defined here even though only Plan 05-02 consumes
# them (interface-first — 05-02 must not reach back to add them).
_PROTECTED = frozenset({"master", "main"})
_GATED = frozenset({"add", "commit", "stash"})

# General read-only subcommands, admitted in BARE/positional form only. Any
# ``-``-leading option on these abstains (allowlist polarity) — this closes
# ``--output``/``-O`` write/exec flags by construction. A bare positional
# (a path/pathspec/ref) is a read argument and is permitted.
_READ_ONLY_GENERAL = frozenset(
    {
        "show",
        "log",
        "diff",
        "status",
        "blame",
        "rev-parse",
        "describe",
        "ls-files",
        "ls-tree",
        "cat-file",
        "shortlog",
        "grep",
        "for-each-ref",
        "merge-base",
        "name-rev",
        "whatchanged",
        "count-objects",
        "verify-commit",
        "verify-tag",
        "rev-list",
        "show-ref",
        "diff-tree",
        "diff-index",
        "diff-files",
        "cherry",
        "var",
        "help",
        "version",
    }
)

# Per-subcommand read-only OPTION-FLAG allowlists (D-06 argument-SHAPE). A
# subcommand here admits ONLY: bare form, positional args that are NOT a creating
# shape, and the listed read-only flags. Anything else -> abstain. Membership is
# CONSERVATIVE — a flag is listed only when its read-only status is certain.
_BRANCH_READ_FLAGS = frozenset(
    {"-l", "--list", "-v", "-vv", "-a", "-r", "--show-current"}
)
_TAG_READ_FLAGS = frozenset({"-l", "--list", "-n"})
_CONFIG_READ_FLAGS = frozenset({"--get", "--get-all", "--get-regexp", "--list", "-l"})


def recognize_git(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a read-only git command, else ``None``.

    Read-only path only: never resolves the branch (Pitfall 1). Abstains on
    tokenizer abstain, multi-segment input, a non-git leading word, any
    leading option other than ``-C <path>`` (closes bypass #5), a missing
    subcommand, and any subcommand/argument shape not provably read-only.
    """
    result = tokenize(segment)
    # The tokenizer holds ALL expansion safety; its abstain is the recognizer's.
    if result.abstain_reason is not None:
        return None
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens or tokens[0] != "git":
        return None

    # Leading-option scan (D-07, allowlist polarity). Walk options after ``git``
    # and before the subcommand. Only ``-C <path>`` is consumed (the pair is
    # skipped to reach the subcommand); the path is CAPTURED as last-``-C``-wins
    # ``effective_cwd`` (default ``ctx.cwd``) for the gated branch probe — the
    # capture lives here with its consumer below. Every other leading ``-...``
    # token (incl. ``-c``, ``--exec-path``, ``--paginate``, ``--config-env``,
    # ``--work-tree``, ``--namespace``, bare ``--``) -> abstain.
    effective_cwd = ctx.cwd
    i = 1
    while i < len(tokens) and tokens[i].startswith("-"):
        if tokens[i] == "-C" and i + 1 < len(tokens):
            cval = tokens[i + 1]
            # The ``-C`` value token is consumed here (below the final ``i``), so
            # the post-subcommand redirect/control fence (which only scans
            # ``tokens[i + 1:]``) never sees it. A ``>``/``&`` glued into that
            # value (``git -C x&id log`` execs ``id``; ``git -C >/tmp/x status``
            # truncates a file — the tokenizer keeps both as one word) would
            # otherwise reach an ALLOW. Apply the SAME fence here as the value is
            # captured (cardinal zero-false-allow).
            if not _DISCARD_REDIR.fullmatch(cval) and (">" in cval or "&" in cval):
                return None
            effective_cwd = cval  # last -C wins
            i += 2  # consume ``-C`` and its path token
            continue
        return None  # ``-c`` and every other leading option fail closed

    # Classify the subcommand = first non-option token.
    if i >= len(tokens):
        return None  # bare ``git`` (or ``git -C`` with no following token)
    sub = tokens[i]
    args = tokens[i + 1 :]

    # Redirect / control fence (applies to EVERY subcommand, before SHAPE
    # classification). A redirect to a real file or a background operator is a
    # write/exec the `-`-leading flag check cannot see: `git log >/tmp/x`
    # tokenizes to `[..,"log",">/tmp/x"]` and `>/tmp/x` is not a flag, so the
    # SHAPE allowlist would otherwise pass it as a positional. A discard redirect
    # (`>/dev/null`, `2>&1`) is permitted (never touches a user file).
    for tok in args:
        if _DISCARD_REDIR.fullmatch(tok):
            continue
        if ">" in tok or "&" in tok:
            return None

    # Read-only SHAPE takes precedence: ``stash list``/``stash show`` are
    # read-only even though bare ``stash`` is GATED (checked next).
    if _is_read_only(sub, args):
        return Verdict("allow", "read-only git", "git")

    # GATED branch-gate verdict (D-01/D-02). _GATED = add/commit/bare stash (NOT
    # push, NOT stash push — those abstain above/fall through to None) are
    # state-mutating; gate them on the working branch. This is the ONLY place
    # recognize_git resolves the branch (Pitfall 1 — never on the read-only
    # path above). The probe is lazy + per-cwd memoized inside ctx.branch.
    if sub in _GATED:
        branch = ctx.branch(effective_cwd)
        if branch is None:
            # Detached HEAD / not-a-repo / probe error -> ASK, not abstain
            # (D-02; Pitfall 4). Treat unknown like protected — fail-safe
            # visible. Diverges from the seed's abstain.
            return Verdict("ask", "unresolved branch — approve manually", "git")
        if branch in _PROTECTED:
            return Verdict("ask", f"protected branch '{branch}'", "git")
        return Verdict("allow", f"gated git op on '{branch}'", "git")

    return None


def _is_read_only(sub: str, args: list[str]) -> bool:
    """True iff subcommand ``sub`` with ``args`` is a proven read-only SHAPE.

    Allowlist polarity throughout: a subcommand-word match is never sufficient,
    and an unrecognized ``-``-leading token (a possible write/exec flag with no
    ``>``/``&`` token, e.g. ``diff --output=PATH``, ``grep -O<cmd>``) abstains.
    """
    if sub in _READ_ONLY_GENERAL:
        # Bare/positional form only: reject ANY option flag (closes
        # ``--output``/``-O`` by construction). A bare ``--`` is also rejected
        # (no need on a read path). Positional args (paths/refs) are reads.
        return not any(_is_option(tok) for tok in args)

    if sub == "branch":
        # Listing flags only; a bare positional CREATES a ref -> abstain.
        return _all_flags_in(args, _BRANCH_READ_FLAGS) and not _has_positional(args)

    if sub == "tag":
        # Listing flags only; a bare positional (``tag <name>``) CREATES -> abstain.
        return _all_flags_in(args, _TAG_READ_FLAGS) and not _has_positional(args)

    if sub == "remote":
        # bare ``remote``; ``remote -v``; ``remote get-url <name>``;
        # ``remote show -n <name>`` — all LOCAL reads. add/remove/set-url and the
        # network-querying ``remote show`` (without -n) -> abstain.
        if not args:
            return True
        if args == ["-v"] or args == ["--verbose"]:
            return True
        if args[0] == "get-url":
            # the rest are positional remote names (reads); no option flags.
            return not any(_is_option(tok) for tok in args[1:])
        if args[0] == "show":
            # ``remote show <name>`` queries the remote over the network by
            # default (the equivalent of ``git ls-remote``) — egress, same class
            # as the line-below ``ls-remote`` abstain (D-09). Only the LOCAL
            # ``-n``/``--no-query`` form is read-only; require it and allow no
            # other option flag.
            rest = args[1:]
            if not any(f in ("-n", "--no-query") for f in rest):
                return False
            return all(
                tok in ("-n", "--no-query") or not _is_option(tok) for tok in rest
            )
        return False

    if sub == "config":
        # A read flag MUST be present AND no other option flag (a bare ``k v``
        # pair WRITES; ``--file <path>`` reads an arbitrary file).
        if not args:
            return False
        if args[0] not in _CONFIG_READ_FLAGS:
            return False
        # No further option flags (reject ``--file``/``--global``-targeting writes
        # and any second option). Remaining tokens are positional keys (reads).
        return not any(_is_option(tok) for tok in args[1:])

    if sub == "worktree":
        return args == ["list"]

    if sub == "notes":
        return args == ["show"]

    if sub == "reflog":
        # bare ``reflog`` and ``reflog show`` only; delete/expire/drop -> abstain.
        if not args:
            return True
        if args[0] == "show":
            return not any(_is_option(tok) for tok in args[1:])
        return False

    if sub == "stash":
        # ONLY ``stash list`` / ``stash show`` are read-only here. Bare ``stash``
        # is GATED (handled upstream via _GATED); push/pop/apply/drop/clear are
        # not read-only.
        if not args:
            return False
        if args[0] in ("list", "show"):
            return not any(_is_option(tok) for tok in args[1:])
        return False

    # ``ls-remote`` (D-09 network egress) and every unlisted subcommand abstain.
    return False


def _is_option(tok: str) -> bool:
    """True iff ``tok`` is an option flag (starts with ``-``, excluding bare ``-``)."""
    return tok.startswith("-") and tok != "-"


def _all_flags_in(args: list[str], allowed: frozenset[str]) -> bool:
    """True iff every option-flag token in ``args`` is on the ``allowed`` set."""
    return all((not _is_option(tok)) or tok in allowed for tok in args)


def _has_positional(args: list[str]) -> bool:
    """True iff any token is a non-option positional (a creating arg for branch/tag)."""
    return any(not _is_option(tok) for tok in args)

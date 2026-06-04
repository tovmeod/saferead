"""The read-only ``adb`` recognizer (REC-07, D8-05/D8-06).

``adb`` is the ONLY tool in Phase 8 where ``allow`` is a GENUINE read-only proof
(unlike pytest/gradle, whose ``allow`` is an opt-in trust grant for executing
project code). Two surfaces, each allowlist-polarity (D-05/D-16):

1. A SUBCOMMAND ALLOWLIST (``_SAFE_ADB``): the six proven-safe read-only
   subcommands ported from the seed (intent only, D4-03) —
   ``logcat``/``devices``/``get-state``/``get-serialno``/``version``/``help``.
   Everything else abstains BY OMISSION: push/pull/install/uninstall/sync,
   start-server/kill-server/root/unroot/remount, connect/disconnect/forward/
   reverse, bugreport. The uncertain candidates (``get-devpath``/``features``/
   ``host-features``) are deliberately NOT admitted — coverage loss is free,
   but admitting an uncertain entry would be the cardinal failure (T-08-01).

   CARDINAL — a subcommand-WORD match is NOT sufficient (T-08-01b). ``adb logcat
   -c``/``--clear`` CLEARS the device log buffer (a mutation); ``-f``/``--file``,
   ``-r``/``--rotate-kbytes``, ``-n`` write/rotate device files. So each
   allowlisted subcommand carries a per-subcommand AUDITED read-only FLAG
   allowlist (``_SAFE_ADB_FLAGS``, mirroring the Phase-4 ``_READ_ONLY_FLAGS``
   precedent in reader.py). The audit (conservative — abstain when uncertain,
   D8-05):

   - ``logcat`` -> frozenset() — NO flags admitted. Bare ``adb logcat`` is the
     common read; ``-c``/``-f``/``-r``/``-n``/``-b``/``-g``/``-G`` mutate or are
     unaudited -> abstain by omission.
   - ``devices`` -> {``-l``, ``--long``} — a long listing, read-only.
   - ``get-state``/``get-serialno``/``version``/``help`` -> frozenset() — no
     read-only flags.

   A subcommand with NO entry permits the BARE form only. An option token (a
   ``startswith("-")`` token, excluding bare ``-``) abstains unless its NAME —
   after splitting a long ``--flag=value`` on ``=``, and for a glued short flag
   its 2-char head — EXACTLY matches an entry in that subcommand's allowlist.
   This closes the glued/``=value``/split blindspot (MEMORY.md flag-audit
   lesson). Since the only admitted set is ``devices`` ``-l``/``--long``, any
   unaudited flag abstains by omission.

2. ``adb shell <cmd>`` — the engine RE-ENTRY seam (D8-06) Phase 13's
   ssh-journalctl recognizer inherits. The remote command string (sliced RAW
   from the segment AFTER the ``shell`` word so quoting is preserved) is
   re-decomposed through the EXISTING engine ``fold``:

       inner = fold(tokenize(remote).segments, ctx)

   - bare ``adb shell`` (no remote command) opens an INTERACTIVE shell -> abstain.
   - a shell OPTION before the command (``-t``/``-T``/``-x``/``-n``) -> abstain
     (do NOT allowlist shell options; free coverage loss, T-08-04).
   - adb's OWN OUTER tail (a host redirect OUTSIDE the remote quotes, e.g.
     ``adb shell "echo hi" >/etc/passwd``) is routed through the shared
     ``redirect_tail_is_safe`` (the D-05 policy) — the redirect appears as a
     trailing adb token, caught here in addition to the inner re-fold (T-08-03).
   - INNER-VERDICT rule: ``inner is None`` -> abstain; ``inner.decision ==
     "ask"`` -> abstain (do NOT propagate an ask up through adb — simplest safe
     choice); ``inner.decision == "allow"`` -> re-wrap as
     ``Verdict("allow", "adb shell read", "adb")`` so the tag identifies THIS
     recognizer (``fold`` returns the inner tag, e.g. ``"reader"``).

   SAFETY (T-08-02): lossy token re-join can only OVER-segment (more abstains),
   never MERGE two commands into one — so the re-decompose cannot create a
   false-allow. We pass the RAW segment slice to ``tokenize`` (never re-joined /
   de-quoted tokens), so the inner reader re-tokenizes the true structure. A
   consequence (accepted over-abstain, NOT a bug): a quoted single command
   ``adb shell "cat /x"`` abstains — the quoted blob's leading word ``cat /x``
   is not ``cat``. The allow cases are all UNQUOTED. The inner-operator abstains
   ``"ls && rm -rf /"`` / ``"rm -rf /; reboot"`` / ``"cat >/etc/passwd"`` /
   ``'echo a;b'`` PIN that a smuggled mutation re-folds to abstain.

Tokenizer abstain is the recognizer's abstain (D8-08): ``$(...)``/backtick/
brace-body all already abstain in ``tokenize``, so ``adb shell "$(id)"``
abstains there.

CIRCULAR-IMPORT fix (NOT a TODO): ``recognizers/__init__`` imports
``recognize_adb`` -> a module-top ``from ..engine import fold`` would trigger
``engine.py`` -> ``from .recognizers import REGISTRY`` while
``recognizers/__init__`` is still mid-import -> ImportError. Resolution:
``tokenize`` is imported at module top (``tokenizer.py`` has no package imports,
safe); ``fold`` is imported LAZILY inside ``recognize_adb``. ``engine.py`` stays
byte-untouched.
"""

from __future__ import annotations

from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from .redirects import redirect_tail_is_safe

#: Proven-safe read-only ``adb`` subcommands (ported from the seed, intent only,
#: D4-03). Deliberately EXCLUDES shell (handled via engine re-entry) and every
#: write/daemon/connection subcommand. Uncertain candidates (get-devpath,
#: features, host-features) are NOT admitted (D8-05 — coverage loss is free).
_SAFE_ADB = frozenset(
    {"logcat", "devices", "get-state", "get-serialno", "version", "help"}
)

#: Per-subcommand AUDITED read-only FLAG allowlist (T-08-01b). A subcommand-word
#: match is NOT sufficient: ``adb logcat -c`` clears the device log buffer.
#: ``logcat`` admits NO flags (bare form only); ``devices`` admits the read-only
#: long listing ``-l``/``--long``; the rest admit no flags. A subcommand with no
#: entry permits the bare form only.
_SAFE_ADB_FLAGS: dict[str, frozenset[str]] = {
    "logcat": frozenset(),
    "devices": frozenset({"-l", "--long"}),
    "get-state": frozenset(),
    "get-serialno": frozenset(),
    "version": frozenset(),
    "help": frozenset(),
}


def _flag_is_audited(tok: str, allowed: frozenset[str]) -> bool:
    """Return True if option token ``tok`` is on the subcommand's read-only set.

    Handles all three token shapes (MEMORY.md flag-audit blindspot): split exact
    (``-l``), long ``--flag=value`` (split on ``=`` before membership), and a
    glued short flag (match its 2-char head). Any flag not exactly named on the
    allowlist returns False -> abstain by omission.
    """
    if tok.startswith("--"):
        # Long flag: split a ``=value`` tail before membership.
        name = tok.split("=", 1)[0]
        return name in allowed
    # Short flag: exact match, or a glued short flag whose 2-char head is admitted.
    if tok in allowed:
        return True
    return len(tok) > 2 and tok[:2] in allowed


def recognize_adb(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a read-only ``adb`` invocation, else ``None``.

    Allows the six read-only subcommands in bare form (plus the audited read-only
    flags per subcommand), and ``adb shell <cmd>`` when the remote command
    re-decomposes to a read-only allow through the existing engine. Abstains on
    everything else by omission (D8-05) — including any global option, any
    mutating/unaudited flag, an interactive bare shell, an inner mutation, an
    inner operator/redirect, an outer host-redirect, and any tokenizer abstain.
    """
    result = tokenize(segment)
    # The tokenizer holds ALL expansion safety; its abstain is the recognizer's.
    if result.abstain_reason is not None:
        return None
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens or tokens[0] != "adb":
        return None

    # Bare ``adb`` (no subcommand) -> abstain.
    if len(tokens) < 2:
        return None

    sub = tokens[1]

    # No adb global options: ``adb -s SERIAL …`` / ``-H host`` / ``-P port`` ->
    # abstain (free coverage loss; avoids opening an egress option, T-08-04).
    if sub.startswith("-"):
        return None

    if sub == "shell":
        return _recognize_adb_shell(segment, tokens, ctx)

    if sub in _SAFE_ADB:
        rest = tokens[2:]
        allowed = _SAFE_ADB_FLAGS.get(sub, frozenset())
        for tok in rest:
            # Only option flags are constrained here (a bare ``-`` or a
            # positional operand is not an option). Redirect tokens are not
            # ``-``-leading and are vetted by ``redirect_tail_is_safe`` below.
            is_option = tok.startswith("-") and tok != "-"
            if is_option and not _flag_is_audited(tok, allowed):
                return None
        # Complementary outer ``>``/``&`` fence over the FULL tail (D-05).
        if not redirect_tail_is_safe(rest):
            return None
        return Verdict("allow", "read-only adb", "adb")

    # Anything else -> abstain by omission (D8-05).
    return None


def _recognize_adb_shell(
    segment: str, tokens: list[str], ctx: Context
) -> Verdict | None:
    """Handle ``adb shell <cmd>`` via engine re-entry (D8-06).

    ``tokens`` is the tokenized ``adb shell …`` segment; ``segment`` is the RAW
    string (used to slice the remote command with its quoting intact).
    """
    rest = tokens[2:]
    # Bare ``adb shell`` -> interactive shell -> abstain.
    if not rest:
        return None
    # A shell option before the command (``-t``/``-T``/``-x``/``-n``) -> abstain
    # (do NOT allowlist shell options; free coverage loss, T-08-04).
    if rest[0].startswith("-"):
        return None
    # adb's OWN OUTER tail: a host redirect OUTSIDE the remote quotes appears as
    # a trailing adb token (``adb shell "echo hi" >/etc/passwd``). Route the full
    # tail through the shared ``/dev/null`` + ``/tmp`` policy (T-08-03).
    if not redirect_tail_is_safe(rest):
        return None

    # Slice the remote command RAW from the segment AFTER the ``shell`` word so
    # quoting is preserved (re-joining tokens loses quoting). ``shell`` is
    # tokens[1] here, so its first raw occurrence is the right one.
    idx = segment.index("shell") + len("shell")
    remote = segment[idx:]

    # Re-decompose the remote command through the EXISTING engine (lazy import
    # avoids the circular import; ``engine.py`` stays byte-untouched).
    from ..engine import fold

    inner = fold(tokenize(remote).segments, ctx)
    if inner is None or inner.decision == "ask":
        return None
    # Re-wrap as an adb verdict so the tag identifies THIS recognizer.
    return Verdict("allow", "adb shell read", "adb")

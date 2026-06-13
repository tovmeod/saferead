"""The read-only ``journalctl`` recognizer (SSH-01, D-03/D-04/D-05).

``journalctl`` is a GENUINE read-only tool: ``allow`` is a read-only proof, not
an opt-in trust grant. Two policy layers:

1. **FLAG ALLOWLIST (D-04):** ``_JOURNALCTL_FLAGS`` — the audited read-only set.
   Any unrecognized flag abstains BY OMISSION (allowlist polarity). The
   ``=value`` form is handled by ``_flag_is_audited`` (splits before membership)
   so ``--unit=nginx`` is correctly admitted and ``--vacuum-size=1G`` is
   correctly rejected (absent from allowlist).

2. **HARD REJECTS (D-05 — absent by construction):** ``-f``/``--follow``
   (streaming/blocking), ``--vacuum-size``/``--vacuum-time``/``--vacuum-files``/
   ``--rotate``/``--flush`` (mutations). These are NOT in ``_JOURNALCTL_FLAGS``;
   their absence causes abstain.

**Boot-number operand (D-04 boot flag):** ``-b -1`` passes ``-1`` as a positional
argument to ``-b`` (boot number). A token is treated as an option ONLY when it
starts with ``-`` AND its second character (if any) is NOT a digit. So ``-1``
passes through as an operand; ``-f`` is caught as an unaudited flag.

**Outer redirect fence (D-05):** ``redirect_tail_is_safe`` applied to the full
rest tokens; any non-safe redirect abstains.

**Tokenizer abstain = recognizer abstain (D8-08):** ``$(...)``/backtick/brace-body
already abstain in ``tokenize``.

D-03 standalone REGISTRY entry: ``recognize_journalctl`` is wired into the global
REGISTRY so local ``journalctl -u foo`` auto-allows. The Phase 13 Plan 02 ssh
recognizer also imports it into the scoped re-fold allowlist — single source of
truth, no duplicated logic.
"""

from __future__ import annotations

from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from .redirects import redirect_tail_is_safe

#: Audited read-only flag allowlist for ``journalctl`` (D-04).
#:
#: Each flag that takes a value argument is admitted as the flag NAME only; the
#: argument token is a positional operand and passes through freely. The ``=value``
#: form is stripped by ``_flag_is_audited`` before membership testing.
#:
#: Absent by construction (D-05 hard rejects):
#:   ``-f``/``--follow`` — streaming/blocking form.
#:   ``--vacuum-size``/``--vacuum-time``/``--vacuum-files`` — mutations.
#:   ``--rotate``/``--flush`` — mutations.
_JOURNALCTL_FLAGS: frozenset[str] = frozenset(
    {
        "-u",
        "--unit",
        "--since",
        "--until",
        "-n",
        "--lines",
        "-p",
        "--priority",
        "-o",
        "--output",
        "-r",
        "--reverse",
        "-k",
        "--dmesg",
        "-b",
        "--boot",
        "-g",
        "--grep",
        "--no-pager",
        "-e",
        "--pager-end",
    }
)


#: Short flags that CONSUME a value, so a glued ``-Xvalue`` token is the flag
#: plus its value (``-n100`` / ``-unginx`` / ``-ojson``). ONLY these admit the
#: glued 2-char-head match. Boolean short flags (``-e``/``-k``/``-r``) must NOT:
#: ``-ef`` is a POSIX short-flag BUNDLE (``--pager-end --follow``) and
#: ``--follow`` is a D-05 hard reject — admitting a glued boolean head would
#: launder a rejected/unaudited bundled flag into an allow (cardinal false-allow,
#: 13-REVIEW CR-01). A glued boolean head therefore abstains by omission.
_JOURNALCTL_VALUE_SHORT: frozenset[str] = frozenset(
    {"-u", "-n", "-p", "-o", "-g", "-b"}
)


def _flag_is_audited(tok: str, allowed: frozenset[str]) -> bool:
    """Return True if option token ``tok`` is on the read-only allowlist.

    Handles all three token shapes (MEMORY.md flag-audit blindspot): split exact
    (``-r``), long ``--flag=value`` (split on ``=`` before membership), and a
    glued VALUE short flag (match its 2-char head only when that head consumes a
    value, e.g. ``-unginx`` -> head ``-u``). A glued boolean head (``-ef``) is a
    POSIX bundle and abstains (13-REVIEW CR-01). Any flag not exactly named on
    the allowlist returns False -> abstain by omission.
    """
    if tok.startswith("--"):
        # Long flag: strip the ``=value`` tail before membership.
        name = tok.split("=", 1)[0]
        return name in allowed
    # Short flag: exact match, or a glued VALUE short flag whose 2-char head is a
    # value-consuming flag (the remainder is that flag's value). A glued boolean
    # head is a bundle that could smuggle a rejected flag -> abstain by omission.
    if tok in allowed:
        return True
    return len(tok) > 2 and tok[:2] in _JOURNALCTL_VALUE_SHORT


def recognize_journalctl(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a read-only ``journalctl`` invocation, else None.

    Allows bare ``journalctl`` and any combination of the audited read-only flags
    in ``_JOURNALCTL_FLAGS``. Abstains on any unaudited flag (allowlist polarity),
    any D-05 mutation/streaming flag (absent from the allowlist by construction),
    any non-safe outer redirect, and any tokenizer abstain.
    """
    result = tokenize(segment)
    # Tokenizer holds all expansion safety; its abstain is the recognizer's.
    if result.abstain_reason is not None:
        return None
    # Compound command (more than one pipe segment) -> abstain.
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens or tokens[0] != "journalctl":
        return None

    rest = tokens[1:]

    for tok in rest:
        # A token is an option only when it starts with ``-`` and its second
        # character (if any) is NOT a digit. This admits ``-1`` as a boot-number
        # operand (``journalctl -b -1``) while catching ``-f``/``-u``/etc.
        is_option = tok.startswith("-") and (len(tok) < 2 or not tok[1].isdigit())
        if is_option and tok != "-":
            if not _flag_is_audited(tok, _JOURNALCTL_FLAGS):
                return None

    # Outer redirect fence (D-05): any non-safe redirect on the tail abstains.
    if not redirect_tail_is_safe(rest):
        return None

    return Verdict("allow", "read-only journalctl", "journalctl")

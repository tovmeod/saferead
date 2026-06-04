"""The ``pytest`` recognizer (REC-07, D8-01/D8-02/D8-03/D8-04).

CARDINAL POSTURE — ``allow`` != proven read-only (D8-01). pytest executes
ARBITRARY project code: test bodies run, and ``conftest.py`` is imported at
COLLECTION time (so even ``--collect-only`` runs project code — there is no
execution-free pytest form). This recognizer is therefore a deliberate OPT-IN
TRUST grant on the user's OWN project, NOT a proof of side-effect-freedom
(impossible). Its job is the narrower "ensure it runs THE project, not a
redirected/injected one" — i.e. guard the project boundary, not the side-effect
boundary. This is the conscious, recorded departure from D-15/D-16, mirroring
Phase 7's D-03a residual.

The module name is ``pytest_runner.py`` (NOT ``pytest.py``) so importing this
package never shadows the pytest test framework (D8-07 / the PATTERNS caveat).

Two stages:

1. LAUNCHER-PREFIX SCAN (allowlist polarity on the prefix; the ported seed
   grammar D8-02 is the allowlist). Walk an index ``i`` from 0 consuming, IN
   ORDER, any prefix that resolves to the pytest exe:

   - ENV-ASSIGN prefix: zero or more leading ``VAR=val`` tokens (matching
     ``^[A-Za-z_]\\w*=``). Consumed and skipped. These are the D8-03 accepted
     residual (``PYTHONPATH=``/``LD_PRELOAD=``/``PYTHONSTARTUP=`` injection);
     permitted for seed parity.
   - UV prefix: ``uv`` (or path-suffix ``/uv``), then optional ``uv`` flags,
     then literal ``run``, then optional post-``run`` flags. A uv flag CONSUMES
     its following token as a VALUE (so ``--with requests pytest`` — the D8-03
     accepted residual — skips ``requests``) UNLESS that next token is itself a
     flag or the pytest/python exe (the exe is a HARD STOP the prefix never
     swallows, so ``uv run --flag pytest`` lands on ``pytest``, not off it).
   - PYTHON prefix: a python exe (``python``/``python3`` or path-suffix
     ``/python``/``/python3``), then optional python options, then literal
     ``-m``.
   - PYTEST exe: a token matched by PATH-SUFFIX (``== "pytest"`` or
     ``endswith("/pytest")``), NEVER ``tokens[0] ==`` (the leading token is
     usually env-assign / ``uv`` / ``python`` / ``.venv/bin/pytest``).

   If the scan cannot land on a pytest exe token in a recognized shape ->
   abstain. A prefix MIS-parse is abstain-direction by construction: landing
   REQUIRES the path-suffix pytest match, so the only false-allow vector
   (admitting a non-pytest exe as the command) is closed by the suffix match.

2. REDIRECTION/INJECTION DENYLIST (D8-04) on the post-exe args. Allow arbitrary
   tasks/flags EXCEPT the audited set that redirects WHICH config/plugin/rootdir
   runs (the foreign-project injection vectors). The blocked set is EXACTLY
   these nine — finalized; do NOT add project-state flags like ``--cache-clear``
   (those write the user's OWN project, in-scope-trusted under D8-01):

       -p  -c  --config-file  --rootdir  -o  --override-ini
       --pdb  --pdbcls  --basetemp

   Each blocked flag is matched in ALL THREE token shapes (MEMORY.md flag-audit
   blindspot, D8-04 — the deliberate denylist-polarity EXCEPTION to D-16):
   split exact (``-p`` / ``--config-file``), glued short (``-pplug`` via the
   2-char head for ``-p``/``-c``/``-o``), and long ``--flag=value`` (split on
   ``=`` before membership). ``--pdb`` and ``--pdbcls`` are listed EXPLICITLY
   (no ``startswith`` substring) so ``--pyargs`` does not collide with ``--pdb``
   and the discrimination is exact. A ``-k pdbtest`` value is a SEPARATE
   positional token (``pdbtest``), not a blocked flag.

   BUNDLED-SHORT-FLAG note (T-08-07 audited, NOT a bypass): the short-flag match
   is a 2-char HEAD match (``tok[:2]``), so a value-bearing blocked flag NOT at
   the head of a getopt cluster (``-xp plug``, ``-xo addopts=x``, ``-xc cfg``)
   is not caught by the head check. This was verified EMPIRICALLY to be safe for
   pytest: pytest (argparse) does NOT cluster ``-xp`` into ``-x -p`` — ``pytest
   -xp _no_such_plugin`` collects normally WITHOUT attempting the plugin import,
   and ``pytest -xo addopts=--bogus`` errors with ``unrecognized arguments``
   (the injection does NOT happen). The blocked short flags ``-p``/``-c``/``-o``
   are value-bearing and pytest only honors them as a standalone token or a
   glued head (``-pplug``) — both of which ARE caught. So the head-only match is
   sufficient for pytest's actual getopt behavior (no live false-allow).

3. The trailing redirect is routed through the shared ``redirect_tail_is_safe``
   (the D-05 ``/dev/null`` + ``/tmp`` policy).

D8-03 ACCEPTED RESIDUALS (recorded so downstream agents do NOT silently
"fix" them): ``uv run --with <pkg> pytest`` (a network install) and env-assign
injection prefixes (``PYTHONPATH=``/``LD_PRELOAD=``/``PYTHONSTARTUP=``). The
maintainer chose seed-parity coverage; these mirror D-03a and are part of the
opt-in trust grant, NOT oversights.

Tokenizer abstain is the recognizer's abstain (D8-08): ``$(...)``/backtick/
brace-body all already abstain in ``tokenize``, so ``pytest "$(id)"`` abstains
there.
"""

from __future__ import annotations

import re

from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from .redirects import redirect_tail_is_safe

#: A leading ``VAR=val`` env-assignment token (the D8-03 accepted residual
#: prefix; ``PYTHONPATH=``/``LD_PRELOAD=``/``PYTHONSTARTUP=`` etc.).
_ENV_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")

#: Redirection/injection DENYLIST (D8-04). EXACTLY these nine; do NOT extend
#: with project-state flags (``--cache-clear`` writes the user's OWN project and
#: is in-scope-trusted under D8-01). ``--pdb``/``--pdbcls`` are listed
#: EXPLICITLY (no substring/startswith) so ``--pyargs`` never collides.
_BLOCKED_LONG = frozenset(
    {
        "--config-file",
        "--rootdir",
        "--override-ini",
        "--pdb",
        "--pdbcls",
        "--basetemp",
    }
)
#: Blocked SHORT flags. Value-bearing, so the glued form (``-pplug``/
#: ``-ccustom.ini``/``-oaddopts=x``) is caught by a 2-char head match.
_BLOCKED_SHORT = frozenset({"-p", "-c", "-o"})


def _is_pytest_exe(tok: str) -> bool:
    """True iff ``tok`` is the pytest exe by PATH-SUFFIX (never ``tokens[0]``)."""
    return tok == "pytest" or tok.endswith("/pytest")


def _is_python_exe(tok: str) -> bool:
    """True iff ``tok`` is a python exe by path-suffix (``python``/``python3``)."""
    return (
        tok in ("python", "python3")
        or tok.endswith("/python")
        or tok.endswith("/python3")
    )


def _flag_is_blocked(tok: str) -> bool:
    """True iff option token ``tok`` is a redirection/injection blocked flag.

    Catches all three shapes (D8-04 / MEMORY.md flag-audit blindspot): long
    ``--flag=value`` (split on ``=`` before membership), split short (``-p``),
    and glued short (``-pplug`` via the 2-char head for ``-p``/``-c``/``-o``).
    """
    if tok.startswith("--"):
        name = tok.split("=", 1)[0]
        return name in _BLOCKED_LONG
    if tok in _BLOCKED_SHORT:
        return True
    # glued short (value-bearing): ``-pplug``/``-ccustom.ini``/``-oaddopts=x``.
    return len(tok) > 2 and tok[:2] in _BLOCKED_SHORT


def _scan_launcher_prefix(tokens: list[str]) -> int | None:
    """Return the index of the pytest exe token, or ``None`` if not a launcher.

    Allowlist polarity on the prefix (the ported seed grammar D8-02 IS the
    allowlist). A mis-parse returns ``None`` (abstain) — never a false-allow,
    since landing REQUIRES the path-suffix pytest match.
    """
    i = 0
    n = len(tokens)

    # ENV-ASSIGN prefix: zero or more leading ``VAR=val`` tokens (D8-03 residual).
    while i < n and _ENV_ASSIGN.match(tokens[i]):
        i += 1

    if i >= n:
        return None

    # Direct pytest exe (bare / path) -> done.
    if _is_pytest_exe(tokens[i]):
        return i

    # UV prefix: ``uv [flags] run [flags] <exe>``.
    if tokens[i] == "uv" or tokens[i].endswith("/uv"):
        i += 1
        # optional uv flags before ``run`` (a flag consumes its value unless the
        # value is itself a flag or the python/pytest exe — the exe is a hard stop).
        while i < n and tokens[i].startswith("-"):
            i += 1
            if (
                i < n
                and not tokens[i].startswith("-")
                and not _is_pytest_exe(tokens[i])
                and not _is_python_exe(tokens[i])
            ):
                i += 1  # consume the flag's value
        if i >= n or tokens[i] != "run":
            return None
        i += 1  # consume ``run``
        # optional post-``run`` flags (same value-consume rule).
        while i < n and tokens[i].startswith("-"):
            i += 1
            if (
                i < n
                and not tokens[i].startswith("-")
                and not _is_pytest_exe(tokens[i])
                and not _is_python_exe(tokens[i])
            ):
                i += 1
        if i >= n:
            return None
        # after ``uv run`` either the pytest exe directly, or a python -m prefix.
        if _is_pytest_exe(tokens[i]):
            return i
        return _scan_python_prefix(tokens, i)

    # PYTHON prefix: ``python[3] [opts] -m <pytest>``.
    return _scan_python_prefix(tokens, i)


def _scan_python_prefix(tokens: list[str], i: int) -> int | None:
    """Consume ``python[3] [opts] -m`` then return the pytest exe index or None."""
    n = len(tokens)
    if i >= n or not _is_python_exe(tokens[i]):
        return None
    i += 1
    # optional python options before ``-m`` (kept simple: skip ``-``-leading
    # tokens other than ``-m``). A python opt with a value abstains — safe
    # coverage loss (not a tested shape).
    while i < n and tokens[i].startswith("-") and tokens[i] != "-m":
        i += 1
    if i >= n or tokens[i] != "-m":
        return None
    i += 1  # consume ``-m``
    if i >= n or not _is_pytest_exe(tokens[i]):
        return None
    return i


def recognize_pytest(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for an opt-in pytest run, else ``None``.

    Allows a recognized launcher shape (bare/path ``pytest``; ``python -m
    pytest``; ``uv run [flags] pytest``; ``uv run python -m pytest``; any with
    an env-assign prefix) carrying arbitrary args EXCEPT the redirection/
    injection denylist (D8-04), with a redirect tail that passes the shared
    ``/dev/null`` + ``/tmp`` policy. Abstains on everything else — including a
    tokenizer abstain (D8-08), a non-launcher leading word, a blocked flag in
    any of its three forms, and a non-safe redirect target.
    """
    result = tokenize(segment)
    # The tokenizer holds ALL expansion safety; its abstain is the recognizer's.
    if result.abstain_reason is not None:
        return None
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens:
        return None

    exe_idx = _scan_launcher_prefix(tokens)
    if exe_idx is None:
        return None

    # The REMAINING tokens after the pytest exe are the pytest args.
    args = tokens[exe_idx + 1 :]

    # Redirection/injection DENYLIST audit (D8-04) over the option tokens.
    for tok in args:
        if tok.startswith("-") and tok != "-" and _flag_is_blocked(tok):
            return None

    # The trailing redirect must pass the shared /dev/null + /tmp policy (D-05).
    if not redirect_tail_is_safe(args):
        return None

    return Verdict("allow", "opt-in pytest run", "pytest")

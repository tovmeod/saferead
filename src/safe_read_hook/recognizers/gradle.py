"""The ``gradle``/``gradlew`` recognizer (REC-07, D8-01/D8-04).

CARDINAL POSTURE — ``allow`` != proven read-only (D8-01). gradle evaluates
``build.gradle`` (arbitrary Groovy/Kotlin) at the CONFIGURATION phase even for
``tasks``/``help``/``dependencies`` — there is no execution-free gradle form.
This recognizer is therefore a deliberate OPT-IN TRUST grant on the user's OWN
project, NOT a proof of side-effect-freedom (impossible). Its job is the
narrower "ensure it runs THE project, not a redirected/injected one" — i.e.
guard the PROJECT boundary, not the side-effect boundary. This is the conscious,
recorded departure from D-15/D-16, mirroring Phase 7's D-03a residual and the
sibling pytest recognizer (D8-01).

DENYLIST POLARITY (D8-04). Because the code runs regardless, the guard is a
redirection DENYLIST, not an allowlist — the conscious, justified exception to
D-16 here. The goal is BLOCKING foreign-project redirection (a different
``build.gradle``/``settings.gradle``/init-script/project dir), not proving the
run read-only. An UNKNOWN flag is therefore ALLOWED (it does not abstain); only
the certain redirect-which-project-runs flags block. Admit/deny only when
CERTAIN; the denylist is finalized to the flags below — do NOT extend it with
project-state-writing flags like ``--write-locks`` / ``--refresh-dependencies``,
which write the user's OWN project state (in-scope-trusted under D8-01); the
denylist is redirection/injection ONLY.

Two stages:

1. LAUNCHER MATCH (ported seed grammar, intent only D4-03). Walk an optional
   ENV-ASSIGN prefix (zero or more leading ``VAR=val`` tokens matching
   ``^[A-Za-z_]\\w*=``), then require the next token to be the gradle exe by
   EXACT-OR-SLASH path-suffix (``== "gradle"``/``"gradlew"`` or
   ``endswith("/gradle")``/``endswith("/gradlew")`` — covering ``./gradlew`` and
   ``/path/to/gradle``), NEVER ``tokens[0] ==``. The slash-or-exact form (NOT a
   bare ``endswith("gradle")``) is what makes a launcher mis-match
   abstain-direction: a bare suffix would match ``notgradle`` and false-allow
   running it. If the exe is not found -> abstain.

2. REDIRECTION DENYLIST (D8-04) on the post-exe args. The remaining tokens are
   gradle args (arbitrary TASK NAMES allowed — project code, trusted under
   D8-01). Allow arbitrary tasks/flags EXCEPT the audited redirection set,
   matched in ALL THREE token shapes (MEMORY.md flag-audit blindspot):

       PORTED (seed):  --init-script / -I,  --build-file / -b,
                       --settings-file / -c
       EXTENDED (D8-04, seed misses):  --project-dir / -p,  --include-build,
                       --project-cache-dir,  --gradle-user-home / -g

   Matching rules:
   - long ``--flag=value`` / split: split on ``=`` before membership in
     ``_BLOCKED_LONG`` (the FLAG token is the trigger either way).
   - short flags are CASE-SENSITIVE and value-bearing: split exact (``-b
     other.gradle``) and glued head (``-bbuild.gradle``, ``-p/other``,
     ``-g/home``) via the 2-char head in ``_BLOCKED_SHORT``. CRITICAL
     (T-08-13): ``-p`` (lowercase, project-dir, BLOCK) is distinguished from
     ``-P``/``-Pkey=val`` (uppercase, project PROPERTY, ALLOW) by EXACT
     case-sensitive comparison — tokens are NEVER lowercased, so ``-P`` is not
     in ``_BLOCKED_SHORT`` and passes through for free.

   Residual (smaller than the accepted polarity hole, NOT blocking): gradle
   long-option prefix-abbreviation (``--build-f`` for ``--build-file``) would
   miss the exact split-membership match. Noted, not closed.

3. The trailing redirect is routed through the shared ``redirect_tail_is_safe``
   (the D-05 ``/dev/null`` + ``/tmp`` policy).

Tokenizer abstain is the recognizer's abstain (D8-08): ``$(...)``/backtick/
brace-body all already abstain in ``tokenize``, so ``gradle "$(id)"`` abstains
there.
"""

from __future__ import annotations

import re

from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from .redirects import redirect_tail_is_safe

#: A leading ``VAR=val`` env-assignment token (the launcher env-assign prefix).
_ENV_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")

#: Redirection DENYLIST long flags (D8-04): PORTED seed blocks + EXTENDED seed
#: misses. Each redirects WHICH project/build/settings/init-script runs. Long
#: ``--flag=value`` is split on ``=`` before membership.
_BLOCKED_LONG = frozenset(
    {
        # PORTED (seed)
        "--init-script",
        "--build-file",
        "--settings-file",
        # EXTENDED (seed misses, D8-04)
        "--project-dir",
        "--include-build",
        "--project-cache-dir",
        "--gradle-user-home",
    }
)
#: Blocked SHORT flags. Value-bearing, so the glued form (``-bbuild.gradle``/
#: ``-p/other``/``-g/home``) is caught by a 2-char head match. CASE-SENSITIVE
#: (T-08-13): lowercase ``-p``/``-g`` block; uppercase ``-P``/``-Pkey=val``
#: (property) is NOT in this set and passes through.
_BLOCKED_SHORT = frozenset({"-I", "-b", "-c", "-p", "-g"})


def _is_gradle_exe(tok: str) -> bool:
    """True iff ``tok`` is the gradle exe by EXACT-OR-SLASH path-suffix.

    NEVER a bare ``endswith("gradle")`` (that would match ``notgradle`` and
    false-allow running it). Covers ``gradle``/``gradlew`` and any
    ``./gradlew`` / ``/path/to/gradle`` form.
    """
    return (
        tok in ("gradle", "gradlew")
        or tok.endswith("/gradle")
        or tok.endswith("/gradlew")
    )


def _flag_is_blocked(tok: str) -> bool:
    """True iff option token ``tok`` is a redirection blocked flag.

    Catches all three shapes (D8-04 / MEMORY.md flag-audit blindspot): long
    ``--flag=value`` (split on ``=`` before membership), split short (``-b``),
    and glued short (``-bbuild.gradle`` via the 2-char head). Case-sensitive
    throughout — ``-P`` is not blocked, ``-p`` is (T-08-13).
    """
    if tok.startswith("--"):
        name = tok.split("=", 1)[0]
        return name in _BLOCKED_LONG
    if tok in _BLOCKED_SHORT:
        return True
    # glued short (value-bearing): ``-bbuild.gradle``/``-p/other``/``-g/home``.
    return len(tok) > 2 and tok[:2] in _BLOCKED_SHORT


def recognize_gradle(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for an opt-in gradle run, else ``None``.

    Allows a recognized launcher (env-assign prefix + path-suffix
    ``gradle``/``gradlew`` exe) carrying arbitrary tasks/flags EXCEPT the
    redirection denylist (D8-04), with a redirect tail that passes the shared
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

    # Launcher match: consume an optional ENV-ASSIGN prefix, then require the
    # gradle exe by path-suffix (NEVER tokens[0] ==).
    i = 0
    n = len(tokens)
    while i < n and _ENV_ASSIGN.match(tokens[i]):
        i += 1
    if i >= n or not _is_gradle_exe(tokens[i]):
        return None

    # The REMAINING tokens after the gradle exe are the gradle args (arbitrary
    # task names allowed under D8-01).
    args = tokens[i + 1 :]

    # Redirection DENYLIST audit (D8-04) over the option tokens.
    for tok in args:
        if tok.startswith("-") and tok != "-" and _flag_is_blocked(tok):
            return None

    # The trailing redirect must pass the shared /dev/null + /tmp policy (D-05).
    if not redirect_tail_is_safe(args):
        return None

    return Verdict("allow", "opt-in gradle run", "gradle")

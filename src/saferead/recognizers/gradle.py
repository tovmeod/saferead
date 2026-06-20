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
   - long ``--flag=value`` / split: split on ``=``, then block if the flag name
     is a PREFIX of (or equals) any ``_BLOCKED_LONG`` entry — gradle accepts
     unambiguous prefix abbreviations (``--build-f`` -> ``--build-file``), so an
     exact match would miss the abbreviated redirect (WR-01, D8-04). Prefix
     matching over-abstains at worst on a benign shared-prefix flag (free loss).
   - short flags are CASE-SENSITIVE and value-bearing: split exact (``-b
     other.gradle``) and glued head (``-bbuild.gradle``, ``-p/other``,
     ``-g/home``) via the 2-char head in ``_BLOCKED_SHORT``. CRITICAL
     (T-08-13): ``-p`` (lowercase, project-dir, BLOCK) is distinguished from
     ``-P``/``-Pkey=val`` (uppercase, project PROPERTY, ALLOW) by EXACT
     case-sensitive comparison — tokens are NEVER lowercased, so ``-P`` is not
     in ``_BLOCKED_SHORT`` and passes through for free.

   Long-option prefix-abbreviation (``--build-f`` for ``--build-file``) is
   CLOSED (WR-01): the long-flag match is by prefix, not exact membership.

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


#: The bare blocked short-flag LETTERS (without the leading ``-``), used by the
#: bundled-cluster scan. Case-sensitive — uppercase ``P``/``D`` are NOT here.
_BLOCKED_SHORT_LETTERS = frozenset("Ibcpg")

#: Glued-VALUE short options: the remainder after the 2-char head is a VALUE, not
#: a flag cluster, so a blocked LETTER appearing inside it must NOT trip the
#: bundled-cluster scan. ``-P`` (project property, ``-Pgpr.key=val``) is
#: case-verified (T-08-13). ``-D`` (system property, ``-Dorg.gradle.parallel=...``,
#: very common, ``g`` inside the value) is a KNOWLEDGE-BASED carve-out — omitting
#: it would only OVER-abstain (the strictly-safe direction), so this is a
#: coverage choice, not a safety one.
_GLUED_VALUE_HEADS = frozenset({"-P", "-D"})


def _flag_is_blocked(tok: str) -> bool:
    """True iff option token ``tok`` is a redirection blocked flag.

    Catches all FOUR shapes (D8-04 / MEMORY.md flag-audit blindspot): long
    ``--flag=value`` (split on ``=``, then PREFIX-abbreviation match against
    ``_BLOCKED_LONG`` per WR-01), split short (``-b``),
    glued short (``-bbuild.gradle`` via the 2-char head), AND a bundled getopt
    cluster whose blocked letter is NOT at the head (``-ip`` = ``-i -p`` would
    redirect the project). Case-sensitive throughout — ``-P`` is not blocked,
    ``-p`` is (T-08-13).

    The bundled-cluster scan abstains on ANY single-dash token (other than a
    ``-P``/``-D`` glued-value head) that CONTAINS a blocked letter. gradle is not
    installed here, so its custom ``CommandLineParser`` clustering semantics
    cannot be verified empirically (unlike pytest's T-08-07); per D8-04 ("when
    unsure, abstain — free loss") the conservative direction is to block the
    cluster. If gradle DOES cluster ``-ip`` -> ``-i -p`` this closes the
    redirect; if it does NOT, the token would not run a valid gradle anyway, so
    abstaining is a harmless over-abstain. Either branch -> no false-allow.
    """
    if tok.startswith("--"):
        name = tok.split("=", 1)[0]
        # Prefix-abbreviation match (WR-01, D8-04): gradle's CommandLineParser
        # accepts unambiguous PREFIX abbreviations of long options, so
        # ``--build-f`` resolves to ``--build-file``, ``--init-scr`` to
        # ``--init-script``. Exact membership would miss these, leaving a
        # build-file/init-script redirect un-blocked. gradle is not installed
        # here, so per D8-04 (can't verify -> abstain conservatively) treat ANY
        # ``--xxx`` token that is a prefix of a blocked long flag as blocked. At
        # worst this over-abstains on a benign flag sharing a prefix — free
        # coverage loss, the strictly-safe direction.
        return any(blocked.startswith(name) for blocked in _BLOCKED_LONG)
    if tok in _BLOCKED_SHORT:
        return True
    if len(tok) <= 2:
        return False
    # glued short (value-bearing) at the head: ``-bbuild.gradle``/``-p/other``.
    if tok[:2] in _BLOCKED_SHORT:
        return True
    # glued-VALUE head (``-P``/``-D``): the remainder is a VALUE, never a cluster
    # of flags — a blocked letter inside it must NOT trip (preserves ``-Pkey=val``,
    # ``-Pgpr.key=val``, ``-Dorg.gradle.parallel=true``).
    if tok[:2] in _GLUED_VALUE_HEADS:
        return False
    # bundled getopt cluster: a blocked letter anywhere after the leading ``-``
    # (e.g. ``-ip`` = ``-i -p``) -> abstain (conservative, unverifiable parser).
    return any(c in _BLOCKED_SHORT_LETTERS for c in tok[1:])


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

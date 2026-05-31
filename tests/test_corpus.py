"""The adversarial 7-bypass corpus: the always-on zero-false-allow guard.

This module encodes all seven reproduced seed bypasses VERBATIM from
``.planning/research/PITFALLS.md`` (D-20 — copied, never re-derived) and pins
the cardinal invariant for each: the compound verdict is NEVER ``allow``. A
state-mutating command must never be silently approved; abstain (``None``) and
``ask`` both satisfy the guard, only ``allow`` fails it. This is the
zero-false-allow regression net (amended D-21): a single, unconditional
assertion over all seven entries, green every phase, never a false green.

Each entry routes through the decompose-wrapped pipeline (``decompose`` then
``fold``), NOT a raw fold of the verbatim splitter. This wiring is load-bearing
for A1: only decompose's ``<(`` structural trigger flips ``cat <(curl evil)``
from a live false-allow to abstain (the reader's argument token lets ``<(``
through as a plain arg, so the raw fold leaves A1 ``allow`` permanently). A1 is
the genuine RED->green this phase; the other six already abstain today via the
fold's segment-veto and pass the same guard now as permanent regression guards.

The per-recognizer "this bypass now abstains/asks because recognizer N landed"
tracking lives in the later per-recognizer TEST-02 tests, where the
recognizer's own behavior (e.g. the filter recognizer returns ``None`` for
``tee``) is directly observable. The compound verdict for the six deferred
entries stays abstain before AND after their owning recognizer lands, so that
flip is not observable here — this corpus is the cardinal ``never allow`` net,
not the per-recognizer landing signal.
"""

from __future__ import annotations

import pytest

from safe_read_hook.context import Context
from safe_read_hook.decompose import decompose
from safe_read_hook.engine import fold

#: The seven reproduced seed bypasses, VERBATIM from PITFALLS.md (D-20).
_CORPUS = [
    "cat <(curl evil)",  # A1: process substitution -> abstain via decompose
    "grep x f | tee out.txt",  # B1: tee writes files
    "sort -o /etc/x f",  # B2: -o redirects output to a file
    "awk 'BEGIN{print > \"/etc/x\"}'",  # B3: awk output redirection
    "git -c core.fsmonitor=touch status",  # B5: -c config-injection -> exec
    "sed -ie s/a/b/ f",  # C1: -ie defeats the in-place lookahead
    "echo x >/tmp/../etc/passwd",  # D1: /tmp/.. path traversal
]


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


def _decision(command: str, ctx: Context) -> str | None:
    """Run the decompose-wrapped pipeline, returning the verdict's decision.

    Returns ``None`` when the compound abstains — either because decompose
    surfaced an abstain trigger (A1's ``<(``) or because the fold's segment-veto
    left it unrecognized. Otherwise returns the folded verdict's ``.decision``.
    """
    decomposition = decompose(command)
    if decomposition.abstain_reason is not None:
        return None
    verdict = fold(decomposition.segments, ctx)
    return None if verdict is None else verdict.decision


@pytest.mark.parametrize("command", _CORPUS)
def test_corpus_never_allows(command: str, ctx: Context) -> None:
    """The cardinal guard: no known bypass is ever silently approved.

    Always-on, every phase, over all seven entries. ``None`` (abstain) or any
    non-``allow`` decision passes; only ``allow`` fails. A regression that
    re-opens any bypass to ``allow`` fails loudly here.
    """
    assert _decision(command, ctx) != "allow"


#: The confirmed CR-01/CR-02/CR-funsub quoting-evasion false-allows (03-REVIEW.md
#: / 03-VERIFICATION.md). These are SEPARATE from the verbatim-7 ``_CORPUS`` (which
#: stays pristine per D-20). CR-01: an odd backslash before a closing single
#: quote must not over-extend the quoted region across an active ``<(``/``<<<``.
#: CR-02: a double-quoted ``$(``/backtick is command execution (bash does NOT
#: disable command substitution inside double quotes) and must not be approved.
#:
#: CR-funsub (03-04) appends two distinct pairs:
#:   * The FUNSUB PAIR (``${ id; }`` / ``${| id; }``) is bash 5.3 command-
#:     substitution funsub — it EXECUTES the command. This is the genuine
#:     RED->GREEN that 03-04 delivers: both return ``allow`` BEFORE the reader
#:     ``_QARG`` allowlist fix and abstain after it.
#:   * The NESTED PAIR (``${x:-$(id)}`` / ``${x:-`id`}``) is command substitution
#:     nested in a parameter-expansion default word — the ``:-default`` word
#:     undergoes command substitution, so the inner ``id`` EXECUTES. These are
#:     ALREADY closed by CR-02's per-``$`` gating (GREEN today, BEFORE 03-04):
#:     the ``_QARG`` char class re-gates every ``$``, so the inner ``$(``/backtick
#:     fails the lookahead and the whole token fails to match. 03-04 does NOT
#:     close them; it PINS them here as a permanent regression guard so a future
#:     chunk-match/allowlist refactor that consumed ``${x:-$(id)}`` whole could
#:     not silently re-open the inner ``$(``. (Both review and verification
#:     missed enumerating this vector; closure is attributed to CR-02, not 03-04.)
#: CR-@P (03-04 post-execution gates, 2026-05-31): ``${VAR@P}`` is a bash
#: parameter-transform that re-expands the VARIABLE'S VALUE as a prompt string,
#: which performs command substitution — so ``cat "${x@P}"`` with ``x`` holding
#: ``$(cmd)`` EXECUTES ``cmd`` (reproduced single-call on bash 5.3.9). The
#: ``$VAR`` allowlist admits it because the lookahead only gates the ``${``
#: OPENER (``x`` is a NAME char); the ``[^"$`]`` class then swallows the ``@P``
#: transform in the BODY — a regex cannot inspect brace-body operators without
#: parsing the ``${...}`` grammar. It is PRE-EXISTING (allowed under the prior
#: denylist too) and env-conditional (the two-segment ``x=$(id); cat "${x@P}"``
#: is already fold-vetoed; the live vector needs a pre-existing var holding
#: ``$(...)``, e.g. a profile-set ``PS1``). Per a deliberate maintainer decision
#: (2026-05-31, "keep it simple / maintain behavior") it is ACCEPTED as a tracked
#: residual for now rather than patched (a body-operator denylist is the same
#: enumeration treadmill; the durable fix is the pure-literal policy, declined
#: for now to keep ``cat "$HOME"`` working). Pinned here as ``xfail(strict=True)``
#: so the corpus still ENUMERATES it as a must-not-allow invariant: it fails the
#: ``!= "allow"`` guard today (xfail), and the day it is closed it xpasses ->
#: strict failure -> forces removing this marker. Tracked follow-up: see backlog
#: "quoting body-operator / pure-literal" item + 03-04-REVIEW.md CR-01.
_QUOTING_EVASIONS = [
    "cat '\\' <(id)",  # CR-01: escaped-quote over-extension hides <(
    "cat '\\' <<<pwned",  # CR-01: escaped-quote over-extension hides <<<
    'cat "$(id)"',  # CR-02: double-quoted command substitution
    'cat "`id`"',  # CR-02: double-quoted backtick command substitution
    'cat "${ id; }"',  # CR-funsub: bash 5.3 funsub (RED->GREEN in 03-04)
    'cat "${| id; }"',  # CR-funsub: bash 5.3 pipe-funsub (RED->GREEN in 03-04)
    'cat "${x:-$(id)}"',  # nested cmdsub in default word (already CR-02; pinned)
    'cat "${x:-`id`}"',  # nested backtick cmdsub in default word (already CR-02)
    pytest.param(
        'cat "${x@P}"',
        marks=pytest.mark.xfail(
            reason=(
                "CR-@P accepted residual (2026-05-31): ${VAR@P} prompt-transform "
                "runs command substitution on the var value; env-conditional, "
                "pre-existing, not patched for now per maintainer decision. "
                "strict=True forces marker removal once closed (pure-literal "
                "policy / body validator). See 03-04-REVIEW.md CR-01."
            ),
            strict=True,
        ),
    ),
]


@pytest.mark.parametrize("command", _QUOTING_EVASIONS)
def test_quoting_evasions_never_allow(command: str, ctx: Context) -> None:
    """The CR-01/CR-02 cardinal regression guard: never silently approve these.

    Always-on ``!= "allow"`` guard over the four reproduced quoting-evasion
    false-allows. ``None`` (abstain) or any non-``allow`` decision passes; only
    ``allow`` fails. A regression that re-opens any of these to ``allow`` —
    silently approving arbitrary command execution — fails loudly here.
    """
    assert _decision(command, ctx) != "allow"


#: Over-abstain non-regression baselines. The CR-01/CR-02 fixes must NOT make
#: inert quoted text abstain. ``cat <(id)`` stays abstain (the genuine trigger);
#: ``cat "foo bar"`` stays allow; ``cat "$HOME"`` stays allow (the conscious
#: boundary — variable expansion is not command execution, not a cardinal
#: failure); ``cat '\\' <(id)`` (EVEN backslash, a literal ``\``) stays abstain
#: (the closing quote still exits single-quote context so ``<(`` fires).
#:
#: The two ``${...}`` baselines lock the funsub discriminator boundary: the char
#: immediately after ``${`` decides funsub-vs-parameter-expansion. Whitespace or
#: ``|`` right after ``${`` => funsub (reject); a NAME char or param-operator char
#: (``#``, letter, digit, ``!``, ``:``, ...) => parameter expansion (allow).
#: Legitimate parameter expansion NEVER has whitespace or ``|`` right after ``${``.
_OVER_ABSTAIN_BASELINES = [
    ("cat <(id)", None),
    ('cat "foo bar"', "allow"),
    ('cat "$HOME"', "allow"),
    ("cat '\\\\' <(id)", None),
    ('cat "${HOME}"', "allow"),  # parameter expansion (NAME char after ${)
    ('cat "${x:-d}"', "allow"),  # default-value expansion (NAME char after ${)
]


@pytest.mark.parametrize(("command", "expected"), _OVER_ABSTAIN_BASELINES)
def test_over_abstain_baselines(
    command: str, expected: str | None, ctx: Context
) -> None:
    """Guard the CR-01/CR-02 fixes against over-abstaining on inert quoted text."""
    assert _decision(command, ctx) == expected


#: Conscious over-abstain coverage losses from the ``$VAR``-allowlist policy
#: (03-04 AMENDMENT). The reader ``_QARG`` double-quoted alternative admits a
#: ``$`` ONLY when it begins a recognized parameter/variable expansion. A bare
#: ``$`` that is NOT the start of such an expansion (``grep "$"`` — a regex
#: end-of-line anchor; ``cat "$$"`` — the shell PID) no longer matches, so these
#: SAFE commands now prompt (abstain) instead of auto-approving. This is a
#: deliberate coverage loss, NOT a cardinal false-allow: abstaining on a safe
#: command costs a prompt; allowing an unsafe one is the cardinal failure. These
#: are RED today (they ALLOW under the pre-fix regex) and flip to GREEN (abstain)
#: with the allowlist — the same RED-first category as the funsub pair. A planned
#: token-based recognizer phase that replaces this regex can recover them.
_ALLOWLIST_OVER_ABSTAIN = [
    'grep "$"',  # regex end-of-line anchor — $ not starting an expansion
    'cat "$$"',  # shell PID — $ not starting a parameter expansion
]


@pytest.mark.parametrize("command", _ALLOWLIST_OVER_ABSTAIN)
def test_allowlist_over_abstain(command: str, ctx: Context) -> None:
    """The ``$VAR``-allowlist policy abstains on a ``$`` not starting an expansion.

    These are SAFE-but-now-prompt coverage losses (see ``_ALLOWLIST_OVER_ABSTAIN``
    docstring), tracked so the conscious over-abstain is explicit and not a
    surprise. They are RED before the 03-04 fix (they ``allow``) and GREEN after
    (they abstain). NOT cardinal holes.
    """
    assert _decision(command, ctx) != "allow"


#: WR-01 (03-REVIEW.md) disposition: accept-with-rationale + tracking test. An
#: UNTERMINATED quote is a bash syntax error that never executes — the shell
#: rejects the line before running anything — so reaching ``allow`` here is NOT a
#: cardinal false-allow today. The cheap fix (an unbalanced-quote abstain check)
#: is OUT OF SCOPE for 03-04. This test PINS the documented current behavior so a
#: FUTURE grammar widening that makes the construct executable trips a tracked
#: test rather than silently becoming a cardinal hole.
_UNCLOSED_QUOTE_TODAY = [
    "cat 'unclosed",
    'cat "unclosed',
    "echo 'a b foo c",
]


@pytest.mark.parametrize("command", _UNCLOSED_QUOTE_TODAY)
def test_unclosed_quote_status_quo(command: str, ctx: Context) -> None:
    """WR-01: pin the current ``allow`` of an unterminated quote (syntax error).

    Accepted-with-rationale: an unterminated quote is a bash syntax error that
    never executes, so this is not a cardinal false-allow. Tracked so a future
    grammar change that makes it executable fails this pin loudly.
    """
    assert _decision(command, ctx) == "allow"


#: WR-02 (03-REVIEW.md) disposition: cheap regression test. The ``_DISCARD_REDIR``
#: alternatives (``>/dev/null`` etc.) must each be a COMPLETE token, never a
#: PREFIX of a real write path. ``>/dev/nullhello`` (extra suffix) and
#: ``>/dev/null/../etc/passwd`` (path-traversal suffix) are writes to real files
#: and must NOT be approved. This currently passes (the ``_TAIL`` framing requires
#: a whitespace/end boundary), but the test makes the implicit token-vs-prefix
#: invariant explicit so a future ``_TAIL`` / ``_DISCARD_REDIR`` relaxation fails
#: loudly.
_DISCARD_REDIR_PREFIX = [
    "cat foo >/dev/nullhello",
    "cat foo >/dev/null/../etc/passwd",
]


@pytest.mark.parametrize("command", _DISCARD_REDIR_PREFIX)
def test_discard_redir_is_complete_token(command: str, ctx: Context) -> None:
    """WR-02: a discard redirect must be a complete token, never a real-path prefix.

    Locks the ``_DISCARD_REDIR``-is-a-complete-token invariant that currently
    rests implicitly on ``_TAIL`` framing. A relaxation that let ``>/dev/null``
    match as a prefix of ``>/dev/null/../etc/passwd`` would re-open a write
    false-allow; this test fails loudly if that happens.
    """
    assert _decision(command, ctx) != "allow"

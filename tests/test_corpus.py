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


#: The four confirmed CR-01/CR-02 quoting-evasion false-allows (03-REVIEW.md /
#: 03-VERIFICATION.md). These are SEPARATE from the verbatim-7 ``_CORPUS`` (which
#: stays pristine per D-20). CR-01: an odd backslash before a closing single
#: quote must not over-extend the quoted region across an active ``<(``/``<<<``.
#: CR-02: a double-quoted ``$(``/backtick is command execution (bash does NOT
#: disable command substitution inside double quotes) and must not be approved.
_QUOTING_EVASIONS = [
    "cat '\\' <(id)",  # CR-01: escaped-quote over-extension hides <(
    "cat '\\' <<<pwned",  # CR-01: escaped-quote over-extension hides <<<
    'cat "$(id)"',  # CR-02: double-quoted command substitution
    'cat "`id`"',  # CR-02: double-quoted backtick command substitution
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
_OVER_ABSTAIN_BASELINES = [
    ("cat <(id)", None),
    ('cat "foo bar"', "allow"),
    ('cat "$HOME"', "allow"),
    ("cat '\\\\' <(id)", None),
]


@pytest.mark.parametrize(("command", "expected"), _OVER_ABSTAIN_BASELINES)
def test_over_abstain_baselines(
    command: str, expected: str | None, ctx: Context
) -> None:
    """Guard the CR-01/CR-02 fixes against over-abstaining on inert quoted text."""
    assert _decision(command, ctx) == expected

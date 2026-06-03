"""Boundary tests for the read-only ``find`` recognizer (REC-04 / TEST-02).

The cardinal axis is the allow/abstain BOUNDARY for ``find``: a command whose
predicates are ALL on a read-only allowlist (test predicates + stdout actions
``-print``/``-print0``/``-ls``/``-quit``/``-prune``) auto-allows, while EVERY
mutating or exec action abstains by ALLOWLIST OMISSION (D-04) — there is no
``-exec``/``-delete``/``-fprint*`` denylist. A predicate word not on the
allowlist is the abstain trigger, which closes the file-writing ``-fprint``/
``-fprintf``/``-fprint0``/``-fls`` (B4) family AND any future GNU action by
construction.

Value-bearing predicates (``-mtime -7``, ``-size +100M``) consume their next
token as an OPAQUE value (Pitfall 3) so a value starting with ``-``/``+`` is
never mis-evaluated as a predicate.

Test-name contract (load-bearing, MEMORY.md silent-skip lesson): the ``-k``
filter selects on the substrings ``find``, ``readonly``/``allow``, ``abstain``,
``mutating``. A test whose name misses every substring is silently NOT run.
"""

from __future__ import annotations

import pytest

from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers.find import recognize_find


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- read-only allow ------------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "find .",
        "find . -name '*.py'",
        "find /x -type f -print",
        "find . -type f -print0",
        "find . -mtime -7",
        "find . -size +100M -print0",
        "find . -maxdepth 2 -ls",
        r"find . \( -name a -o -name b \)",
        "find . -empty -print",
        "find . -newer x -print",
        "find . -type f >/tmp/list",
    ],
)
def test_find_readonly_predicates_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_find(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "find"


# --- mutating / exec / write actions abstain ------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "find . -delete",
        r"find . -exec rm {} \;",
        r"find . -execdir sh -c x \;",
        r"find . -ok rm {} \;",
        r"find . -okdir rm {} \;",
        "find . -fprint out",
        "find . -fprintf out fmt",
        "find . -fprint0 out",
        "find . -fls out",
        r"find . -newer x -exec rm {} \;",
    ],
)
def test_find_mutating_actions_abstain(segment: str, ctx: Context) -> None:
    assert recognize_find(segment, ctx) is None


# --- unknown predicate + tokenizer abstain --------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "find . -bogus",
        "find . -files0-from list",
        "find . -name",  # value-bearing predicate with no value -> malformed
        'find . -name "$(id)"',  # tokenizer abstains on the expansion
        "find . -type f >/etc/passwd",  # non-safe redirect target
    ],
)
def test_find_unknown_or_ambiguous_abstain(segment: str, ctx: Context) -> None:
    assert recognize_find(segment, ctx) is None


# --- live fold-path wiring (Task 2 analog) --------------------------------


def test_find_allow_through_fold_readonly(ctx: Context) -> None:
    verdict = fold(["find . -name x"], ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


def test_find_mutating_through_fold_abstain(ctx: Context) -> None:
    assert fold(["find . -delete"], ctx) is None

"""Boundary tests for the minimal reader recognizer.

The point of these tests is the allow/abstain BOUNDARY: the reader must claim a
narrow read-only set and abstain on everything else — especially on write-mode
commands and on redirects to real files (the cardinal zero-false-allow cases).
"""

from __future__ import annotations

import pytest

from safe_read_hook.context import Context
from safe_read_hook.recognizers.reader import recognize_reader


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- allow cases ----------------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "cat foo.txt",
        "echo hi",
        "printf '%s' x",
        "head -5 f",
        "grep x f",
        "wc -l f",
        "ls -la",
        "echo hi >/dev/null",
        "grep x f 2>&1",
    ],
)
def test_reader_allows_read_only(segment: str, ctx: Context) -> None:
    verdict = recognize_reader(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "reader"


def test_reader_cat_is_allow_prover(ctx: Context) -> None:
    """The D-11 prover: cat foo.txt -> allow with tag 'reader'."""
    verdict = recognize_reader("cat foo.txt", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "reader"


# --- abstain (no-match) cases ---------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "rm -rf x",  # not read-only -> the veto input for the compound proof
        "tee f",  # write-mode command, not claimed (deferred phase)
        "sort -o f",  # write-mode command, not claimed (deferred phase)
        "echo x >/tmp/foo",  # redirect to a real file -> no false-allow (999.1 #7)
        "echo x >/tmp/../etc/passwd",  # path-escaping redirect -> no false-allow
        "cat foo.txt > out.txt",  # redirect to a user file -> no false-allow
    ],
)
def test_reader_abstains(segment: str, ctx: Context) -> None:
    assert recognize_reader(segment, ctx) is None


def test_reader_abstains_on_rm(ctx: Context) -> None:
    """The cardinal no-match: rm -rf x -> None (feeds the engine abstain-veto)."""
    assert recognize_reader("rm -rf x", ctx) is None


def test_reader_discard_redirect_stays_allow(ctx: Context) -> None:
    """A discard redirect never touches a user file -> safe to keep as allow."""
    verdict = recognize_reader("echo hi >/dev/null", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"

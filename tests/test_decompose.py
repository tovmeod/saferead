"""Boundary tests for the decompose() hardening wrapper (CORE-01/CORE-02).

The point of these tests is the abstain BOUNDARY: ``decompose`` must surface
abstain on the structural false-allow vectors (process substitution, heredocs,
here-strings) and on over-length input BEFORE the verbatim ``split_compound``
runs, while leaving quoted literals and benign compounds untouched. An abstain
is a ``Decomposition`` whose ``abstain_reason is not None`` (D-18). The same
entrypoint applies the same triggers on an arbitrary substring (D-19).
"""

from __future__ import annotations

import pytest
from safe_read_hook.decompose import Decomposition, decompose

from safe_read_hook.context import Context
from safe_read_hook.splitter import split_compound


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- abstain-trigger cases ------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "cat <(curl evil)",  # process-sub <( -> abstain (CORE-02; the A1 hole)
        "cat >(tee x)",  # output process-sub >( -> abstain (defense-in-depth)
    ],
)
def test_process_sub_abstains(command: str) -> None:
    result = decompose(command)
    assert isinstance(result, Decomposition)
    assert result.abstain_reason is not None


@pytest.mark.parametrize(
    "command",
    [
        "cat <<EOF",  # heredoc <<     -> abstain (CORE-02)
        "cat <<-EOF",  # heredoc <<-    -> abstain (CORE-02)
        "cat <<<hello",  # here-string <<< -> abstain (CORE-02)
    ],
)
def test_here_constructs_abstain(command: str) -> None:
    result = decompose(command)
    assert result.abstain_reason is not None


def test_over_length_abstains() -> None:
    command = "cat " + "a" * 70000  # len 70004 > 65536 -> abstain (D-17)
    result = decompose(command)
    assert result.abstain_reason is not None


@pytest.mark.parametrize(
    "command",
    [
        "echo '<(foo)'",  # single-quoted literal -> NOT abstain
        'echo "<(foo)"',  # double-quoted literal -> NOT abstain
    ],
)
def test_quoted_literal_stays_safe(command: str) -> None:
    result = decompose(command)
    assert result.abstain_reason is None
    assert result.segments == split_compound(command)


def test_arith_shift_not_allow(ctx: Context) -> None:
    """echo $((1 << 2)) must never yield an allow verdict (<<  trigger or veto)."""
    from safe_read_hook.engine import fold

    result = decompose("echo $((1 << 2))")
    if result.abstain_reason is not None:
        return  # abstain already satisfies the "never allow" invariant
    verdict = fold(result.segments, ctx)
    assert verdict is None or verdict.decision != "allow"


def test_substring_reuse() -> None:
    """The SAME triggers apply to an arbitrary substring (CORE-01/D-19)."""
    result = decompose("cat <(curl evil)")
    assert result.abstain_reason is not None


def test_benign_split_preserved() -> None:
    """A benign compound's segments equal split_compound's (wrapper is transparent)."""
    command = "cat foo.txt && head -5 f"
    result = decompose(command)
    assert result.abstain_reason is None
    assert result.segments == split_compound(command)

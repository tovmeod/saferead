"""Unit + property tests for the from-scratch bash tokenizer (TOK-01).

These port the abstain-boundary DIMENSIONS from ``test_decompose.py`` and the
property dimensions from ``test_splitter.py`` against the new ``tokenize()``
entrypoint. The tokenizer owns top-level segmentation AND within-segment token
emission in ONE pass.

Contract under test:

* ``TokenizeResult.segments`` is a ``list[str]`` (attribute-compatible with
  ``Decomposition.segments`` so the Plan-02 entrypoint/harness swap is mechanical).
* ``abstain_reason is not None`` is the abstain signal (D-15/D-18). Assertions on
  abstain assert ``is not None`` ONLY — never coupling to the reason string.
* Structural triggers (unquoted ``<<`` subsuming ``<<-``/``<<<``, ``<(``, ``>(``)
  abstain. ``$(`` / ``${``-funsub are NOT triggers this plan (deferred to the
  Plan-02 allowlist).
* ``$((...))`` arithmetic is held as ONE opaque unit: ``echo $((1 << 2))`` stays
  one segment with no fragmentation and the inner ``<<`` is not misread as a
  heredoc. The ``!= allow`` dimension is set by the Plan-02 allowlist on the live
  path (named deferral); this plan only guarantees no-fragmentation.
* The tokenizer is pure / re-entrant: the same triggers fire on an arbitrary
  substring passed directly to ``tokenize()`` (D-19).
"""

from __future__ import annotations

import pytest

from sash.tokenizer import TokenizeResult, tokenize

# --- segmentation -------------------------------------------------------------


def test_single_segment() -> None:
    result = tokenize("cat foo.txt")
    assert isinstance(result, TokenizeResult)
    assert result.abstain_reason is None
    assert result.segments == ["cat foo.txt"]


def test_top_level_split_two_segments() -> None:
    result = tokenize("cat foo && head f")
    assert result.abstain_reason is None
    assert result.segments == ["cat foo", "head f"]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("a; b", ["a", "b"]),
        ("a | b", ["a", "b"]),
        ("a || b", ["a", "b"]),
        ("a\nb", ["a", "b"]),
    ],
)
def test_top_level_operators_split(command: str, expected: list[str]) -> None:
    result = tokenize(command)
    assert result.abstain_reason is None
    assert result.segments == expected


def test_operators_inside_single_quotes_do_not_split() -> None:
    result = tokenize("echo 'a && b'")
    assert result.abstain_reason is None
    assert result.segments == ["echo 'a && b'"]


def test_operators_inside_double_quotes_do_not_split() -> None:
    result = tokenize('echo "a && b"')
    assert result.abstain_reason is None
    assert result.segments == ['echo "a && b"']


def test_escaped_separator_does_not_split() -> None:
    # a \&\& b  -- escaped ampersands are literal, one segment
    result = tokenize("a \\&\\& b")
    assert result.abstain_reason is None
    assert result.segments == ["a \\&\\& b"]


def test_quoted_operator_in_backtick_does_not_split() -> None:
    """UPDATED 04-02: inner ``;`` does not split; backtick cmdsub now ABSTAINS.

    The backtick-quoted ``;`` must NOT split the segment (TOK-01 structure
    preserved). UPDATED in 04-02 (TOK-02): backtick command substitution is
    command execution, not a provably-read-only form, so the allowlist abstains
    (complete-then-flag — segment stays one unit).
    """
    result = tokenize("echo `a; b`")
    assert result.abstain_reason is not None  # backtick cmdsub abstains (TOK-02)
    assert result.segments == ["echo `a; b`"]  # no fragmentation (TOK-01)


# --- structural abstain triggers ---------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "cat <(curl evil)",  # process-sub <(
        "cat >(tee x)",  # output process-sub >(
    ],
)
def test_process_sub_abstains(command: str) -> None:
    result = tokenize(command)
    assert result.abstain_reason is not None


@pytest.mark.parametrize(
    "command",
    [
        "cat <<EOF",  # heredoc
        "cat <<-EOF",  # heredoc dash
        "cat <<<hello",  # here-string
    ],
)
def test_here_constructs_abstain(command: str) -> None:
    result = tokenize(command)
    assert result.abstain_reason is not None


@pytest.mark.parametrize(
    "command",
    [
        "cat '\\' <(id)",  # CR-01: odd backslash before closing ' vs <(
        "cat '\\' >(id)",  # CR-01: vs >(
        "cat '\\' <<EOF",  # CR-01: vs <<
        "cat '\\' <<-EOF",  # CR-01: vs <<-
        "cat '\\' <<<x",  # CR-01: vs <<<
    ],
)
def test_odd_backslash_in_single_quote_abstains(command: str) -> None:
    """CR-01: bash applies NO escape inside single quotes.

    The closing ``'`` exits single-quote context so the following
    ``<(``/``>(``/``<<`` fires its abstain trigger. ``in_single`` MUST be
    evaluated BEFORE the backslash branch or the quoted region over-extends.
    """
    result = tokenize(command)
    assert result.abstain_reason is not None


def test_over_length_abstains() -> None:
    command = "cat " + "a" * 70000  # > 65536 code points -> abstain (D-17)
    result = tokenize(command)
    assert result.abstain_reason is not None


# --- safe forms stay non-abstain ---------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "echo '<(foo)'",  # single-quoted literal
        'echo "<(foo)"',  # double-quoted literal
        "echo '<<EOF'",  # single-quoted heredoc-lookalike
    ],
)
def test_quoted_literal_stays_safe(command: str) -> None:
    result = tokenize(command)
    assert result.abstain_reason is None


# --- arithmetic opaque unit (Pitfall 4) --------------------------------------


def test_arith_shift_no_fragmentation() -> None:
    """``echo $((1 << 2))`` is one opaque unit, no fragmentation; now ABSTAINS.

    The inner ``<<`` must NOT be misread as a heredoc; the segment must not
    split (Plan-01 no-fragmentation). UPDATED in 04-02 (TOK-02): the
    safe-expansion allowlist now sets ``abstain_reason`` on the ``$((`` opener
    (arithmetic is not a provably-read-only form) WITHOUT fragmenting the
    segment — both dimensions hold jointly (complete-then-flag).
    """
    result = tokenize("echo $((1 << 2))")
    assert result.abstain_reason is not None  # arith abstains (TOK-02)
    assert result.segments == ["echo $((1 << 2))"]  # no fragmentation (TOK-01)


def test_arith_unit_emits_no_garbage_tokens() -> None:
    """The ``$((...))`` arithmetic is held as ONE word token, no fragments.

    UPDATED in 04-02: arith now abstains (TOK-02), but the no-garbage-tokens /
    no-fragmentation structure (TOK-01) is unchanged — the unit is still one
    opaque word token.
    """
    result = tokenize("echo $((1 << 2))")
    assert result.abstain_reason is not None  # arith abstains (TOK-02)
    assert len(result.tokens) == 1
    seg = result.tokens[0]
    # Exactly two word tokens: `echo` and the opaque `$((1 << 2))` unit.
    texts = [t.text for t in seg.tokens]
    assert "$((1 << 2))" in texts
    # No fragment such as a bare `<` / `<<` / `2))` operator token.
    assert not any(t.text in ("<", "<<", "2))", "))") for t in seg.tokens)


def test_arith_does_not_split_on_inner_operators() -> None:
    """UPDATED 04-02: inner ``||`` does not split; arith abstains (TOK-02)."""
    result = tokenize("echo $((1 || 2))")
    assert result.abstain_reason is not None  # arith abstains (TOK-02)
    assert result.segments == ["echo $((1 || 2))"]  # no fragmentation (TOK-01)


# --- purity / re-entrancy (D-19) ---------------------------------------------


def test_substring_reuse_same_triggers() -> None:
    """The SAME triggers fire on an arbitrary substring (D-19 re-call)."""
    result = tokenize("cat <(curl evil)")
    assert result.abstain_reason is not None


def test_re_callable_identical_results() -> None:
    """Pure function: identical input yields identical results across calls."""
    a = tokenize("cat foo && head f")
    b = tokenize("cat foo && head f")
    assert a.segments == b.segments
    assert a.abstain_reason == b.abstain_reason

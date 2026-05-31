"""Behavior-preservation tests for the verbatim-ported compound splitter.

The splitter is the cardinal security path (it decomposes compound commands so
the fold can require EVERY segment to be recognized). These tests pin the
top-level split behavior the port must preserve.
"""

from __future__ import annotations

import pytest

from safe_read_hook.splitter import split_compound


def test_no_operators_returns_single_segment() -> None:
    assert split_compound("cat foo.txt") == ["cat foo.txt"]


@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        ("cat foo.txt && rm -rf x", ["cat foo.txt", "rm -rf x"]),
        ("a || b", ["a", "b"]),
        ("a ; b ; c", ["a", "b", "c"]),
        ("a | b", ["a", "b"]),
        ("a\nb", ["a", "b"]),
    ],
)
def test_top_level_operators_split(cmd: str, expected: list[str]) -> None:
    assert split_compound(cmd) == expected


def test_operators_inside_single_quotes_not_split() -> None:
    assert split_compound("echo 'a && b'") == ["echo 'a && b'"]


def test_operators_inside_double_quotes_not_split() -> None:
    assert split_compound('echo "a | b"') == ['echo "a | b"']


def test_operators_inside_command_substitution_not_split() -> None:
    assert split_compound("echo $(a && b)") == ["echo $(a && b)"]


def test_empty_string_yields_single_empty_stripped() -> None:
    # No splits occur -> the fallback returns [cmd.strip()] == [""].
    assert split_compound("") == [""]


def test_comment_stripped_at_top_level() -> None:
    assert split_compound("cat foo.txt # a comment") == ["cat foo.txt"]


# --- TEST-03 property/edge dimensions ------------------------------------
# Four named dimensions pinning split_compound's verbatim behavior on the
# adversarial edges: escaped separators, quoted operators (incl. backtick +
# mixed), nested $(), and embedded newlines. Each expected output is derived
# from the actual splitter logic (backslash handling line 91, $( paren-tracking
# line 129, the quote-state machine lines 80-128), not guessed. Plus the
# arith-shift collision pin that locks the <<-scan-vs-arithmetic interaction.


@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        # Escaped separators: a backslash before an operator char suppresses the
        # split (splitter line 91 consumes the escaped char), so each is one
        # segment with the backslashes preserved verbatim.
        (r"a \&\& b", [r"a \&\& b"]),
        (r"a \; b", [r"a \; b"]),
        (r"a \| b", [r"a \| b"]),
    ],
)
def test_property_escaped_separators_do_not_split(
    cmd: str, expected: list[str]
) -> None:
    assert split_compound(cmd) == expected


@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        # Backtick command substitution suppresses operators inside it.
        ("echo `a; b`", ["echo `a; b`"]),
        # ...but a top-level operator AFTER the closing backtick still splits.
        ("echo `a; b` && echo done", ["echo `a; b`", "echo done"]),
        # Mixed quoting: a backtick nested inside a double-quoted string, with a
        # separator inside the quotes, stays a single segment.
        ('echo "a;b`c`"', ['echo "a;b`c`"']),
    ],
)
def test_property_quoted_operators_do_not_split(cmd: str, expected: list[str]) -> None:
    assert split_compound(cmd) == expected


@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        # Nested $() — the paren_depth counter (line 129) tracks the inner
        # substitution, so neither the nesting nor a separator/operator inside
        # it splits the segment.
        ("echo $(a $(b) c)", ["echo $(a $(b) c)"]),
        ("echo $(a && b)", ["echo $(a && b)"]),
    ],
)
def test_property_nested_command_substitution_does_not_split(
    cmd: str, expected: list[str]
) -> None:
    assert split_compound(cmd) == expected


@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        # An unquoted newline is a top-level separator (in _SINGLE_SPLITS).
        ("a\nb", ["a", "b"]),
        # A newline inside single quotes is a literal, not a separator.
        ("echo 'a\nb'", ["echo 'a\nb'"]),
    ],
)
def test_property_embedded_newlines(cmd: str, expected: list[str]) -> None:
    assert split_compound(cmd) == expected


def test_property_arith_shift_collision_stays_single_segment() -> None:
    # Cross-link pin (TEST-03): `<<` inside $((...)) is the left-shift operator,
    # NOT a heredoc. The splitter keeps the whole arithmetic expansion as one
    # segment, locking the <<-scan-vs-arithmetic interaction so a future change
    # cannot silently fragment it into a false-allow.
    assert split_compound("echo $((1 << 2))") == ["echo $((1 << 2))"]

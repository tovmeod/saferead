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

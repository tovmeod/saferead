"""REC-06 boundary tests for the shared redirect-target helper (D-05).

The cardinal point of these tests is the ALLOW/ABSTAIN boundary of
``redirect_tail_is_safe``: a discard redirect and a genuine single-component
``/tmp`` scratch write are safe (glued AND split shapes); a ``/tmp`` traversal
(glued OR spaced), a second-slash target, a bare operator with no target, any
non-``/tmp`` real-file target, the SAFETY-FLOOR append/combined-redirect forms,
and any metacharacter target are all unsafe (the recognizer then abstains).

A single live ``tokenize -> fold`` assertion pins the D-07 corpus flip:
``echo x >/tmp/../etc/passwd`` folds to a non-allow decision through the real
pipeline (the reader has always abstained on this via its ``>`` veto, and
continues to after Task 2 routes through this helper).
"""

from __future__ import annotations

import pytest

from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers.redirects import redirect_tail_is_safe
from safe_read_hook.tokenizer import tokenize


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- redirect ALLOW (safe) cases ------------------------------------------


@pytest.mark.parametrize(
    "arg_tokens",
    [
        # discard redirects (glued)
        [">/dev/null"],
        ["2>/dev/null"],
        ["2>&1"],
        ["&>/dev/null"],
        ["&>>/dev/null"],
        [">&2"],  # fd dup
        ["1>&2"],  # fd dup, named source fd
        # discard redirects (split)
        [">", "/dev/null"],
        ["2>", "/dev/null"],
        # /tmp single-component scratch (glued)
        [">/tmp/scratch"],
        [">>/tmp/log"],  # append to scratch
        ["2>/tmp/err"],
        # /tmp single-component scratch (split)
        [">", "/tmp/scratch"],
        [">>", "/tmp/log"],
        # plain operands / flags with no redirect at all
        [],
        ["foo.txt"],
        ["-l", "f"],
        # mixed: an operand plus a safe redirect
        ["x", ">/tmp/foo"],
        ["x", ">", "/tmp/foo"],
    ],
)
def test_redirect_tail_allow(arg_tokens: list[str]) -> None:
    assert redirect_tail_is_safe(arg_tokens) is True


# --- redirect ABSTAIN (unsafe) cases --------------------------------------


@pytest.mark.parametrize(
    "arg_tokens",
    [
        # traversal — glued AND spaced (Pitfall 1)
        [">/tmp/../etc/passwd"],
        [">", "/tmp/../etc/passwd"],
        # bare /tmp/.. component
        [">/tmp/.."],
        [">/tmp/."],
        # second slash after /tmp/
        [">/tmp/sub/file"],
        # bare operator with no target
        [">/tmp"],
        [">"],
        [">>"],
        ["2>"],  # trailing split operator, no target
        # non-/tmp real-file targets
        [">file"],
        [">out.txt"],
        ["2>/etc/x"],
        [">~/.bashrc"],
        [">", "out.txt"],
        # SAFETY FLOOR: append / combined-redirect to a real file
        [">>/etc/passwd"],
        [">&/etc/passwd"],  # combined-redirect to a FILE, NOT the >&N fd-dup
        # metacharacter in target
        [">/tmp/a;b"],
        [">/tmp/a|b"],
    ],
)
def test_redirect_tail_abstain(arg_tokens: list[str]) -> None:
    assert redirect_tail_is_safe(arg_tokens) is False


# --- live fold-path corpus flip (D-07) ------------------------------------


def test_redirect_traversal_folds_non_allow(ctx: Context) -> None:
    """D-07: ``echo x >/tmp/../etc/passwd`` folds to a non-allow decision.

    Asserted through the real ``tokenize -> fold`` pipeline (not the helper in
    isolation): the traversal vector never reaches ``allow``.
    """
    result = tokenize("echo x >/tmp/../etc/passwd")
    assert result.abstain_reason is None
    verdict = fold(result.segments, ctx)
    assert verdict is None or verdict.decision != "allow"

"""Tests for the pure decision fold: abstain-veto, precedence, and CORE-04.

The registry-patch target is ``safe_read_hook.engine.REGISTRY`` — ``fold`` does
``from .recognizers import REGISTRY``, which binds the name in the engine's own
namespace. Rebinding ``recognizers.REGISTRY`` would leave the engine pointing at
the old list and the patch would silently misfire.
"""

from __future__ import annotations

import pytest

from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers.reader import recognize_reader


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


def test_all_allow_returns_allow_input_verdict(ctx: Context) -> None:
    verdict = fold(["cat foo.txt"], ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "reader"  # an input Verdict, not synthesized


def test_veto_one_unrecognized_segment_abstains(ctx: Context) -> None:
    # The cardinal proof (CORE-05): rm is unrecognized -> the compound abstains.
    assert fold(["cat foo.txt", "rm -rf x"], ctx) is None


def test_empty_segments_abstain(ctx: Context) -> None:
    assert fold([], ctx) is None


def test_precedence_ask_dominates_allow(ctx: Context, stub_ask, monkeypatch) -> None:
    # Registry must contain stub_ask, else "gitstub op" is unrecognized -> veto.
    monkeypatch.setattr("safe_read_hook.engine.REGISTRY", [recognize_reader, stub_ask])
    verdict = fold(["cat foo.txt", "gitstub op"], ctx)
    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.tag == "test.ask"  # the surviving input Verdict, unchanged


def test_registry_extension_point(ctx: Context, stub_ask, monkeypatch) -> None:
    # CORE-04: adding a recognizer is a REGISTRY list edit; fold is unchanged.
    monkeypatch.setattr("safe_read_hook.engine.REGISTRY", [recognize_reader, stub_ask])
    # A segment only stub_ask recognizes now resolves instead of vetoing.
    verdict = fold(["gitstub op"], ctx)
    assert verdict is not None
    assert verdict.decision == "ask"

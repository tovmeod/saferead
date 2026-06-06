"""TEST-04 golden regression: documented intent through tokenize -> fold.

A data-driven, parametrized regression over an EXTERNAL checked-in fixture
(``golden_decisions.json``) mapping representative payloads to their
LIVE-VERIFIED intended ``(decision, tag)``. It proves the extracted package
reproduces the seed's CORRECTED intent — seed-parity MINUS the 7 deliberately
fixed bypasses, which each assert ``(abstain, None)`` with a divergence note.

This is a POSITIVE payload->intended-decision parity net, DISTINCT from and
additive to ``test_corpus.py``'s ``!= allow`` never-allow net (D-11): it catches
both "right answer, wrong recognizer" regressions (an exact-tag assertion) and
silently re-opened bypasses (an exact ``(abstain, None)`` assertion).

The test IS the authoring guard (T-10-06): each fixture payload is re-run
through ``tokenize -> fold`` and must reproduce its verified tuple, so a JSON
quoting drift on the embedded-quote awk/sed payloads fails loudly rather than
silently asserting a different command.

Only ``(decision, tag)`` is asserted — NEVER the reason string (D-09, Pitfall
5); the fixture ``note`` is documentation, surfaced as the assert message.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.tokenizer import tokenize

#: The external checked-in golden fixture, loaded once at module scope.
_GOLDEN = json.loads((Path(__file__).parent / "golden_decisions.json").read_text())


def _decision_and_tag(command: str, branch: str | None) -> tuple[str, str | None]:
    """Run ``command`` through tokenize -> fold, returning ``(decision, tag)``.

    Mirrors ``test_corpus._decision`` but returns the full tuple and injects a
    per-case branch via ``_resolver`` (Pitfall 4 — needed for the feature-branch
    allow arm). BOTH abstain paths — the tokenizer surfacing an abstain trigger
    AND the fold's segment-veto returning ``None`` — collapse to
    ``("abstain", None)``; otherwise the folded verdict's ``(decision, tag)``.
    """
    ctx = Context(cwd="/x", _resolver=lambda _c: branch)
    result = tokenize(command)
    if result.abstain_reason is not None:
        return ("abstain", None)
    verdict = fold(result.segments, ctx)
    if verdict is None:
        return ("abstain", None)
    return (verdict.decision, verdict.tag)


@pytest.mark.parametrize(
    "case",
    _GOLDEN,
    ids=[f'{c["decision"]}:{c["command"]}@{c.get("branch", "-")}' for c in _GOLDEN],
)
def test_golden_decision_and_tag(case: dict) -> None:
    """Each fixture payload reproduces its documented intended ``(decision, tag)``.

    Asserts the LIVE tuple ONLY (never the reason string, D-09). The fixture
    ``note`` is the assert message — documentation, not an assertion.
    """
    actual = _decision_and_tag(case["command"], case.get("branch"))
    expected = (case["decision"], case.get("tag"))
    assert actual == expected, case.get("note", "")

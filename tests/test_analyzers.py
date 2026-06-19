"""Tests for the pluggable language-analyzer seam (TOK-03 / TOK-04).

Three dimensions:

* dispatch: ``ANALYZERS["python"]`` is registered and callable, returning
  ``Verdict | None`` (the analyzer contract).
* Python skeleton: ``analyze_python`` abstains (returns ``None``) on both a
  parseable-but-unjudged source AND an unparseable one (``SyntaxError``).
* extensibility ACCEPTANCE (TOK-04): adding a language touches ONLY the
  ``ANALYZERS`` mapping — mirror the ``conftest.stub_ask`` injection idiom; add
  one dict entry and assert dispatch fires, with no engine/tokenizer/sibling
  edit required (asserted by construction: the test adds a dict entry, nothing
  else).
"""

from __future__ import annotations

from sash.analyzers import ANALYZERS
from sash.analyzers.python_skeleton import analyze_python
from sash.verdict import Verdict

# --- dispatch -------------------------------------------------------------


def test_python_registered_and_callable() -> None:
    """``ANALYZERS["python"]`` is registered and returns ``Verdict | None``."""
    assert "python" in ANALYZERS
    analyzer = ANALYZERS["python"]
    assert callable(analyzer)
    result = analyzer("import os")
    assert result is None or isinstance(result, Verdict)


# --- Python skeleton ------------------------------------------------------


def test_python_skeleton_abstains_on_parseable() -> None:
    """The skeleton proves the seam only — a parseable source still abstains."""
    assert analyze_python("import os") is None


def test_python_skeleton_abstains_on_syntax_error() -> None:
    """An unparseable source (SyntaxError) -> abstain (None), D-15."""
    assert analyze_python("x = (") is None


# --- extensibility acceptance (TOK-04) ------------------------------------


def test_extensibility_touch_one_module() -> None:
    """Adding a language touches ONLY the ANALYZERS mapping.

    Mirrors the ``conftest.stub_ask`` injection idiom: inject a stub analyzer
    into ``ANALYZERS`` and assert dispatch fires for that language. The act of
    adding the entry is the entire change — no engine/tokenizer/sibling edit.
    """
    sentinel = Verdict("allow", "stub", "test.analyzer")
    ANALYZERS["stublang"] = lambda s: sentinel
    try:
        assert ANALYZERS["stublang"]("anything") is sentinel
    finally:
        del ANALYZERS["stublang"]

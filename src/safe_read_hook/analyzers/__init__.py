"""The per-language analyzer registry (TOK-03).

A language *analyzer* has the contract ``analyze(source) -> Verdict | None``
(D4-08): given an embedded-sublanguage source string, it returns a
:class:`~safe_read_hook.verdict.Verdict` or ``None`` to abstain. This mirrors
the recognizer ``Callable`` contract (``recognizers/__init__.py``), but the
analyzers live in a SEPARATE mapping keyed by language name — distinct from the
ordered fold ``REGISTRY``: analyzers are dispatched by language (``ANALYZERS[
lang](source)``), not folded first-match-wins over segments.

Adding a language is a single import + a single dict entry here — no engine,
tokenizer, or sibling-recognizer change (the extensibility acceptance signal,
TOK-04). A bash recognizer extracts an embedded sublanguage argument and
dispatches it to the matching ``ANALYZERS[lang]``.
"""

from __future__ import annotations

from collections.abc import Callable

from ..verdict import Verdict
from .python_skeleton import analyze_python

#: The per-language analyzer contract (D4-08): analyze(source) -> Verdict | None.
Analyzer = Callable[[str], "Verdict | None"]

#: Per-language analyzers, keyed by language name. SEPARATE from REGISTRY.
#: Add a language = one import above + one entry here.
ANALYZERS: dict[str, Analyzer] = {
    "python": analyze_python,
}

"""Stub Python language analyzer (TOK-04) — prove-the-seam only.

A language analyzer has the contract ``analyze(source) -> Verdict | None``: it
returns a :class:`~safe_read_hook.verdict.Verdict` when it can judge the
embedded source, or ``None`` to abstain. This skeleton exists to prove the
analyzer seam fires and to abstain on unparseable input — it implements NO
Python safety policy (no import-checking, no ``open()``-mode analysis). The
full Python read-only policy is Phase 12 (D4-10); for TOK-04, returning ``None``
always is acceptable (the acceptance signal is "the module plugs in by touching
only its own file + one ANALYZERS entry," not "Python safety is decided").

``ast`` is imported INSIDE the function (Pitfall 5): the reader top-imports
``ANALYZERS`` and runs on every hook invocation, so a module-top ``import ast``
would pull ``ast`` onto the common read path and cost latency on every Bash
call. Keeping the import lazy honors the project's low-latency constraint. (This
is a deliberate exception to the usual top-level-import rule, justified by the
performance constraint on the common read path.)
"""

from __future__ import annotations

from ..verdict import Verdict


def analyze_python(source: str) -> Verdict | None:
    """Abstain on any Python source (skeleton); abstain on SyntaxError too.

    Returns ``None`` in all cases: an unparseable source (``SyntaxError`` ->
    abstain, D-15) and a parseable one (skeleton has no policy yet). The
    ``Verdict | None`` return type is the analyzer contract; a future Phase-12
    policy returns an ``allow`` Verdict for a provably read-only program.
    """
    import ast

    try:
        ast.parse(source)
    except SyntaxError:
        return None  # unparseable -> abstain (D-15)
    return None  # skeleton: prove-the-seam only; full policy = Phase 12 (D4-10)

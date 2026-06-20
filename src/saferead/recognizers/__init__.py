"""The ordered recognizer registry (D-01/D-02, CORE-04).

A recognizer is a ``(segment, ctx) -> Verdict | None`` callable. The registry
is an ordered list; the engine iterates it first-match-wins and never names a
recognizer by hand. Adding a recognizer in a later phase is a single list edit
here — no engine change.

Recognizer disable (D-06, Phase 9): each REGISTRY entry is wrapped in a
tag-labeled GUARD (:func:`_guarded`) that reads ``ctx.config.disabled_recognizers``
per call. When the recognizer's tag is in that set the guard ABSTAINS (returns
``None``) before the recognizer runs; otherwise it delegates unchanged. The
disabled set rides ``ctx.config`` (injected once at the entrypoint), so there is
NO module global and the registry is never mutated at runtime. ``engine.fold``
stays byte-identical — it iterates the guarded list exactly as before and never
learns about the disabled set. A disabled recognizer can only abstain, never
allow, so disabling is monotonic toward MORE prompts (cardinal-safe).
"""

from __future__ import annotations

from collections.abc import Callable

from ..context import Context
from ..verdict import Verdict
from .adb import recognize_adb
from .find import recognize_find
from .git import recognize_git
from .gradle import recognize_gradle
from .journalctl import recognize_journalctl
from .psql import recognize_psql
from .pytest_runner import recognize_pytest
from .python import recognize_python
from .reader import recognize_reader
from .sed import recognize_sed
from .ssh import recognize_ssh

#: The uniform recognizer contract (D-01).
Recognizer = Callable[[str, Context], "Verdict | None"]


def _guarded(tag: str, fn: Recognizer) -> Recognizer:
    """Wrap ``fn`` in a tag-labeled guard reading ``ctx.config.disabled_recognizers``.

    The returned closure abstains (returns ``None``) when ``tag`` is in
    ``ctx.config.disabled_recognizers`` — short-circuiting BEFORE ``fn`` runs —
    and otherwise delegates to ``fn`` unchanged. The disabled set is read per-call
    from ``ctx`` (no module global; the registry is never mutated). ``tag`` must
    EXACTLY match the ``Verdict.tag`` string ``fn`` emits (D-06).
    """

    def _guard(segment: str, ctx: Context) -> Verdict | None:
        if tag in ctx.config.disabled_recognizers:
            return None
        return fn(segment, ctx)

    return _guard


#: Ordered registry; order is significant (D-02). Reader stays FIRST (the common
#: read path); the git, find, sed, adb, pytest, gradle, psql, python,
#: journalctl, and ssh recognizers follow (CORE-04 — one list edit per new
#: recognizer, no engine change). Order among the latter is immaterial: they
#: claim disjoint leading commands (``git`` / ``find`` / ``sed`` / ``adb`` /
#: a ``pytest`` launcher shape / a ``gradle`` launcher shape / ``psql`` /
#: ``python`` / ``journalctl`` / ``ssh``).
#:
#: Each entry is a tag-labeled guard (:func:`_guarded`) so a globally/project
#: disabled tag abstains its recognizer (D-06). The tag string MUST match the
#: ``Verdict.tag`` the wrapped recognizer emits. ``engine.fold`` iterates this
#: guarded list transparently — no engine change (CORE-04/CORE-05).
REGISTRY: list[Recognizer] = [
    _guarded("reader", recognize_reader),
    _guarded("git", recognize_git),
    _guarded("find", recognize_find),
    _guarded("sed", recognize_sed),
    _guarded("adb", recognize_adb),
    _guarded("pytest", recognize_pytest),
    _guarded("gradle", recognize_gradle),
    _guarded("psql", recognize_psql),
    _guarded("python", recognize_python),
    _guarded("journalctl", recognize_journalctl),
    _guarded("ssh", recognize_ssh),
]

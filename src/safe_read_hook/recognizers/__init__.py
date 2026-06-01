"""The ordered recognizer registry (D-01/D-02, CORE-04).

A recognizer is a ``(segment, ctx) -> Verdict | None`` callable. The registry
is an ordered list; the engine iterates it first-match-wins and never names a
recognizer by hand. Adding a recognizer in a later phase is a single list edit
here — no engine change.
"""

from __future__ import annotations

from collections.abc import Callable

from ..context import Context
from ..verdict import Verdict
from .git import recognize_git
from .reader import recognize_reader

#: The uniform recognizer contract (D-01).
Recognizer = Callable[[str, Context], "Verdict | None"]

#: Ordered registry; order is significant (D-02). Reader stays FIRST (the common
#: read path); the git recognizer follows (CORE-04 — one list edit per new
#: recognizer, no engine change).
REGISTRY: list[Recognizer] = [recognize_reader, recognize_git]

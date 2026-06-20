"""The pure decision fold — the cardinal zero-false-allow mitigation (CORE-05).

``fold`` reduces a list of command segments to a single ``Verdict`` (or
``None`` = abstain) by running each segment through the ordered recognizer
REGISTRY. Two rules give the safety guarantee:

1. **Abstain-veto (D-07):** if ANY segment is unrecognized by every recognizer,
   the whole compound abstains (``return None`` immediately). A deliberately
   thin reader is safe because one unrecognized segment vetoes the lot.
2. **Precedence abstain > ask > allow:** among recognized segments, an ``ask``
   Verdict supersedes ``allow``. The returned Verdict is LITERALLY one of the
   input Verdicts — its own tag/reason unchanged, never a synthesized combine.

The fold is PURE: deterministic given ``(segments, ctx)``, with no I/O and no
side effects of any kind. The engine never names a recognizer; adding one is a
single edit to REGISTRY (CORE-04).
"""

from __future__ import annotations

from .context import Context
from .recognizers import REGISTRY
from .verdict import Verdict


def fold(segments: list[str], ctx: Context) -> Verdict | None:
    """Reduce ``segments`` to one Verdict, or ``None`` (abstain).

    Returns ``None`` if there are no segments, or the moment one segment is
    unrecognized by every recognizer (the abstain-veto). Otherwise returns the
    surviving input Verdict by precedence ``ask`` > ``allow``.
    """
    survivor: Verdict | None = None
    for segment in segments:
        match: Verdict | None = None
        for recognizer in REGISTRY:
            match = recognizer(segment, ctx)
            if match is not None:
                break
        if match is None:
            # One unrecognized segment vetoes the whole compound (D-07/CORE-05).
            return None
        # Precedence: an ask supersedes an allow. Keep an actual input Verdict.
        ask_beats_allow = (
            survivor is not None
            and survivor.decision == "allow"
            and match.decision == "ask"
        )
        if survivor is None or ask_beats_allow:
            survivor = match
    return survivor

"""The Verdict value object returned by recognizers.

A recognizer returns a ``Verdict`` to express a decision about a single
command segment, or ``None`` to *abstain* (stay silent and let the normal
permission flow proceed). Abstain is deliberately NOT a Verdict value: the
absence of an opinion is the absence of an object.

The hook never emits ``"deny"`` (D-03/D-04); blocking dangerous commands is
``dcg``'s job. ``tag`` is carried now and consumed in Phase 9 (observability).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: The only valid ``Verdict.decision`` values. Abstain is ``None``, not a member.
Decision = Literal["allow", "ask"]


@dataclass(frozen=True, slots=True)
class Verdict:
    """An immutable recognizer decision about one command segment.

    Attributes:
        decision: ``"allow"`` (auto-approve) or ``"ask"`` (gated confirmation).
            Abstaining is expressed by returning ``None`` instead of a Verdict.
        reason: Short human-readable justification, surfaced to the user / log.
        tag: Short stable identifier of the deciding recognizer (e.g.
            ``"reader"``); used for logging/observability and test assertions.
    """

    decision: Decision
    reason: str
    tag: str

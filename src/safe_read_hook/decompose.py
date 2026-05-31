"""The hardening wrapper that makes decomposition the cardinal-failure surface.

``decompose`` runs three checks on the RAW command string BEFORE the verbatim
``split_compound`` (D-10 — that scan is never edited):

1. **Over-length guard (D-17):** if the raw input exceeds 64 KB code points,
   abstain. Measured on the raw string before splitting; deterministic, caps
   ReDoS/latency on pathological model-generated one-liners.
2. **Quote-aware structural scan (D-15/CORE-02):** an UNQUOTED ``<(``, ``>(``,
   ``<<`` (which subsumes ``<<-`` and ``<<<``) surfaces abstain. ``<(``/``>(``
   are process substitution; ``<<`` opens a heredoc/here-string whose body is
   not a real command. These fragment ACROSS ``split_compound`` segments (``<(``
   is not paren-tracked, line 129), so detection MUST run on the raw string.
3. Otherwise return the verbatim ``split_compound(command)`` segments.

Any trigger surfaces abstain via a frozen ``Decomposition(segments,
abstain_reason)`` (D-18): ``abstain_reason is not None`` means abstain. This
folds in the entrypoint now and the Phase-10 ssh recognizer later — the SAME
``decompose`` re-applies the same triggers on an arbitrary substring (D-19), so
a remote ``cat <(curl evil)`` is exactly as dangerous as a local one.

The quote model is MIRRORED from ``split_compound`` (single/double/backtick +
backslash). ``paren_depth`` is deliberately NOT replicated: it suppresses
operator splits inside ``$()`` and would wrongly suppress a ``<(`` nested in a
command substitution — detecting the constructs everywhere-unquoted is strictly
more conservative, which is the cardinal direction.
"""

from __future__ import annotations

from dataclasses import dataclass

from .splitter import split_compound

#: Raw-input ceiling in code points (D-17). Far exceeds any real read command.
_MAX_LEN = 65536


@dataclass(frozen=True, slots=True)
class Decomposition:
    """An immutable decomposition result, or an abstain signal.

    Attributes:
        segments: The top-level command segments from the verbatim
            ``split_compound``. Empty when an abstain trigger fired before the
            split ran.
        abstain_reason: ``None`` on success; otherwise a short human-readable
            cause (over-length or the offending construct). A non-``None`` value
            is the D-15 abstain signal — the entrypoint emits nothing. The
            reason forwards to Phase-9 logging, the role ``Verdict.reason`` plays.
    """

    segments: list[str]
    abstain_reason: str | None


def decompose(command: str) -> Decomposition:
    """Harden + split ``command``, surfacing abstain on the structural triggers.

    Over-length and unquoted process-substitution / heredoc / here-string
    constructs abstain (``abstain_reason`` set). Otherwise the verbatim
    ``split_compound`` segments are returned with ``abstain_reason=None``.
    """
    if len(command) > _MAX_LEN:
        return Decomposition(
            segments=[],
            abstain_reason=f"over-length input ({len(command)} > {_MAX_LEN})",
        )

    i = 0
    n = len(command)
    in_single = in_double = in_backtick = False
    while i < n:
        c = command[i]
        if in_single:
            # Bash applies NO escape semantics inside single quotes (CR-01 fix):
            # evaluate in_single BEFORE the backslash branch so an odd backslash
            # before the closing quote stays literal and does not over-extend the
            # quoted region across an active <(/<<. Mirror splitter._strip_comments
            # ordering (in_single precedes the backslash check).
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            # Backslash escape suppresses the next char (mirror splitter line 91).
            i += 2
            continue
        if in_double:
            if c == '"':
                in_double = False
            i += 1
            continue
        if in_backtick:
            if c == "`":
                in_backtick = False
            i += 1
            continue
        if c == "'":
            in_single = True
            i += 1
            continue
        if c == '"':
            in_double = True
            i += 1
            continue
        if c == "`":
            in_backtick = True
            i += 1
            continue
        # Unquoted structural triggers. `<<` subsumes `<<-` and `<<<`.
        if c == "<" and i + 1 < n and command[i + 1] == "<":
            return Decomposition(
                segments=[], abstain_reason="heredoc/here-string operator (<<)"
            )
        if c == "<" and i + 1 < n and command[i + 1] == "(":
            return Decomposition(
                segments=[], abstain_reason="process substitution (<()"
            )
        if c == ">" and i + 1 < n and command[i + 1] == "(":
            return Decomposition(
                segments=[], abstain_reason="process substitution (>()"
            )
        # Unquoted command substitution `$(` (CR-02 defense-in-depth ONLY). The
        # reader `_QARG` fix is the OPERATIVE closer for the QUOTED `cat "$(id)"`
        # / `cat "`id`"` vectors — those `$(`/backtick sit inside in_double and
        # never reach this section. This trigger only catches bare unquoted
        # `cat $(id)` so a future widened reader grammar cannot re-open it. The
        # unquoted backtick already abstains via the reader's bare-arg exclusion.
        if c == "$" and i + 1 < n and command[i + 1] == "(":
            return Decomposition(
                segments=[], abstain_reason="command substitution ($()"
            )
        i += 1

    return Decomposition(segments=split_compound(command), abstain_reason=None)

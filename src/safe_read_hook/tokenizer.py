"""From-scratch bash tokenizer (TOK-01) — segmentation + token emission + abstain.

A pure, re-entrant char-state-machine that owns top-level segmentation AND
within-segment token emission in ONE pass, replacing the dual ``splitter`` +
``decompose`` tracking. It tracks single/double/backtick quote state and the
opaque ``$((...))`` arithmetic unit, splits at top-level ``&&``/``||``/``;``/
``|``/newline, and surfaces abstain on the structural false-allow triggers.

MECHANISM is copied from the now-superseded ``splitter.py`` (the ``flush()``
segment-buffer pattern, the ``_DOUBLE_SPLITS``/``_SINGLE_SPLITS`` operator sets,
the ``paren_depth`` bookkeeping) and ``decompose.py`` (the frozen result +
``abstain_reason`` idiom, the 64 KB over-length guard, the ``in_single``-BEFORE-
backslash ordering = the CR-01 fix, the non-``$`` structural triggers). POLICY
is NOT copied: there is no ``split_compound`` parity, and the ``$(`` cmdsub /
``${``-funsub abstain triggers are deliberately NOT carried — every ``$``-form is
gated by the safe-expansion allowlist that lands in the next plan (one gate for
all ``$``-forms, not two parallel gates). ``paren_depth`` survives ONLY to bound
the opaque ``$((...))`` unit, never to pass command-substitution contents
through.

Abstain contract (D-15/D-18): ``abstain_reason is not None`` means abstain. The
top-level ``segments: list[str]`` field mirrors ``Decomposition.segments``
exactly so the next plan's entrypoint/harness swap is attribute-compatible and
``fold`` (which takes ``list[str]``) is never touched. The richer ``tokens``
structure is consumed by the reader in a later plan.

The function is PURE — all scan state is local, no module-level mutable state —
so the SAME triggers fire on an arbitrary substring (D-19): a remote
``cat <(curl evil)`` is exactly as dangerous as a local one.

Arithmetic note (Pitfall 4): ``$((`` ... ``))`` is accumulated verbatim as ONE
opaque word token while paren depth is counted; the ``<<`` structural trigger
and top-level operator splits are SUPPRESSED inside it so the inner left-shift /
embedded whitespace cannot fragment the segment. ``$((...))`` is not a
provably-read-only form, but THIS plan only guarantees no-fragmentation; the
complementary live-path abstain (``!= allow``) is set by the next plan's
allowlist on the ``$((`` opener.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Raw-input ceiling in code points (D-17). Far exceeds any real read command;
#: caps ReDoS/latency on pathological model-generated one-liners. Measured on the
#: raw string before scanning.
_MAX_LEN = 65536

#: Top-level two-char operators that split a compound (mirror splitter.py:13).
_DOUBLE_SPLITS = frozenset({("&", "&"), ("|", "|")})
#: Top-level single-char operators that split a compound (mirror splitter.py:14).
_SINGLE_SPLITS = frozenset({";", "|", "\n"})


@dataclass(frozen=True, slots=True)
class Token:
    """A single within-segment token.

    Attributes:
        kind: ``"word"`` for an argument-bearing run. The opaque ``$((...))``
            arithmetic unit is a single ``"word"`` token (no fragmentation).
            Top-level separators are segment boundaries, not tokens, so they are
            not emitted; the ``kind`` field is reserved for the richer token
            classes the reader adds in a later plan.
        text: The verbatim token text.
    """

    kind: str
    text: str


@dataclass(frozen=True, slots=True)
class Segment:
    """The within-segment token list for one top-level segment."""

    tokens: list[Token]


@dataclass(frozen=True, slots=True)
class TokenizeResult:
    """An immutable tokenize result, or an abstain signal.

    Attributes:
        segments: The top-level command segments as stripped strings. Mirrors
            ``Decomposition.segments`` exactly (same shape/semantics) so the
            entrypoint/harness swap is attribute-compatible. Empty when an
            abstain trigger fired before the scan finished.
        tokens: The per-segment token structure, index-aligned with
            ``segments``. Consumed by the reader in a later plan. Empty on
            abstain.
        abstain_reason: ``None`` on success; otherwise a short human-readable
            cause. A non-``None`` value is the D-15 abstain signal.
    """

    segments: list[str]
    tokens: list[Segment]
    abstain_reason: str | None


def _abstain(reason: str) -> TokenizeResult:
    return TokenizeResult(segments=[], tokens=[], abstain_reason=reason)


def tokenize(command: str) -> TokenizeResult:
    """Segment + tokenize ``command``, surfacing abstain on structural triggers.

    Over-length input and unquoted process-substitution / heredoc / here-string
    constructs abstain (``abstain_reason`` set). ``$((...))`` arithmetic is held
    as one opaque word token (no fragmentation, no abstain this plan). Otherwise
    the stripped segments are returned with ``abstain_reason=None``.

    Pure / re-entrant: all scan state is local, so the same triggers fire on any
    substring (D-19).
    """
    if len(command) > _MAX_LEN:
        return _abstain(f"over-length input ({len(command)} > {_MAX_LEN})")

    i = 0
    n = len(command)
    in_single = in_double = in_backtick = False
    arith_depth = 0  # > 0 while inside an open `$((` ... `))` opaque unit.

    segments: list[str] = []
    seg_tokens: list[Token] = []
    all_tokens: list[Segment] = []
    cur: list[str] = []  # current segment-string buffer
    word: list[str] = []  # current word-token buffer

    def flush_word() -> None:
        s = "".join(word)
        if s:
            seg_tokens.append(Token(kind="word", text=s))
        word.clear()

    def flush_segment() -> None:
        flush_word()
        s = "".join(cur).strip()
        if s:
            segments.append(s)
            all_tokens.append(Segment(tokens=list(seg_tokens)))
        cur.clear()
        seg_tokens.clear()

    while i < n:
        c = command[i]

        # --- inside the opaque arithmetic unit ($(( ... ))) ------------------
        # Accumulate verbatim; count paren depth; suppress ALL triggers and
        # operator splits so the inner `<<` / whitespace / `||` cannot fragment
        # the segment (Pitfall 4). Quote state is irrelevant inside the unit.
        if arith_depth > 0:
            if c == "(":
                arith_depth += 1
            elif c == ")":
                arith_depth -= 1
            cur.append(c)
            word.append(c)
            i += 1
            continue

        # --- quote-state ordering: in_single BEFORE backslash (CR-01) --------
        # Bash applies NO escape inside single quotes, so an odd backslash before
        # the closing quote stays literal and does not over-extend the quoted
        # region across an active <(/<<.
        if in_single:
            cur.append(c)
            word.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            # Backslash escape suppresses the next char (outside single quotes).
            cur.append(c)
            cur.append(command[i + 1])
            word.append(c)
            word.append(command[i + 1])
            i += 2
            continue
        if in_double:
            cur.append(c)
            word.append(c)
            if c == '"':
                in_double = False
            i += 1
            continue
        if in_backtick:
            cur.append(c)
            word.append(c)
            if c == "`":
                in_backtick = False
            i += 1
            continue
        if c == "'":
            in_single = True
            cur.append(c)
            word.append(c)
            i += 1
            continue
        if c == '"':
            in_double = True
            cur.append(c)
            word.append(c)
            i += 1
            continue
        if c == "`":
            in_backtick = True
            cur.append(c)
            word.append(c)
            i += 1
            continue

        # --- opaque arithmetic opener: `$((` --------------------------------
        # Enter the opaque unit BEFORE the `$(` cmdsub / `<<` checks so the
        # inner shift is never misread. The whole `$((...))` is one word token.
        if (
            c == "$"
            and i + 2 < n
            and command[i + 1] == "("
            and command[i + 2] == "("
        ):
            arith_depth = 2  # the two opening parens
            cur.append("$((")
            word.append("$((")
            i += 3
            continue

        # --- structural abstain triggers (mechanism from decompose) ----------
        # `<<` subsumes `<<-` and `<<<`. NOTE: the `$(` cmdsub and `${`-funsub
        # triggers are DELIBERATELY NOT carried — those $-forms are gated by the
        # safe-expansion allowlist in the next plan (one gate for all $-forms).
        if c == "<" and i + 1 < n and command[i + 1] == "<":
            return _abstain("heredoc/here-string operator (<<)")
        if c == "<" and i + 1 < n and command[i + 1] == "(":
            return _abstain("process substitution (<()")
        if c == ">" and i + 1 < n and command[i + 1] == "(":
            return _abstain("process substitution (>()")

        # --- top-level operator splits (mechanism from splitter) -------------
        # The separator is a boundary BETWEEN segments, not a token within the
        # segment it closes, so flush the segment without emitting an operator
        # token into it.
        if i + 1 < n and (c, command[i + 1]) in _DOUBLE_SPLITS:
            flush_segment()
            i += 2
            continue
        if c in _SINGLE_SPLITS:
            flush_segment()
            i += 1
            continue

        # --- word accumulation ----------------------------------------------
        if c.isspace():
            flush_word()
            cur.append(c)
            i += 1
            continue
        cur.append(c)
        word.append(c)
        i += 1

    flush_segment()
    return TokenizeResult(segments=segments, tokens=all_tokens, abstain_reason=None)

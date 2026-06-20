"""From-scratch bash tokenizer (TOK-01) — segmentation + token emission + abstain.

A pure, re-entrant char-state-machine that owns top-level segmentation AND
within-segment token emission in ONE pass, replacing the dual ``splitter`` +
``decompose`` tracking. It tracks single/double/backtick quote state and the
opaque ``$((...))`` arithmetic unit, splits at top-level ``&&``/``||``/``;``/
``|``/newline, and surfaces abstain on the structural false-allow triggers.

MECHANISM is copied from the now-superseded ``splitter.py`` (the ``flush()``
segment-buffer pattern, the ``_DOUBLE_SPLITS``/``_SINGLE_SPLITS`` operator sets)
and ``decompose.py`` (the frozen result + ``abstain_reason`` idiom, the 64 KB
over-length guard, the ``in_single``-BEFORE-backslash ordering = the CR-01 fix,
the non-``$`` structural triggers).

SAFE-EXPANSION ALLOWLIST (TOK-02, the single gate for all ``$``-forms): every
``$``-bearing expansion — in BOTH unquoted and double-quoted context (bash does
NOT disable substitution inside double quotes) — is gated by ``_scan_dollar`` /
``_brace_body_allowed``. Allow BY FORM only: ``$name``, ``${name}``, and the
default-value family ``${name:-word}`` / ``:=`` / ``:+`` / ``:?`` (``word``
recursively re-scanned through ``tokenize()``). Every other ``${...}`` family
abstains WHOLESALE by its discriminator char (``@`` transform, ``[`` subscript,
``:`` not + ``-=+?`` offset/substring, ``#``/``!``/``%``/``/`` forms), as do
``$(`` cmdsub, ``${ ``/``${|`` funsub, backtick cmdsub, ``$((`` arithmetic, and
any novel ``${X`` opener (FAILS CLOSED). This is an allowlist, not an operator
denylist — no enumeration of which operators are dangerous; non-allowlisted
families simply are not on it. This closes the brace-BODY value-re-evaluation
class (CR-bodyeval: ``${x@P}``/``${s:i}``/``${arr[i]}``) by FORM.

Abstain contract (D-15/D-18): ``abstain_reason is not None`` means abstain. Two
abstain mechanisms — the structural triggers (``<<``/``<(``/``>(``) set-and-
return (empty segments); the allowlist abstains are COMPLETE-THEN-FLAG via a
``pending_abstain`` applied at the final return, so ``segments`` stays fully
populated (e.g. ``$((1 << 2))`` keeps its segment intact AND abstains jointly).
An end-of-scan open-quote check abstains on an unterminated quote (A3). The
top-level ``segments: list[str]`` field mirrors ``Decomposition.segments``
exactly so the entrypoint/harness swap is attribute-compatible and ``fold``
(which takes ``list[str]``) is never touched. The richer ``tokens`` structure is
consumed by the reader in a later plan.

The function is PURE — all scan state is local, no module-level mutable state —
so the SAME triggers fire on an arbitrary substring (D-19): a remote
``cat <(curl evil)`` is exactly as dangerous as a local one. The recursive
default-word re-scan (``tokenize(word)`` inside ``_brace_body_allowed``) is the
in-phase D-19 re-entrancy proof: ``${x:-$(id)}`` re-gates the inner ``$(``.

Arithmetic note (Pitfall 4): ``$((`` ... ``))`` is consumed verbatim as ONE
opaque word token by paren depth inside ``_scan_dollar`` so the inner left-shift
/ embedded whitespace cannot fragment the segment, THEN abstains (arithmetic is
not a provably-read-only form). No-fragmentation (TOK-01) and ``!= allow``
(TOK-02) hold jointly via complete-then-flag.
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


#: Characters that may appear in a parameter/variable NAME after ``$`` or ``${``.
_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)
#: The default-value family discriminator: a ``:`` immediately followed by one of
#: these is the ``${name:-word}`` / ``:=`` / ``:+`` / ``:?`` family (the only
#: ``${...}`` operator family on the allowlist). Special single-char params
#: (``$$``/``$?``/``$@``..) are deliberately NOT on the minimal allowlist — they
#: fail closed (D4-05 start-simple); a token-based recognizer phase recovers them.
_DEFAULT_OPS = frozenset("-=+?")


def _scan_dollar(s: str, i: int) -> tuple[int, bool]:
    """Scan one ``$``-expansion starting at ``s[i] == '$'``.

    Returns ``(end_index, allowed)`` where ``end_index`` is the index just past
    the expansion and ``allowed`` is ``True`` only for a provably-read-only form
    on the safe-expansion allowlist:

      * ``$name``                       -> allow (BY FORM)
      * ``${name}``                     -> allow (BY FORM)
      * ``${name:-word}`` / ``:=`` / ``:+`` / ``:?`` (default family) ->
        allow IFF ``word`` recursively re-scans clean (``tokenize(word)``).

    Everything else ABSTAINS WHOLESALE by its discriminator char — with NO
    operator enumeration and NO inspection of whether an operand is literal or
    hostile:

      * ``$((`` arithmetic                       -> abstain (not read-only)
      * ``$(`` cmdsub / ``${ `` / ``${|`` funsub -> abstain (command exec)
      * ``${name@op}``  (``@`` after name)        -> abstain (transform family)
      * ``${name[..]}`` (``[`` after name)        -> abstain (subscript family)
      * ``${name:X..}`` (``:`` not + ``-=+?``)    -> abstain (offset/substring)
      * ``${#..}`` ``${!..}`` ``${..#}`` etc.     -> abstain (not on allowlist)
      * novel ``${X`` opener / bare ``$``         -> abstain (fails CLOSED)

    The end index is always advanced past the whole construct so the caller can
    continue the scan; ``allowed=False`` is the abstain signal (complete-then-
    flag at the caller's final return — never a set-and-return here).
    """
    n = len(s)
    # i points at '$'. Look at the next char.
    if i + 1 >= n:
        # bare trailing '$' — not a recognized expansion, fails closed.
        return i + 1, False

    nxt = s[i + 1]

    # --- $((  arithmetic : NOT a provably-read-only form -> abstain ----------
    if nxt == "(" and i + 2 < n and s[i + 2] == "(":
        # Consume the opaque $(( ... )) unit by paren depth so the segment stays
        # intact (Plan-01 no-fragmentation), then signal abstain.
        depth = 2
        j = i + 3
        while j < n and depth > 0:
            if s[j] == "(":
                depth += 1
            elif s[j] == ")":
                depth -= 1
            j += 1
        return j, False

    # --- $( cmdsub : command execution -> abstain ---------------------------
    if nxt == "(":
        # Consume a best-effort balanced $( ... ); abstain regardless.
        depth = 1
        j = i + 2
        while j < n and depth > 0:
            if s[j] == "(":
                depth += 1
            elif s[j] == ")":
                depth -= 1
            j += 1
        return j, False

    # --- ${...} brace expansion ---------------------------------------------
    if nxt == "{":
        # Find the matching close brace by brace depth so a nested ${...} in a
        # default word is bounded correctly (e.g. ${x:-${y}}).
        depth = 1
        j = i + 2
        while j < n and depth > 0:
            if s[j] == "{":
                depth += 1
            elif s[j] == "}":
                depth -= 1
            if depth == 0:
                break
            j += 1
        if depth != 0:
            # Unbalanced ${ ... — fails closed.
            return n, False
        body = s[i + 2 : j]  # between { and }
        end = j + 1  # past the closing }
        return end, _brace_body_allowed(body)

    # --- $name  bare variable / parameter expansion -------------------------
    if nxt in _NAME_CHARS:
        j = i + 1
        while j < n and s[j] in _NAME_CHARS:
            j += 1
        return j, True

    # Any other char after $ (``$$``, ``$?``, ``$ ``, ``$(``-already-handled,
    # novel openers) is NOT on the minimal allowlist -> fails closed.
    return i + 1, False


def _brace_body_allowed(body: str) -> bool:
    """Decide allow/abstain for the BODY of a ``${...}`` (between the braces).

    Allow BY FORM only: a plain ``name`` (``${name}``) or the default-value
    family ``${name:-word}`` / ``:=`` / ``:+`` / ``:?`` where ``word``
    recursively re-scans clean through ``tokenize()``. Every other family
    abstains WHOLESALE by its discriminator char (``@`` transform, ``[``
    subscript, ``:`` not + ``-=+?`` offset/substring, and any ``#``/``!``/``%``/
    ``/`` length/indirect/strip/replace form, plus the funsub openers ``  ``/``|``
    that begin the body). No operator enumeration; fails CLOSED on novelty.
    """
    if not body:
        return False  # ${} is not a legitimate read form.

    first = body[0]

    # funsub: a body that opens with whitespace (``${ cmd; }``) or ``|``
    # (``${| cmd; }``) is bash-5.3 command-substitution funsub -> abstain.
    if first.isspace() or first == "|":
        return False

    # The name must start with a NAME char; anything else (``#`` length, ``!``
    # indirect, etc.) is not on the minimal allowlist -> abstain wholesale.
    if first not in _NAME_CHARS:
        return False

    k = 0
    ln = len(body)
    while k < ln and body[k] in _NAME_CHARS:
        k += 1

    if k == ln:
        return True  # bare ${name}

    disc = body[k]  # the discriminator char immediately after the name

    # Default-value family: ``:`` followed by one of ``-=+?`` -> recurse on word.
    if disc == ":" and k + 1 < ln and body[k + 1] in _DEFAULT_OPS:
        word = body[k + 2 :]
        return tokenize(word).abstain_reason is None

    # Every other discriminator abstains WHOLESALE (no operator enumeration):
    #   ``:`` not + ``-=+?`` -> offset/substring family (``${s:i}``)
    #   ``[``                -> subscript family (``${arr[i]}``)
    #   ``@``                -> transform family (``${x@P}``)
    #   ``#`` ``%`` ``/`` …  -> strip/replace forms (not on the allowlist)
    return False


def tokenize(command: str) -> TokenizeResult:
    """Segment + tokenize ``command``, surfacing abstain via the allowlist.

    Over-length input, process-substitution / heredoc / here-string constructs,
    unterminated quotes, and any ``$``-form NOT on the safe-expansion allowlist
    (cmdsub/funsub/backtick/arithmetic/non-default ``${...}`` families) abstain
    (``abstain_reason`` set). ``$((...))`` arithmetic is held as one opaque word
    token (no fragmentation) AND abstains (complete-then-flag). Otherwise the
    stripped segments are returned with ``abstain_reason=None``.

    Pure / re-entrant: all scan state is local, so the same triggers fire on any
    substring (D-19), including the recursive default-word re-scan.
    """
    if len(command) > _MAX_LEN:
        return _abstain(f"over-length input ({len(command)} > {_MAX_LEN})")

    i = 0
    n = len(command)
    in_single = in_double = in_backtick = False
    pending_abstain: str | None = None  # complete-then-flag allowlist abstain

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
            # A `$`-expansion inside double quotes is STILL live (bash does not
            # disable substitution in double quotes). Gate it by the same
            # safe-expansion allowlist as the unquoted path — this is what makes
            # the brace-BODY classes (`${x@P}`/`${s:i}`/`${arr[i]}`) visible.
            if c == "$":
                end, allowed = _scan_dollar(command, i)
                chunk = command[i:end]
                cur.append(chunk)
                word.append(chunk)
                if not allowed and pending_abstain is None:
                    pending_abstain = "non-read-only expansion in allowlist"
                i = end
                continue
            if c == "`":
                # Backtick command substitution is STILL live inside double
                # quotes (bash does not disable it) and is command execution ->
                # abstain (no legitimate read form uses it). Complete-then-flag.
                if pending_abstain is None:
                    pending_abstain = "backtick command substitution"
                cur.append(c)
                word.append(c)
                in_backtick = True
                i += 1
                continue
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
            # Unquoted backtick command substitution -> abstain (command
            # execution, not a provably-read-only form). Complete-then-flag.
            if pending_abstain is None:
                pending_abstain = "backtick command substitution"
            in_backtick = True
            cur.append(c)
            word.append(c)
            i += 1
            continue

        # --- unquoted `$`-expansion : safe-expansion allowlist --------------
        # Handle EVERY unquoted $-form through the same allowlist scanner as the
        # double-quoted path. `$((` arithmetic stays one opaque unit (consumed by
        # paren depth inside _scan_dollar) so the inner shift / whitespace cannot
        # fragment the segment (Plan-01 no-fragmentation), and abstains because
        # arithmetic is not a provably-read-only form (complete-then-flag). `$(`
        # cmdsub and non-allowlisted `${...}` families likewise abstain.
        if c == "$":
            end, allowed = _scan_dollar(command, i)
            chunk = command[i:end]
            cur.append(chunk)
            word.append(chunk)
            if not allowed and pending_abstain is None:
                pending_abstain = "non-read-only expansion in allowlist"
            i = end
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

    # End-of-scan unbalanced-quote guard (Assumption A3): an unterminated quote
    # is a bash syntax error; the tokenizer cannot close the quote state, so it
    # cannot prove the command read-only -> abstain (strictly conservative, loses
    # no legitimate coverage). Complete-then-flag: segments are populated above.
    if in_single or in_double or in_backtick:
        if pending_abstain is None:
            pending_abstain = "unterminated quote"

    return TokenizeResult(
        segments=segments, tokens=all_tokens, abstain_reason=pending_abstain
    )

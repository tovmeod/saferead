"""The read-only ``sed`` recognizer (REC-05, D-01/D-02).

``sed`` is treated as a real mini-language, NOT a "reject ``-i`` only" command.
``-i`` is a cardinal red herring: sed writes files (``w``/``W``, the ``s///w``
flag) and executes commands (``e``, the ``s///e`` flag) entirely independent of
``-i`` (PITFALLS C1/C2; D-01). So this recognizer allows a ``sed`` invocation
ONLY when BOTH hold:

1. Every OPTION is on an EXACT-MATCH safe-option allowlist (Pitfall 2, the C1
   closure). EXACT match — never a prefix/substring/word-boundary test — so
   ``-i``, ``-ie``, ``-i.bak``, ``--in-place[=suffix]`` and the getopt bundle
   ``-ni`` all fail to match and abstain BY CONSTRUCTION. ``-f``/``--file=``
   (an unseeable script body) likewise are not on the allowlist -> abstain.
2. Every SCRIPT classifies as provably read-only by a classify-only mini-parser
   (``_script_is_read_only``). The parser admits ONLY a read-only command
   allowlist and a positive ``s``/``y`` flag allowlist; it abstains (returns
   ``False``) on ANY ambiguity — an unknown command letter, an unresolvable
   delimiter, a write/exec/read command (``w``/``W``/``e``/``r``/``R``/``F``),
   the ``s///w``/``s///e`` flags, the parse-hostile a/i/c
   backslash-continuation forms, or running off the end mid-command (D-02). A
   verdict is
   emitted ONLY on full classification — a misparse defaults to abstain, the
   cardinal-safe direction.

Tokenizer abstain is the recognizer's abstain (D-06). A trailing redirect is
routed through the shared ``redirect_tail_is_safe`` helper (the single ``/tmp``
+ discard policy, D-05).
"""

from __future__ import annotations

import os.path

from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from ._pathscope import resolve_lexical, under_any_root
from ._quoting import strip_one_quote_layer
from .redirects import redirect_tail_is_safe

#: EXACT-MATCH safe option tokens (Pitfall 2). A leading ``-``-token is admitted
#: ONLY when it is literally one of these. ``-i``/``-ie``/``-i.bak``/
#: ``--in-place``/``--in-place=.bak``/the ``-ni`` bundle/``-f``/``--file=`` all
#: fail this membership test and abstain BY CONSTRUCTION — no enumeration of the
#: dangerous forms, no substring reasoning.
_SAFE_OPTIONS = frozenset(
    {
        "-n",
        "--quiet",
        "--silent",
        "-E",
        "-r",
        "--regexp-extended",
        "-s",
        "--separate",
        "-z",
        "--null-data",
        "-u",
        "--unbuffered",
        "--posix",
        "--sandbox",
    }
)

#: Options that consume the NEXT token as a value (split form). ``-l N`` sets the
#: ``l`` command wrap length (read-only). The glued ``--line-length=N`` form is
#: self-contained (handled via exact-name ``partition('=')``).
_VALUE_OPTIONS = frozenset({"-l", "--line-length"})

#: Options that introduce a SCRIPT to classify (next token, split form).
_SCRIPT_OPTIONS = frozenset({"-e", "--expression"})

#: Read-only single-letter script commands that take NO field/file argument.
#: Every one writes (at most) to stdout or manipulates the pattern/hold space;
#: none names a file or executes a command.
_READ_ONLY_COMMANDS = frozenset(
    {
        "p",
        "P",
        "d",
        "D",
        "n",
        "N",
        "g",
        "G",
        "h",
        "H",
        "x",
        "l",
        "=",
        "z",
    }
)

#: Commands that take an optional trailing NUMERIC argument (exit code / line
#: wrap width). The number, if present, is consumed up to the next separator.
_OPTIONAL_NUMBER_COMMANDS = frozenset({"q", "Q"})

#: Branch / label commands. Their argument is a LABEL that runs to the next
#: command separator (whitespace / ``;`` / newline / ``}``). CRITICAL: the label
#: MUST stop at a separator, never swallow a following command — otherwise a
#: ``b end; w out`` would hide the ``w`` write behind the label (POSIX runs a
#: label to end-of-line, GNU stops at ``;``; stopping at any separator is the
#: cardinal-safe intersection).
_LABEL_COMMANDS = frozenset({"b", "t", "T", ":"})

#: Positive ``s``-substitution flag allowlist. ``w`` (write FILE), ``W``, and
#: ``e`` (execute) are intentionally ABSENT and abstain; any char that is neither
#: an allowed flag nor a separator also abstains (closes unknown/future flags).
_S_FLAGS = frozenset({"g", "p", "i", "I", "m", "M"})

#: Characters that separate sed commands (and terminate a label).
_SEPARATORS = frozenset({" ", "\t", "\n", ";"})


def _scan_field(script: str, start: int, delim: str) -> int | None:
    """Return the index just past the closing ``delim`` of a delimiter field.

    Scans from ``start`` (the char AFTER the opening delimiter) to the next
    UNESCAPED ``delim``. A ``\\<delim>`` (and any ``\\x``) is a literal pair and
    skipped. Returns ``None`` if the field runs off the end with no closing
    delimiter (the cardinal-safe abstain — an unbalanced field).
    """
    i = start
    n = len(script)
    while i < n:
        c = script[i]
        if c == "\\":
            # An escape pair (``\<delim>``, ``\n``, ...) — skip both chars. A
            # trailing backslash with nothing after is malformed.
            if i + 1 >= n:
                return None
            i += 2
            continue
        if c == delim:
            return i + 1
        i += 1
    return None  # no closing delimiter -> unbalanced -> abstain


def _classify_substitution(script: str, i: int) -> int | None:
    """Classify an ``s`` substitution starting at the delimiter (index after ``s``).

    Resolves the ACTUAL delimiter (the char at ``i``), reads the THREE
    delimiter-separated fields honoring ``\\<delim>`` escapes, then scans the
    flag run against the positive ``_S_FLAGS`` allowlist. Returns the index just
    past the command on full clean classification, or ``None`` (abstain) on an
    unbalanced field, the ``w``/``W``/``e`` hidden-write/exec flags, or any
    unknown flag char (D-02).
    """
    n = len(script)
    if i >= n:
        return None
    delim = script[i]
    if delim == "\\" or delim in _SEPARATORS:
        return None  # a backslash or whitespace delimiter is ambiguous -> abstain
    # Field 1 (regex), field 2 (replacement): each terminated by ``delim``.
    after_regex = _scan_field(script, i + 1, delim)
    if after_regex is None:
        return None
    after_repl = _scan_field(script, after_regex, delim)
    if after_repl is None:
        return None
    # Flag run: scan until a separator. Every char must be an allowed flag or a
    # digit (Nth-occurrence). ``w``/``W``/``e`` and any unknown char abstain.
    j = after_repl
    while j < n:
        c = script[j]
        if c in _SEPARATORS:
            break
        if c == "}":
            break
        if c.isdigit() or c in _S_FLAGS:
            j += 1
            continue
        return None  # ``w``/``W``/``e`` or an unknown flag -> abstain
    return j


def _classify_transliterate(script: str, i: int) -> int | None:
    """Classify a ``y`` transliteration starting at the delimiter (index after ``y``).

    Like ``s`` but with NO flag run (``y`` takes no flags). Three
    delimiter-separated fields, then the command ends. Returns the index just
    past the third field, or ``None`` on an unbalanced field.
    """
    n = len(script)
    if i >= n:
        return None
    delim = script[i]
    if delim == "\\" or delim in _SEPARATORS:
        return None
    after_src = _scan_field(script, i + 1, delim)
    if after_src is None:
        return None
    after_dst = _scan_field(script, after_src, delim)
    if after_dst is None:
        return None
    return after_dst


def _consume_address(script: str, i: int) -> int | None:
    """Consume an optional leading address / range before a command.

    Handles ``/re/`` and ``\\cREc`` custom-delimiter regex addresses (the
    delimiter is the char after ``\\``), a line number, ``$``, ``0~step``,
    ``N,M``, ``addr,+N``, ``addr,~N``, and a leading ``!`` negation (possibly
    repeated / spaced). Returns the index of the command letter. Returns ``None``
    when a regex-address delimiter cannot be cleanly resolved (D-02 abstain).

    The scan is permissive about the NON-regex address syntax (it skips the run
    of address chars ``0-9 , + ~ $`` and whitespace) — that can only ever
    over-consume harmless address bytes, never a command letter, because the
    command-letter classification that follows is itself a strict allowlist.
    """
    n = len(script)
    while i < n:
        c = script[i]
        if c == "/":
            # ``/re/`` regex address — delimiter is ``/``.
            after = _scan_field(script, i + 1, "/")
            if after is None:
                return None
            i = after
            continue
        if c == "\\":
            # ``\cREc`` custom-delimiter regex address: next char is the delim.
            if i + 1 >= n:
                return None
            d = script[i + 1]
            after = _scan_field(script, i + 2, d)
            if after is None:
                return None
            i = after
            continue
        if c in "0123456789,+~$ \t":
            i += 1
            continue
        if c == "!":
            i += 1
            continue
        break
    return i


def _script_is_read_only(script: str) -> bool:
    """True iff EVERY command in ``script`` is provably read-only (D-02).

    Classify-only: scan left to right, command by command (NOT pre-split on
    ``;`` — a ``;`` inside a regex/replacement is data). For each command consume
    an optional leading address, read the command letter, and classify it. A
    verdict of ``True`` is returned ONLY when the ENTIRE script classified with
    no ambiguity. Any unknown command letter, unresolvable delimiter, write/exec/
    read command, or running off the end mid-command returns ``False`` — the
    cardinal-safe abstain. Never skip past something that was not parsed.
    """
    i = 0
    n = len(script)
    while i < n:
        c = script[i]
        # Skip separators and command-group braces between commands.
        if c in _SEPARATORS or c in "{}":
            i += 1
            continue
        if c == "#":
            # Comment to end of line.
            nl = script.find("\n", i)
            if nl == -1:
                return True  # comment runs to EOF — whole rest is a comment
            i = nl + 1
            continue

        # Optional leading address / range, then the command letter.
        after_addr = _consume_address(script, i)
        if after_addr is None:
            return False
        i = after_addr
        if i >= n:
            # An address with no command (e.g. a trailing ``/re/``). Ambiguous.
            return False

        cmd = script[i]
        i += 1

        if cmd == "s":
            after = _classify_substitution(script, i)
            if after is None:
                return False
            i = after
            continue
        if cmd == "y":
            after = _classify_transliterate(script, i)
            if after is None:
                return False
            i = after
            continue
        if cmd in _LABEL_COMMANDS:
            # The label may be whitespace-separated from the command (``b end``)
            # or glued (``:loop``). Skip ANY leading spaces/tabs (but NOT ``;``
            # or newline — those END the command with an empty label), then
            # consume the label as a run that STOPS at a separator or ``}``. The
            # label MUST NOT swallow a following command (else ``b end; w out``
            # or ``b end w out`` would hide the ``w`` write). The label itself
            # never writes.
            while i < n and script[i] in " \t":
                i += 1
            while i < n and script[i] not in _SEPARATORS and script[i] != "}":
                i += 1
            continue
        if cmd in _OPTIONAL_NUMBER_COMMANDS:
            # Optional trailing exit code: consume digits up to a separator.
            while i < n and script[i].isdigit():
                i += 1
            continue
        if cmd in _READ_ONLY_COMMANDS:
            # ``l`` accepts an optional numeric wrap width; consume trailing
            # digits. The others take no argument. Either way the command ends
            # at the next separator, which the outer loop handles.
            while i < n and script[i].isdigit():
                i += 1
            continue

        # ANY other command letter — ``w``/``W`` (write FILE), ``r``/``R`` (read
        # arbitrary FILE), ``e`` (execute), ``F`` (per D-01 — conservative),
        # ``a``/``i``/``c`` (parse-hostile ``\``-continuation, OMITTED per
        # D-02/A2), and any unknown/GNU-extension letter — is NOT on the
        # allowlist and abstains BY CONSTRUCTION (D-02). There is intentionally
        # no denylist enumeration here.
        return False

    return True


def recognize_sed(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a read-only ``sed``, else ``None``.

    Allows when every option is on the EXACT-MATCH safe-option allowlist and
    every script classifies as provably read-only; abstains on any in-place
    form, ``-f`` scriptfile, write/exec/read script command, the ``s///w``/
    ``s///e`` flags, any unparseable script, and any non-safe redirect target.
    """
    result = tokenize(segment)
    # The tokenizer holds ALL expansion safety; its abstain is the recognizer's.
    if result.abstain_reason is not None:
        return None
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens or tokens[0] != "sed":
        return None

    args = tokens[1:]
    scripts: list[str] = []
    saw_expression = False
    operands: list[str] = []

    i = 0
    n = len(args)
    while i < n:
        tok = args[i]

        if tok.startswith("-") and tok not in ("-", "--"):
            # A long option may carry a glued ``=value`` — split on the FIRST
            # ``=`` and EXACT-match the option name (no prefix matching: the
            # name is tested for set membership, never a leading substring).
            name, sep, value = tok.partition("=")
            if sep == "=":
                if name in _SCRIPT_OPTIONS:
                    scripts.append(value)
                    saw_expression = True
                    i += 1
                    continue
                if name in _VALUE_OPTIONS:
                    # e.g. ``--line-length=70`` — self-contained, read-only.
                    i += 1
                    continue
                # ``--in-place=.bak``/``--file=script`` etc. — not on any
                # allowlist -> abstain by construction.
                return None
            # No ``=``: an EXACT-match option token.
            if tok in _SAFE_OPTIONS:
                i += 1
                continue
            if tok in _SCRIPT_OPTIONS:
                if i + 1 >= n:
                    return None  # ``-e`` with no script
                scripts.append(args[i + 1])
                saw_expression = True
                i += 2
                continue
            if tok in _VALUE_OPTIONS:
                if i + 1 >= n:
                    return None  # ``-l`` with no value
                i += 2
                continue
            # ANY other ``-``-token — ``-i``/``-ie``/``-i.bak``/``-ni``/``-f``/
            # ``--in-place``/``--file`` — fails exact-match and abstains BY
            # CONSTRUCTION (the C1 word-boundary closure). No enumeration.
            return None

        # A non-option token: the first one is the script (unless a ``-e`` was
        # given, in which case every positional is a file operand).
        operands.append(tok)
        i += 1

    # Determine the script(s) to classify. With ``-e``/``--expression`` the
    # positionals are all FILE operands (Pitfall: do NOT parse a filename as a
    # script). Without one, the FIRST positional is the script.
    if not saw_expression:
        if not operands:
            return None  # no script at all
        scripts.append(operands[0])
        file_operands = operands[1:]
    else:
        file_operands = operands

    # A trailing redirect among the file operands must pass the shared policy.
    if not redirect_tail_is_safe(file_operands):
        return None

    # REC-08: gate each file_operand via _pathscope (D-05/D-06).
    # The script is already excluded from file_operands (by the -e/positional
    # split above), so it is NEVER gated here.  A no-file sed (stdin) has an
    # empty file_operands list — the loop is a no-op and the read is unaffected
    # (D-06: a no-path read is unaffected by read-roots).
    roots = (
        ctx.config.ssh_allowed_roots
        if ctx.read_scope == "ssh"
        else ctx.config.local_allowed_roots
    )
    for operand in file_operands:
        # Skip redirect/control tokens — these were accepted by redirect_tail_is_safe
        # and are not file paths (they bear ">" or "&").
        if ">" in operand or "&" in operand:
            continue
        # SC#3: ssh-relative guard — abstain BEFORE resolving.
        if ctx.read_scope == "ssh" and not os.path.isabs(operand):
            return None
        resolved = resolve_lexical(operand, ctx.cwd)
        if resolved is None or not under_any_root(resolved, roots):
            return None

    # EVERY script must classify clean (strip one quote layer first — the
    # tokenizer keeps a quoted script with its quotes).
    for raw in scripts:
        if not _script_is_read_only(strip_one_quote_layer(raw)):
            return None

    return Verdict("allow", "read-only sed", "sed")

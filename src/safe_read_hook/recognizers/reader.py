"""The one minimal happy-path read-only command recognizer (D-11/D-12).

This recognizer is deliberately thin. The zero-false-allow promise does NOT
come from breadth here — it comes from the engine's abstain-veto fold (D-13):
one unrecognized segment vetoes a whole compound to abstain. So the reader only
needs to claim a narrow, unambiguously read-only command set, and abstain
(return ``None``) on everything else.

Command set: ``echo``/``printf``, a group of file-inspection readers, and a
group of read-only text filters. Write-capable commands are intentionally NOT
claimed; they belong to later phases.

Token-consuming (04-03): the reader re-invokes ``tokenize()`` on its own segment
and classifies the resulting word tokens — it no longer carries any ``$``-form
regex. ALL ``$``/backtick/arithmetic/brace-body expansion safety is held by the
tokenizer's safe-expansion ALLOWLIST (the single place expansion state is
tracked — criterion 1): if ``tokenize`` abstains, the reader abstains. The old
per-dollar quoted-argument regex is GONE; the brace-BODY value-re-evaluation
class (``${x@P}``/``${s:i}``/``${arr[i]}``) is now closed BY FORM upstream.

Redirect / control fence (closes backlog 999.1 #7): the argument tail accepts
ordinary word tokens and ONLY discard redirects (``>/dev/null``, ``2>&1`` and
friends), which never touch a user file. A token still bearing a ``>`` redirect
to a real file, or a ``&`` background/control operator (the tokenizer keeps both
glued into a word token), makes the whole segment unrecognized, so the
recognizer abstains rather than approve a write or a background job. Real
redirect handling is a later phase.

Dispatch seam (TOK-03): an embedded-sublanguage command shape (``python``/
``python3 -c "<code>"``) extracts the quoted source argument and dispatches it
to ``ANALYZERS["python"](source)``, returning the analyzer's Verdict (or
abstaining when it returns ``None``). The skeleton analyzer returns ``None``, so
a ``python -c`` shape abstains today — the seam exists to prove dispatch fires;
the full Python recognizer is Phase 12 (D4-10). This recognizes the SHAPE only,
NOT a general python command.
"""

from __future__ import annotations

import re

from ..analyzers import ANALYZERS
from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from .redirects import redirect_tail_is_safe

# echo / printf.
_CMD_ECHO = frozenset({"echo", "printf"})

# File-inspection readers — all read-only in bare form.
#
# CR-01 (04-REVIEW): ``less``/``more``/``bat`` are DELIBERATELY absent. They are
# not provably read-only: ``less FILE`` runs the ``LESSOPEN``/``lesspipe`` input
# preprocessor (external decoders) on the target file, ``bat`` pages through
# ``less`` and inherits the same exposure, and ``more`` can shell-escape via
# ``!``/``v``. ``cat``/``head``/``tail``/``nl`` cover the "show a file" use case
# without spawning a preprocessor.
_CMD_FILE_READERS = frozenset(
    {
        "cat",
        "ls",
        "file",
        "stat",
        "readlink",
        "realpath",
        "basename",
        "dirname",
        "pwd",
        "which",
        "whereis",
        "type",
        "du",
        "df",
    }
)

# Read-only text filters (the seed filter group, with the two write-capable
# members removed — those are deferred to a later phase).
_CMD_FILTERS = frozenset(
    {
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ag",
        "head",
        "tail",
        "wc",
        "uniq",
        "cut",
        "tr",
        "jq",
        "column",
        "nl",
        "rev",
        "tac",
        "base64",
        "xxd",
        "od",
        "strings",
        "diff",
        "comm",
        "paste",
        "join",
        "fold",
        "expand",
        "unexpand",
        "sort",
    }
)

#: All command names the reader claims as read-only (by leading token text).
_READ_ONLY_CMDS = _CMD_ECHO | _CMD_FILE_READERS | _CMD_FILTERS

#: Embedded-sublanguage launchers recognized as a ``-c "<code>"`` SHAPE only.
_SUBLANG_CMDS = {"python": "python", "python3": "python"}

#: Per-command read-only OPTION-FLAG allowlist (CR-02, 04-REVIEW). Allowlist BY
#: FORM: a flag token (starts with ``-``) is permitted ONLY when it appears in
#: the leading command's entry here; any other flag -> abstain. A command with
#: NO entry permits BARE FORM ONLY (every ``-flag`` abstains). This enforces the
#: "read-only in bare form" contract the docstrings claim while preserving
#: common-flag coverage. Membership is CONSERVATIVE — a flag is included only
#: when its read-only status is certain for THAT command; when unsure, OMIT
#: (coverage loss is acceptable, a false-allow is not).
#:
#: ``file`` is DELIBERATELY absent: ``file -C -m PATH`` compiles and WRITES
#: ``PATH.mgc`` with no ``>`` redirect (the unique direct-write vector in the
#: allowlist). ``file``'s safe surface here is path-only, so every ``file -<f>``
#: abstains; bare ``file PATH`` stays allow.
_READ_ONLY_FLAGS: dict[str, frozenset[str]] = {
    "ls": frozenset(
        {"-l", "-a", "-la", "-al", "-lh", "-h", "-R", "-t", "-r", "-S", "-1", "--color"}
    ),
    "grep": frozenset(
        {
            "-i",
            "-n",
            "-r",
            "-R",
            "-v",
            "-c",
            "-l",
            "-L",
            "-E",
            "-F",
            "-w",
            "-x",
            "-H",
            "-h",
            "-o",
            "-A",
            "-B",
            "-C",
            "--color",
        }
    ),
    "egrep": frozenset(
        {
            "-i",
            "-n",
            "-r",
            "-R",
            "-v",
            "-c",
            "-l",
            "-L",
            "-w",
            "-x",
            "-H",
            "-h",
            "-o",
            "-A",
            "-B",
            "-C",
            "--color",
        }
    ),
    "fgrep": frozenset(
        {
            "-i",
            "-n",
            "-r",
            "-R",
            "-v",
            "-c",
            "-l",
            "-L",
            "-w",
            "-x",
            "-H",
            "-h",
            "-o",
            "-A",
            "-B",
            "-C",
            "--color",
        }
    ),
    "rg": frozenset(
        {
            "-i",
            "-n",
            "-r",
            "-R",
            "-v",
            "-c",
            "-l",
            "-L",
            "-E",
            "-F",
            "-w",
            "-x",
            "-H",
            "-h",
            "-o",
            "-A",
            "-B",
            "-C",
            "--color",
        }
    ),
    "head": frozenset({"-n", "-c"}),
    # NOTE: tail's read-only flags are -n/-c only — NOT -f/-F (follow blocks).
    "tail": frozenset({"-n", "-c"}),
    "wc": frozenset({"-l", "-w", "-c", "-m", "-L"}),
    "cut": frozenset({"-d", "-f", "-c"}),  # value-bearing; matched by 2-char head
    "du": frozenset({"-s", "-h", "-sh", "-a", "-c"}),
    "df": frozenset({"-h", "-k", "-T"}),
    # sort (D-04/D-05): ADMIT only flags proven read-only in GNU *and* BSD/uutils.
    # OMIT every write/exec form by allowlist-by-omission: ``-o``/``--output``
    # (W2 output file), ``-T``/``--temporary-directory`` (D-05 — directs temp
    # writes), ``--compress-program`` (W6 exec), ``--random-source``,
    # ``--files0-from``, ``-m``/``--merge``. ``-k``/``-t``/``-S`` are
    # value-bearing (see ``_VALUE_BEARING_FLAGS``) — they appear here so the
    # separate-token form (``sort -S 2M``) exact-matches, AND there so the glued
    # form (``-S2M``) head-matches. They do NOT go in ``_VALUE_PREFIX_CMDS``
    # (that re-opens the LV-3 ``-ro`` smuggle — D-11).
    "sort": frozenset(
        {
            "-n",
            "-r",
            "-u",
            "-f",
            "-b",
            "-h",
            "-g",
            "-M",
            "-V",
            "-s",
            "-z",
            "-c",
            "-C",
            "-k",
            "-t",
            "-S",
            "--numeric-sort",
            "--reverse",
            "--unique",
            "--ignore-case",
            "--ignore-leading-blanks",
            "--human-numeric-sort",
            "--general-numeric-sort",
            "--month-sort",
            "--version-sort",
            "--stable",
            "--zero-terminated",
            "--check",
            "--check-silent",
            "--key",
            "--field-separator",
            "--buffer-size",
        }
    ),
}

#: Commands whose short flags carry a glued value (e.g. ``cut -d:`` / ``-f1``).
#: For these, a flag token is matched by its 2-char head (``tok[:2]``) so the
#: value tail is accepted. Restricted to ``cut`` (no write/exec flag shares the
#: ``-d``/``-f``/``-c`` prefix for ``cut``); do NOT extend without re-auditing.
#: ``sort`` is DELIBERATELY absent — the coarse ``tok[:2] in allowed`` path would
#: re-open the LV-3 ``-ro`` smuggle (``-r`` is on the allowlist, so ``-ro``
#: head-matches and writes ``OUT``). ``sort`` uses ``_VALUE_BEARING_FLAGS``
#: instead (D-11).
_VALUE_PREFIX_CMDS = frozenset({"cut"})

#: Per-command set of genuinely VALUE-BEARING short-flag heads — flags that
#: consume their ENTIRE remaining tail as a value, so nothing can hide after them
#: (``-k2``, ``-t:``, ``-S2M``). Only these heads may glued-prefix-match; any
#: other 2-char head on the allowlist (``-r``/``-n``/``-u``…) must NOT match a
#: longer glued token — a longer token starting there is a bundle and abstains
#: (closes W4/LV-3 — D-11). Separate from the coarse ``_VALUE_PREFIX_CMDS``.
_VALUE_BEARING_FLAGS: dict[str, frozenset[str]] = {
    "sort": frozenset({"-k", "-t", "-S"}),
}

#: head/tail accept the historic ``-NUM`` line-count form (``head -5 f``), which
#: is genuinely read-only.
_NUMERIC_FLAG_CMDS = frozenset({"head", "tail"})
_NUMERIC_FLAG = re.compile(r"-\d+")

#: Commands whose SECOND positional operand is an OUTPUT file (a write with no
#: flag): ``uniq [INPUT [OUTPUT]]``, ``xxd [infile [outfile]]``. The flag
#: allowlist cannot see this — the write is un-flagged. The W3 fence (D-10):
#: abstain when such a command has >= 2 bare (non-flag, non-discard-redirect)
#: operand tokens. Scoped to ``{uniq, xxd}`` ONLY — it MUST NOT be a blanket
#: operand-count rule, or it would break the inputs-only multi-operand reads
#: ``cat a b`` / ``diff a b`` / ``comm a b`` / ``paste a b`` / ``grep x f1 f2``
#: (Pitfall 3 — their operands are all INPUTS).
_OUTPUT_OPERAND_CMDS = frozenset({"uniq", "xxd"})


def _flag_is_read_only(cmd: str, tok: str) -> bool:
    """True iff option-flag ``tok`` is on ``cmd``'s read-only flag allowlist.

    A command with no ``_READ_ONLY_FLAGS`` entry permits NO flags (bare form
    only). head/tail also accept the historic ``-NUM`` form. ``cut``'s
    value-bearing short flags (``-d:``/``-f1``) match by their 2-char head.
    """
    if cmd in _NUMERIC_FLAG_CMDS and _NUMERIC_FLAG.fullmatch(tok):
        return True
    allowed = _READ_ONLY_FLAGS.get(cmd)
    if allowed is None:
        return False
    if tok in allowed:
        return True
    # Value-bearing short flag: accept the 2-char head (e.g. ``-d:`` -> ``-d``)
    # only when the command opted into coarse prefix matching (``cut``). Every
    # head on the allowlist may match — safe for ``cut`` because ``-d``/``-f``/
    # ``-c`` consume their whole tail.
    if cmd in _VALUE_PREFIX_CMDS and len(tok) > 2 and tok[:2] in allowed:
        return True
    # ``sort``-style value-bearing heads (``-k``/``-t``/``-S``): a glued token
    # head-matches ONLY when its 2-char head is a value-bearing head for ``cmd``
    # (these consume their whole tail). Any other glued bundle (``-ro``) falls
    # through to abstain — closes W4/LV-3 (D-11).
    value_heads = _VALUE_BEARING_FLAGS.get(cmd)
    if value_heads is not None and len(tok) > 2 and tok[:2] in value_heads:
        return True
    return False


def _tail_is_safe(cmd: str, arg_tokens: list[str]) -> bool:
    """True iff every trailing token is a safe arg, flag, or safe redirect.

    The redirect decision is delegated WHOLLY to the shared
    ``redirect_tail_is_safe`` helper (D-05): it owns the discard-redirect
    classification and the hardened ``/tmp`` scratch policy (glued AND split
    shapes), and its SAFETY FLOOR rejects any other token bearing ``>`` or
    ``&``. The reader calls it first and abstains if it returns ``False``; the
    helper is the single definition of the redirect policy reused by find/sed.

    CR-02 flag policy: a token that LOOKS like an option flag (starts with
    ``-``, excluding bare ``-``/``--``) -> abstain UNLESS it is on ``cmd``'s
    read-only flag allowlist (``_flag_is_read_only``). A bare value/path token
    is permitted. Commands with no allowlist entry permit bare form only.

    W3 positional-operand fence (D-10): for a command in
    ``_OUTPUT_OPERAND_CMDS`` (``uniq``/``xxd``), whose SECOND positional is an
    OUTPUT file, abstain when there are >= 2 bare operand tokens (a non-flag,
    non-redirect token; ``-`` stdin counts as an operand). This closes the
    un-flagged positional write LV-1/LV-2. Scoped to those commands only —
    inputs-only multi-operand reads stay allow.

    Over-abstains only on a *quoted* ``">"``/``"&"`` argument or an unlisted
    flag — a safe coverage loss (prompt the command), never a false-allow.
    """
    # Redirect policy is owned by the shared helper (D-05). Abstain on any
    # unsafe redirect/control token before the flag + operand classification.
    if not redirect_tail_is_safe(arg_tokens):
        return False
    operand_count = 0
    fence_operands = cmd in _OUTPUT_OPERAND_CMDS
    for tok in arg_tokens:
        # Redirect / control tokens were already cleared by the helper above;
        # skip them so the W3 operand count is unchanged from today.
        if ">" in tok or "&" in tok:
            continue
        if tok.startswith("-") and tok not in ("-", "--"):
            if not _flag_is_read_only(cmd, tok):
                return False
            continue
        # A bare operand (path, value, or ``-`` stdin). For output-operand
        # commands, a second bare operand is an un-flagged output write (W3).
        if fence_operands:
            operand_count += 1
            if operand_count >= 2:
                return False
    return True


def recognize_reader(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a known read-only command, else ``None``.

    Consumes tokenizer tokens (no ``$``-regex). Abstains (``None``) when the
    tokenizer abstains (any non-allowlisted expansion), on any unrecognized
    leading command, on a redirect to a real file or a background/control
    operator, and dispatches an embedded-sublanguage shape to ``ANALYZERS``.
    """
    result = tokenize(segment)
    # The tokenizer holds ALL expansion safety; its abstain is the reader's.
    if result.abstain_reason is not None:
        return None
    # A single recognized command only — a multi-segment input is the engine's
    # business (it folds each segment), and the reader is handed one segment.
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens:
        return None

    cmd, args = tokens[0], tokens[1:]

    # Dispatch seam (TOK-03): a ``python``/``python3 -c "<code>"`` SHAPE routes
    # the quoted source to the language analyzer.
    lang = _SUBLANG_CMDS.get(cmd)
    if lang is not None and len(args) == 2 and args[0] == "-c":
        source = _strip_one_quote_layer(args[1])
        return ANALYZERS[lang](source)

    if cmd not in _READ_ONLY_CMDS:
        return None

    if not _tail_is_safe(cmd, args):
        return None

    return Verdict("allow", "read-only command", "reader")


def _strip_one_quote_layer(token: str) -> str:
    """Strip a single surrounding matched single/double quote pair, if present.

    The tokenizer emits a quoted argument with its quotes intact (``"import
    os"``); the analyzer wants the source WITHOUT the shell quoting. Only a
    single outer layer is stripped (sufficient for the recognized shape); an
    unbalanced or unquoted token is returned unchanged.
    """
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "'\"":
        return token[1:-1]
    return token

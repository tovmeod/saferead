"""The single source of redirect-target classification policy (D-05).

This shared helper decides whether the trailing tokens of a command's argument
list are a SAFE redirect tail. It is consumed by ``reader.py`` today and by
``find.py`` / ``sed.py`` in later waves of Phase 7, so the hardened ``/tmp``
scratch policy (D-03) is defined EXACTLY ONCE and cannot drift.

Policy (D-03):

- A discard redirect that never writes a user file is safe: ``>/dev/null``,
  ``2>/dev/null``, ``2>&1``, ``&>/dev/null``, ``&>>/dev/null``, and a
  file-descriptor duplication ``>&N`` / ``M>&N`` (e.g. ``>&2``).
- A genuine single-component ``/tmp`` scratch target is safe: ``>/tmp/scratch``,
  ``>>/tmp/log``, ``2>/tmp/err`` (glued OR split ``> /tmp/scratch``). The target
  must match ``^/tmp/[A-Za-z0-9._-]+$`` (an ALLOWLIST charset) AND the single
  component must not be ``.`` or ``..`` — so a second ``/`` (``/tmp/sub/file``),
  a ``..`` traversal (``/tmp/../etc/passwd``), a bare ``>/tmp`` (no component),
  a glued second redirect (``>/tmp/a>b``), and any shell metacharacter are all
  rejected by construction.
- SAFETY FLOOR (cardinal): the discard and ``/tmp`` carve-outs are layered ON
  TOP of the old reader's blanket ``>``/``&`` veto, NOT a replacement for it.
  After the carve-outs, ANY token still containing ``>`` or ``&`` returns
  ``False``. A token is pass-through safe ONLY when it contains NEITHER ``>``
  NOR ``&``. This makes the helper safe-by-construction even for exotic operator
  forms the explicit detection does not enumerate — ``>>/etc/passwd`` (append to
  a real file), ``>&/etc/passwd`` (combined redirect to a FILE, NOT the ``>&N``
  fd-dup discard), and any named-fd-to-file glued form all fall through to the
  floor and return ``False``. Because ``reader.py`` delegates its redirect
  decision wholly to this helper, missing this floor would be a cardinal
  false-allow of a write.

Split-form handling (D-03b — genuinely new permissive code): the tokenizer
emits a spaced redirect as TWO tokens (``> /tmp/foo`` -> ``['>', '/tmp/foo']``)
and a glued redirect as ONE (``>/tmp/foo`` -> ``['>/tmp/foo']``). The scanner
iterates the tail with ONE-TOKEN LOOKAHEAD: a token that is EXACTLY a redirect
operator consumes the NEXT token as its target (a missing next token -> a bare
trailing operator -> ``False``); a token with an operator glued to a target is
split at the operator and the target classified. Discard / fd-dup forms are
``fullmatch``-classified FIRST, before any operator+target split, so glued
discard forms (``2>&1``, ``&>/dev/null``) still pass (the discard-before-veto
ordering invariant, 07-RESEARCH "Design consequences" point 3).

ACCEPTED RESIDUAL (D-03a): a planted symlink ``/tmp/link -> /etc/passwd`` still
writes through ``>/tmp/link``. The hook deliberately does NOT resolve symlinks
on the filesystem (latency + a TOCTOU race), so this is un-closable here. It is
ACCEPTED as the cost of honoring ROADMAP criterion 3 (a real ``/tmp`` scratch
write is allowed) — a known accepted risk, NOT an oversight. Do not add
filesystem resolution and do not drop the ``/tmp`` exception to "fix" it.
"""

from __future__ import annotations

import re

#: Discard redirects + fd-dup forms that never write a user FILE.
#: ``>&N`` / ``M>&N`` duplicate one file descriptor onto another (e.g. ``>&2``,
#: ``2>&1``); they never name a file. The ``\d+`` after ``>&`` is CARDINAL: it
#: forbids ``>&/etc/passwd`` (a combined-redirect to a FILE, which truncates it)
#: from matching as a discard — that form falls through to the SAFETY FLOOR.
_DISCARD_REDIR = re.compile(
    r"(?:"
    r"\d*>&\d+"  # fd-dup: 2>&1, >&2, 1>&2 (digits REQUIRED after >&)
    r"|>/dev/null"
    r"|2>/dev/null"
    r"|&>>?/dev/null"
    r")"
)

#: A token that is EXACTLY a redirect operator (the split / spaced form). The
#: NEXT token is its target. Covers ``>``, ``>>``, ``2>``, ``2>>``, fd-numbered
#: ``M>``/``M>>``, and the combined ``&>``/``&>>``.
#:
#: The ``\d*`` fd head is INTENTIONALLY unbounded (WR-01): ANY descriptor number
#: (``3>``, ``9>``, ``10>``, …) is admitted as an ordinary redirect. This is
#: safe because the fd number never relaxes the TARGET gate — the captured
#: target is still subject to ``_target_is_safe`` (discard or single-component
#: ``/tmp`` only). ``3>/etc/passwd`` therefore abstains; ``3>/tmp/x`` is just a
#: ``/tmp`` scratch write (within policy). Tests pin both directions.
_REDIR_OPERATOR = re.compile(r"(?:\d*>>?|&>>?)")

#: A glued redirect: an operator head immediately followed by a target. The
#: capturing group is the target part to classify.
_GLUED_REDIR = re.compile(r"(?:\d*>>?|&>>?)(.+)")

#: A single-component ``/tmp`` scratch target: literally ``/tmp/`` then exactly
#: one path component drawn from an ALLOWLIST of ordinary filename chars only.
#: This fails closed by construction — any char NOT on the list (a second
#: redirect ``>``/``<``, whitespace, a shell metacharacter, a second ``/``) is
#: rejected, so a glued second redirect (``>/tmp/a>b`` -> two bash redirects,
#: the second writing a real cwd file) cannot pass (CR-01). The project's
#: allowlist philosophy: unanticipated metacharacters never reach the carve-out.
#: The ``.``/``..`` components are rejected separately (the class admits ``.``).
_TMP_SCRATCH = re.compile(r"/tmp/([A-Za-z0-9._-]+)")


def _target_is_safe(target: str) -> bool:
    """True iff a redirect TARGET string is a discard or a /tmp scratch path.

    ``/dev/null`` is the discard target. A ``/tmp`` target is safe only as a
    single path component that is neither ``.`` nor ``..`` (07-RESEARCH "The
    hardened /tmp rule"). Everything else (a real non-/tmp path, a metacharacter,
    a second slash, a traversal) is unsafe.
    """
    if target == "/dev/null":
        return True
    m = _TMP_SCRATCH.fullmatch(target)
    if m is None:
        return False
    component = m.group(1)
    return component not in (".", "..")


def redirect_tail_is_safe(arg_tokens: list[str]) -> bool:
    """True iff every redirect in the tail is a discard or a /tmp scratch write.

    Returns ``True`` for a tail with no redirect/control tokens at all (plain
    operands and flags pass through). Returns ``False`` (the recognizer then
    abstains) the moment a redirect target is neither a discard target nor a
    valid ``/tmp`` single-component scratch path, on a bare operator with no
    target, and — via the SAFETY FLOOR — on any remaining token still containing
    ``>`` or ``&`` after the discard and ``/tmp`` carve-outs.
    """
    i = 0
    n = len(arg_tokens)
    while i < n:
        tok = arg_tokens[i]

        # Carve-out 1: discard / fd-dup forms, classified FIRST (before any
        # operator+target split) so glued discards (2>&1, &>/dev/null) pass.
        if _DISCARD_REDIR.fullmatch(tok):
            i += 1
            continue

        # Carve-out 2a: a bare operator token (split / spaced form). Consume the
        # NEXT token as its target; a missing next token is a bare trailing
        # operator and is unsafe.
        if _REDIR_OPERATOR.fullmatch(tok):
            if i + 1 >= n:
                return False
            if not _target_is_safe(arg_tokens[i + 1]):
                return False
            i += 2
            continue

        # Carve-out 2b: an operator glued to a target (one token). Split at the
        # operator and classify the target part.
        glued = _GLUED_REDIR.fullmatch(tok)
        if glued is not None:
            if not _target_is_safe(glued.group(1)):
                return False
            i += 1
            continue

        # SAFETY FLOOR: a plain operand/flag passes through ONLY when it carries
        # NEITHER a redirect ``>`` NOR a control ``&``. Any token still bearing
        # one here is an unrecognized operator form -> unsafe (no permissive
        # default).
        if ">" in tok or "&" in tok:
            return False

        i += 1

    return True

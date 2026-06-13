"""The read-only ``ssh`` recognizer (SSH-02, D-01/D-02/D-06/D-07/D-08).

``ssh`` here is a GENERAL read-only-over-ssh recognizer: when the remote
command is a genuine read-only invocation (reader/find/sed/git/journalctl),
the whole compound is allowed. Two surfaces:

1. **SSH option gate (D-06/D-07):** A minimal audited connection option
   allowlist: ``-p PORT``, ``-i IDENTITY``, ``-l LOGIN``, ``-F CONFIGFILE``,
   each consuming the following token as its value. Hard rejects (abstain):
   ``-o`` ENTIRELY (can set ProxyCommand/RemoteCommand/LocalCommand — whole-flag
   abstain subsumes all three), ``-L``/``-R``/``-D`` (port-forwards), ``-t``
   (pty). Any other option is unaudited and abstains by omission (D-06). Bare
   interactive ``ssh host`` with no remote command abstains (mirrors ``adb
   shell`` bare form, D-07).

2. **Remote re-fold via ``_fold_readonly_ssh`` (D-01/D-02/CR-01):** The remote
   command string is sliced RAW from the segment (quoting preserved — never
   re-join tokenized tokens; re-joining loses quoting and can merge commands)
   and re-tokenized + folded over the SCOPED allowlist
   (reader/find/sed/git/journalctl). This is a direct clone of ``adb``'s
   ``_fold_readonly``, extended with ``recognize_journalctl``.

   CARDINAL (CR-01 — [[engine-reentry-trust-laundering]]): the full ``REGISTRY``
   includes ``recognize_pytest``, ``recognize_gradle``, ``recognize_adb``,
   ``recognize_psql``, ``recognize_python``, whose ``allow`` is an opt-in TRUST
   grant or a wrapper with embedded analysis — NOT a simple read-only proof.
   Folding the remote command through the full registry would launder that local
   trust into an ssh-side genuine-read-only allow — the cardinal false-allow.
   ``_fold_readonly_ssh`` uses an EXPLICIT allowlist so any future trust-grant
   recognizer defaults to not-trusted here.

   Inner-verdict rule (mirrors adb D8-06):
   - ``inner is None`` → abstain.
   - ``inner.decision == "ask"`` → abstain (do not propagate ask up through ssh).
   - ``inner.decision == "allow"`` → re-wrap as ``Verdict("allow", "ssh read",
     "ssh")`` so the tag identifies THIS recognizer.

   SAFETY (T-08-02 from adb): lossy token re-join can only OVER-segment (more
   abstains), never MERGE two commands → no false-allow. Passing the RAW segment
   slice to ``tokenize`` preserves the true inner structure.

Outer redirect fence (D-08): ``redirect_tail_is_safe`` is applied to the
tokens AFTER the host position, before the raw slice. Any non-safe redirect
appearing as a bare outer token abstains (``ssh host journalctl >/etc/passwd``).

Tokenizer abstain = recognizer abstain (D8-08): ``$(...)``/backtick/brace-body
already abstain in ``tokenize``.

CIRCULAR-IMPORT note: ``recognizers/__init__`` → ``ssh`` → siblings (reader,
find, sed, git, journalctl) are LAZILY imported inside ``_fold_readonly_ssh``
at call time to avoid the ``recognizers/__init__`` → recognizer → ``engine`` →
``recognizers/__init__`` import cycle. ``tokenize`` (from ``tokenizer.py``,
which has no package imports) is safe at module top. ``engine.py`` and
``tokenizer.py`` stay byte-untouched (SC3).
"""

from __future__ import annotations

from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from .redirects import redirect_tail_is_safe

#: Options that each consume the following token as their value (D-06).
_SSH_VALUE_OPTS: frozenset[str] = frozenset({"-p", "-i", "-l", "-F"})

#: Verdict tags that the scoped re-fold is permitted to return (CR-01 tag fence).
#: ``recognize_reader`` has a python dispatch seam (Phase 12) that returns
#: tag="python" when the remote command is ``python -c "<code>"``. Allowing that
#: tag through would launder the python trust grant into an ssh-side allow —
#: the cardinal false-allow (D-02). Any tag NOT in this set is treated as a
#: trust-grant tag and abstains.
_SCOPED_TAGS: frozenset[str] = frozenset({"reader", "find", "sed", "git", "journalctl"})

#: Options that unconditionally abstain (D-07 hard rejects).
_SSH_HARD_REJECT: frozenset[str] = frozenset({"-o", "-L", "-R", "-D", "-t"})


def _fold_readonly_ssh(segments: list[str], ctx: Context) -> Verdict | None:
    """Fold ``segments`` over ONLY the genuinely-read-only recognizers (CR-01).

    A SCOPED clone of ``adb._fold_readonly`` whose recognizer set is an explicit
    ALLOWLIST — reader/find/sed/git/journalctl — NOT the global ``REGISTRY``.
    This is the cardinal CR-01 fix: the full registry includes trust-grant
    recognizers (pytest/gradle) and wrapper-analyzer recognizers (adb/psql/python)
    whose ``allow`` is NOT a genuine read-only proof. Folding the remote command
    through the full registry would launder that trust into an ssh-side
    genuine-read-only allow — the cardinal false-allow (D-02, CR-01).

    The two ``fold`` semantics are preserved exactly: (1) abstain-veto — if ANY
    segment is unrecognized by every allowed recognizer, return ``None``; (2)
    precedence ``ask`` > ``allow``, returning a literal input Verdict.

    REC-08 / 14-03: A DERIVED Context with ``read_scope="ssh"`` is passed to the
    inner recognizers so they consult ``ssh_allowed_roots`` (not
    ``local_allowed_roots``) and abstain on relative remote operands before
    resolution (SC#3 / T-14-08 / T-14-09). ``ctx`` (the OUTER context) is NOT
    mutated; the derived clone is local to this fold so the ssh scope cannot leak
    back to the outer segment (T-14-10). ``recognize_git`` and
    ``recognize_journalctl`` are unaffected — they take no REC-08 path operands.

    Lazy imports keep the existing circular-import discipline (``recognizers/
    __init__`` → ``ssh`` → siblings → ``engine`` → ``recognizers/__init__``);
    importing at call time avoids any import-order coupling.
    """
    from dataclasses import replace

    from .find import recognize_find
    from .git import recognize_git
    from .journalctl import recognize_journalctl
    from .reader import recognize_reader
    from .sed import recognize_sed

    # REC-08: derive a scoped clone so the inner recognizers consult
    # ssh_allowed_roots and SC#3-abstain on relative remote operands.
    # ``replace`` from dataclasses creates a shallow copy with only the
    # named field changed — ctx itself (the outer Context) is NOT mutated.
    ssh_ctx = replace(ctx, read_scope="ssh")

    readonly = (
        recognize_reader,
        recognize_find,
        recognize_sed,
        recognize_git,
        recognize_journalctl,
    )

    survivor: Verdict | None = None
    for segment in segments:
        match: Verdict | None = None
        for recognizer in readonly:
            match = recognizer(segment, ssh_ctx)
            if match is not None:
                break
        if match is None:
            # One unrecognized segment vetoes the whole compound (abstain-veto).
            return None
        ask_beats_allow = (
            survivor is not None
            and survivor.decision == "allow"
            and match.decision == "ask"
        )
        if survivor is None or ask_beats_allow:
            survivor = match
    return survivor


def recognize_ssh(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a read-only ssh invocation, else ``None``.

    Allows ``ssh host <read-only-cmd>`` forms where the remote command re-folds
    to an allow through the scoped read-only allowlist (reader/find/sed/git/
    journalctl). Abstains on hard-reject options (-L/-R/-D/-t/-o), bare
    interactive ssh, outer non-safe redirects, remote mutations, and any
    tokenizer abstain.
    """
    result = tokenize(segment)
    # Tokenizer holds all expansion safety; its abstain is the recognizer's.
    if result.abstain_reason is not None:
        return None
    # Compound command (more than one pipe segment) -> abstain.
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens or tokens[0] != "ssh":
        return None

    # Parse ssh options and locate the host token.
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in _SSH_HARD_REJECT:
            # D-07: hard reject.
            return None
        if tok.startswith("-"):
            # Check for value-consuming admitted options (D-06).
            if tok in _SSH_VALUE_OPTS:
                i += 2  # consume option + its value token
                continue
            # Glued short form: -p2222 (option and value glued together).
            if len(tok) >= 2 and tok[:2] in _SSH_VALUE_OPTS:
                i += 1  # value is glued; no extra token consumed
                continue
            # Any other option: unaudited -> abstain by omission (D-06).
            return None
        else:
            # First non-option token is the host (user@host or bare host).
            break

    # Never found the host token (e.g. consumed past end of tokens).
    if i >= len(tokens):
        return None

    host_idx = i

    # Bare interactive ssh host (no remote command) -> abstain (D-07).
    if host_idx + 1 >= len(tokens):
        return None

    # Outer redirect fence (D-08): vet the tokens AFTER the host position.
    # Any non-safe redirect appearing as a bare outer token abstains.
    outer_tail = tokens[host_idx + 1 :]
    if not redirect_tail_is_safe(outer_tail):
        return None

    # Slice the remote command RAW from the segment AFTER the host token, so
    # quoting is preserved (re-joining tokens loses quoting, T-08-02).
    host_text = tokens[host_idx]
    # Search for host_text in the segment starting after the leading "ssh"
    # keyword, so we skip any occurrence of host_text that happens to appear
    # inside the option values preceding it.
    search_start = segment.index("ssh") + len("ssh")
    idx = segment.index(host_text, search_start)
    remote = segment[idx + len(host_text) :]

    # Re-decompose the remote command over the SCOPED read-only recognizer set
    # (NOT the full REGISTRY — CR-01). ``engine.py`` stays byte-untouched (SC3).
    inner = _fold_readonly_ssh(tokenize(remote).segments, ctx)
    if inner is None or inner.decision == "ask":
        return None
    # CR-01 tag fence: verify the inner verdict tag is from the explicitly
    # trusted scoped allowlist. ``recognize_reader`` has a python dispatch seam
    # (Phase 12) that returns tag="python" when the remote command is a
    # ``python -c "<code>"`` shape — allowing that tag through would launder the
    # python trust grant into an ssh-side allow, violating D-02. Any tag NOT in
    # ``_SCOPED_TAGS`` is treated as a trust-grant tag and abstains.
    if inner.tag not in _SCOPED_TAGS:
        return None
    # Re-wrap as an ssh verdict so the tag identifies THIS recognizer.
    return Verdict("allow", "ssh read", "ssh")

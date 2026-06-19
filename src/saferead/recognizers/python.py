r"""The read-only ``python`` recognizer (PY-02, D-04/D-16).

``recognize_python`` owns the bash argv surface for Python invocation; the
read-only judgement itself lives in the Plan-01 analyzer. This recognizer scans
the launcher prefix, extracts the source (either a ``-c`` value or a readable
script file), dequotes ONE shell layer off a ``-c`` value, fences the redirect
tail, and DISPATCHES the extracted source to the PARAMETERIZED core
``_analyze_python`` with the (possibly project-widened) ``ctx.config`` allowlists
— re-wrapping an allow with THIS recognizer's tag ``"python"``.

DISPATCH, NOT RE-FOLD (T-11-15). Like ``recognize_psql``, this calls the analyzer
core directly and re-wraps the allow; it NEVER re-enters ``engine.fold`` over a
nested command (the adb-style re-fold is the trust-laundering seam, irrelevant
here). Verified: no ``fold(`` / ``ANALYZERS[`` re-entry in this module.

Launcher scan — ADAPTED from ``pytest_runner._scan_launcher_prefix``, with three
deliberate DIVERGENCES (D-04, all tighter than pytest's opt-in trust posture):

* ``--with``/``--with-requirements``/``--with-editable`` after ``uv run`` ABSTAIN
  (a network/package install = state mutation) — pytest ACCEPTS ``--with`` as a
  recorded residual (D8-03); the read-only analyzer must not (Pitfall 5).
* A leading ENV-ASSIGN prefix (``PYTHONPATH=... python``) ABSTAINS — pytest skips
  env-assign as an accepted residual; here over-abstain is free (Pitfall, D-04).
* ``-m <module>`` ABSTAINS (runs arbitrary module code); ``uvx`` / ``uv tool run``
  abstain by omission (only literal ``uv ... run`` lands); the python exe match is
  versioned (``python``/``python3``/``python3.NN`` by path-suffix, NEVER a
  substring so ``pythonfoo`` is rejected — Pitfall 6).

Benign interpreter flags ride along: ``-O``/``-OO``/``-B``/``-q``/``-I``/``-S``/
``-E`` (non-mutating). ANY unknown flag abstains (allowlist polarity, D-16).

WHOLE-TAIL audit BEFORE dispatch (the psql cardinal posture). The post-exe tail
is walked with an index loop requiring EXACTLY one ``-c`` (kills the
``python -c "1" -c "2"`` early-dispatch trap) OR exactly one script operand
(never both); then the redirect tail is fenced and only then is the source
dispatched.

SCRIPT-FILE READ (``_read_script``) is a genuinely NEW primitive (zero ``open(``
in ``recognizers/`` before this). It is bounded: ``stat`` failure → abstain;
non-``S_ISREG`` (fifo/dir/socket/device like ``/dev/zero``) → abstain (prevents a
hot-path hang); ``> 64 KiB`` → abstain; ``OSError``/``UnicodeDecodeError`` →
abstain. ACCEPTED RESIDUAL (TOCTOU, T-12-20): the file Claude actually executes
could be swapped after this stat/read — irreducible without a lock, and a swapped
file is code the user runs on their own machine (same trust boundary as the
read). Documented, NOT locked.

DISABLE-LEAK ACCEPTED RESIDUAL (Pitfall 2, T-12-23): disabling the ``"python"``
tag stops THIS recognizer but NOT the byte-locked reader's floor ``-c`` dispatch
(both emit tag ``"python"``, but the reader path is a separate entry guarded by
its own ``"reader"`` tag). Over-allow is bounded to the FLOOR (never the widened
surface). Do NOT edit the byte-locked reader to "fix" this.

Tokenizer abstain is the recognizer's abstain (D8-08): ``$(...)``/backtick/
process-sub already abstain in ``tokenize``.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

from ..analyzers.python_skeleton import _FLOOR_BUILTINS, _analyze_python
from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from ._quoting import strip_one_quote_layer
from .redirects import redirect_tail_is_safe

#: A leading ``VAR=val`` env-assignment token. Unlike pytest (which accepts these
#: as a residual), the python recognizer REJECTS an env-assign prefix (D-04).
_ENV_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")

#: The python exe by PATH-SUFFIX (never a substring): ``python``, ``python3``,
#: versioned ``python3.NN``, and their ``/``-suffix forms. ``pythonfoo`` rejected.
_PYTHON_EXE = re.compile(r"^(?:.*/)?(?:python|python3|python3\.\d+)$")

#: Benign (non-mutating) interpreter flags that ride along (D-04).
_BENIGN_FLAGS = frozenset({"-O", "-OO", "-B", "-q", "-I", "-S", "-E"})

#: ``uv run`` flags that install packages (state mutation) — REJECT before the
#: value-consume (Pitfall 5; DIVERGES from pytest's accepted ``--with`` residual).
_WITH_FLAGS = frozenset({"--with", "--with-requirements", "--with-editable"})

#: The 64 KiB script-file read cap.
_MAX_SCRIPT_BYTES = 65536


def _is_python_exe(tok: str) -> bool:
    """True iff ``tok`` is a (possibly versioned) python exe by path-suffix."""
    return _PYTHON_EXE.match(tok) is not None


def _is_with_flag(tok: str) -> bool:
    """True iff ``tok`` is a ``--with*`` install flag (split or ``=value`` form)."""
    return tok in _WITH_FLAGS or tok.split("=", 1)[0] in _WITH_FLAGS


def _is_redirect_token(tok: str) -> bool:
    """True iff ``tok`` is a redirect/control token (left for the fence, not a
    script operand). Catches ``>``/``>>``/``2>``/``&``/``&>`` and ``<`` input
    redirects; the actual safety vetting is ``redirect_tail_is_safe``."""
    return ">" in tok or "&" in tok or tok.startswith("<")


def _scan_uv_python_prefix(tokens: list[str]) -> tuple[str, int] | None:
    """Locate the launcher landing token, or ``None`` if not a recognized shape.

    Returns ``("exe", i)`` when ``tokens[i]`` is the python exe (direct or after
    ``uv run``), or ``("script", i)`` for the ``uv run <script.py>`` direct-script
    shape (no exe token). Allowlist polarity on the prefix: a mis-parse abstains.
    """
    n = len(tokens)
    if n == 0:
        return None

    # ENV-ASSIGN prefix -> abstain (tighter than pytest; D-04).
    if _ENV_ASSIGN.match(tokens[0]):
        return None

    # Direct python exe.
    if _is_python_exe(tokens[0]):
        return ("exe", 0)

    # UV prefix: ``uv [flags] run [flags] (<python exe> | <script.py>)``.
    if tokens[0] == "uv" or tokens[0].endswith("/uv"):
        i = 1
        # uv flags before ``run`` (a flag consumes its value unless the value is a
        # flag, ``run``, or the python exe). REJECT a --with* flag first.
        while i < n and tokens[i].startswith("-"):
            if _is_with_flag(tokens[i]):
                return None
            i += 1
            if (
                i < n
                and not tokens[i].startswith("-")
                and tokens[i] != "run"
                and not _is_python_exe(tokens[i])
            ):
                i += 1  # consume the flag's value
        if i >= n or tokens[i] != "run":
            return None
        i += 1  # consume ``run``
        # optional post-``run`` flags (same value-consume rule; --with* rejected).
        while i < n and tokens[i].startswith("-"):
            if _is_with_flag(tokens[i]):
                return None
            i += 1
            if (
                i < n
                and not tokens[i].startswith("-")
                and not _is_python_exe(tokens[i])
            ):
                i += 1
        if i >= n:
            return None
        if _is_python_exe(tokens[i]):
            return ("exe", i)
        # ``uv run <script.py>`` direct-script shape (no exe token).
        return ("script", i)

    # Any other leading word (uvx / uv tool run / poetry run / ...) -> abstain.
    return None


def _read_script(arg: str) -> str | None:
    """Read a script file's text, bounded; abstain (``None``) on any risk.

    ``stat`` failure, a non-regular file (fifo/dir/socket/device), a file over the
    64 KiB cap, or an ``OSError``/``UnicodeDecodeError`` on read all return
    ``None`` (T-12-19). TOCTOU is an accepted residual (T-12-20, see module doc).
    """
    path = Path(arg)
    try:
        st = path.stat()
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    if st.st_size > _MAX_SCRIPT_BYTES:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None


def recognize_python(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a read-only Python invocation, else ``None``.

    Allows ``python``/``python3``/``python3.NN -c <readonly>``, a readable
    read-only script path, and the ``uv run`` python forms; the extracted source
    must be proven read-only by ``_analyze_python`` (with ``ctx.config`` allowlists,
    possibly project-widened per PY-04). Abstains by omission on everything else.
    """
    result = tokenize(segment)
    # The tokenizer holds ALL expansion safety; its abstain is the recognizer's.
    if result.abstain_reason is not None:
        return None
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens:
        return None

    landing = _scan_uv_python_prefix(tokens)
    if landing is None:
        return None
    kind, idx = landing

    # ``uv run <script.py>`` direct shape: tokens[idx] is the script path itself.
    if kind == "script":
        args = tokens[idx + 1 :]
        source = _read_script(tokens[idx])
        if source is None:
            return None
        if not redirect_tail_is_safe(args):
            return None
        return _dispatch(source, ctx)

    # ``exe`` shape: walk the post-exe tail (whole-tail audit BEFORE dispatch).
    args = tokens[idx + 1 :]
    c_source: str | None = None
    c_count = 0
    script_path: str | None = None
    operand_count = 0
    i = 0
    n = len(args)
    while i < n:
        tok = args[i]
        if tok in _BENIGN_FLAGS:
            i += 1
            continue
        if tok == "-m":
            return None  # arbitrary module code
        if tok == "-":
            return None  # stdin
        if tok == "-c" or tok == "--command":
            if i + 1 >= n:
                return None  # dangling -c
            c_source = args[i + 1]
            c_count += 1
            i += 2
            continue
        if _is_redirect_token(tok):
            i += 1  # left for the redirect fence below, not a script operand
            continue
        if tok.startswith("-"):
            return None  # unknown flag (allowlist polarity, D-16)
        # a bare non-flag, non-redirect token: a script path candidate.
        operand_count += 1
        if operand_count == 1:
            script_path = tok
        else:
            return None  # a second genuine operand -> ambiguous
        i += 1

    # Require EXACTLY one source: a single -c value XOR a single script operand.
    if c_count > 1:
        return None
    if c_count == 1 and script_path is not None:
        return None  # ambiguous (-c and a script)
    if c_count == 1:
        source = strip_one_quote_layer(c_source) if c_source is not None else None
    elif script_path is not None:
        source = _read_script(script_path)
    else:
        return None  # bare python (REPL) — no source
    if source is None:
        return None

    # Outer redirect fence over the full post-exe tail (T-12-18).
    if not redirect_tail_is_safe(args):
        return None

    return _dispatch(source, ctx)


def _dispatch(source: str, ctx: Context) -> Verdict | None:
    """Dispatch source to the parameterized core with ``ctx.config`` allowlists.

    NOT an engine re-fold (T-11-15): calls ``_analyze_python`` directly and
    re-wraps an allow with this recognizer's tag ``"python"``. The method/module
    allowlists come from ``ctx.config`` (the PY-03 wiring; possibly project-widened
    per PY-04), the builtins from the analyzer floor.
    """
    inner = _analyze_python(
        source,
        allowed_builtins=_FLOOR_BUILTINS,
        allowed_methods=ctx.config.python_allowed_methods,
        allowed_modules=ctx.config.python_allowed_modules,
    )
    if inner is None or inner.decision == "ask":
        return None
    return Verdict("allow", "read-only python", "python")

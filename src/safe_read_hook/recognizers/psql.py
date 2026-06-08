r"""The read-only ``psql`` recognizer (SQL-02, D-03/D-16).

``recognize_psql`` owns the bash argv surface for ``psql``; the SQL judgement
itself lives in ``ANALYZERS["sql"]`` (the Plan 02 analyzer). This recognizer
extracts the single ``-c``/``--command`` value, dequotes ONE shell layer, and
DISPATCHES the dequoted SQL to the analyzer — re-wrapping an allow with THIS
recognizer's tag ``"psql"``. It is allowlist polarity throughout: anything not
explicitly recognized abstains (returns ``None``), and a false-allow (approving
a state-mutating command) is the cardinal failure.

Two-stage shape (mirrors ``adb.py``'s entry + flag audit, and ``reader.py``'s
capture -> ``strip_one_quote_layer`` -> ``ANALYZERS[lang]`` dispatch at
reader.py:420-422):

1. ENTRY (adb.py:153-161): ``tokenize`` -> tokenizer abstain IS the recognizer's
   abstain (D8-08 — ``$(...)``/backtick/process-sub already abstain upstream) ->
   exactly one segment -> leading word ``psql``.

2. FLAG AUDIT (allowlist polarity, D-16). The flag tail is walked with an INDEX
   loop because flags consume value tokens (a simple name-only audit like adb's
   ``_flag_is_audited`` cannot capture values):

   - Connection flags ride along as benign. Value-bearing
     (``-h``/``--host``, ``-U``/``--username``, ``-d``/``--dbname``,
     ``-p``/``--port``) consume their following token as an OPAQUE value (split
     shape) — that value token is never re-classified as a flag. Valueless
     (``-w``/``--no-password``, ``-W``/``--password``) consume nothing (so
     ``psql -w -c "..."`` keeps its SQL).
   - ``-c``/``--command`` is the ONE command-carrier. CAPTURE its value across
     the three shapes from the token TEXT (which still carries shell quotes —
     the tokenizer does NOT dequote): split = the NEXT token's text; glued short
     ``-c"SELECT 1"`` -> ``text[2:]`` = ``"SELECT 1"``; ``--command="SELECT 1"``
     -> remainder after the first ``=`` = ``"SELECT 1"``. The value is captured
     RAW (quotes intact) and the ``-c`` count is incremented; we do NOT dispatch
     mid-loop.
   - ``-f``/``--file``, ``-o``/``--output``, ``-L``/``--log-file``, and ANY
     unknown/unenumerated flag abstain by omission (allowlist polarity).
   - A non-option token (a bare operand or a redirect token) is left for the
     redirect fence; an unquoted multi-word ``-c`` value yields a dangling
     operand token and is caught here / by the ``c_count`` check.

CARDINAL — the WHOLE tail is audited BEFORE dispatch. Dispatching the moment a
read-only ``-c`` is captured would false-allow ``psql -c "SELECT 1" -c "DELETE
FROM t"`` and ``psql -c "SELECT 1" -f x.sql`` (the second mutating clause / file
flag never gets seen). So the order is strictly: walk the whole tail -> require
``c_count == 1`` (covers bare-psql=0 AND multi-c) -> ``strip_one_quote_layer``
once -> backslash check -> ``redirect_tail_is_safe`` -> dispatch.

ONE-LAYER DEQUOTE (D-03, the reader.py:421 analog). The captured value still
carries its shell quotes; ``strip_one_quote_layer`` removes ONE layer BEFORE the
backslash check and dispatch, so pglast receives ``SELECT 1`` not ``"SELECT 1"``
(a quoted string parses as a delimited identifier -> ParseError -> spurious
abstain, killing the canonical allow case).

BACKSLASH REJECTION (D-03, T-11-10). A backslash anywhere in the DEQUOTED ``-c``
value abstains — a cheap conservative pre-filter for psql meta-commands
(``\copy``/``\!``/``\o``/``\i``/``\g``) that escape SQL entirely. Checked AFTER
dequote so the backslash is matched on the same string pglast would see.

OUTER FENCE (T-11-13). The full token tail is routed through the shared
``redirect_tail_is_safe`` so a host redirect outside the SQL
(``psql -c "SELECT 1" >/etc/passwd``) abstains. Accepted harmless over-abstain:
SQL containing a literal ``>``/``&`` (e.g. ``SELECT a > b``) trips the safety
floor and abstains — not in the allow corpus; over-abstain is free.

DISPATCH, NOT RE-FOLD (T-11-15). ``recognize_psql`` calls ``ANALYZERS["sql"]``
and re-wraps an allow as ``Verdict("allow", "psql read-only sql", "psql")``. It
deliberately does NOT copy adb's read-only re-fold / engine re-entry seam —
re-folding a nested command over the registry is the trust-laundering vector,
irrelevant here.

No cycle: ``analyzers`` do not import ``recognizers``, so ``ANALYZERS`` imports
at module top; the heavy ``pglast`` import stays lazy INSIDE ``analyze_sql``, so
the common read path pays no import cost.
"""

from __future__ import annotations

from ..analyzers import ANALYZERS
from ..context import Context
from ..tokenizer import tokenize
from ..verdict import Verdict
from ._quoting import strip_one_quote_layer
from .redirects import redirect_tail_is_safe

#: Connection flags that consume a following value token (split shape). Their
#: value is OPAQUE and is never re-classified as a flag.
_CONN_VALUE_FLAGS = frozenset(
    {"-h", "--host", "-U", "--username", "-d", "--dbname", "-p", "--port"}
)

#: Connection flags that take NO value (so they do not swallow the next token).
_CONN_VALUELESS_FLAGS = frozenset({"-w", "--no-password", "-W", "--password"})


def recognize_psql(segment: str, ctx: Context) -> Verdict | None:
    """Return an ``allow`` Verdict for a read-only ``psql -c <sql>``, else ``None``.

    Allows a single ``psql`` invocation whose one ``-c``/``--command`` SQL is
    proven read-only by ``ANALYZERS["sql"]`` (with benign connection flags
    riding along). Abstains on everything else by omission (D-16): file/output/
    log flags, more than one ``-c``, ``-c`` combined with ``-f``, any unknown
    flag, a backslash meta-command, an unsafe outer redirect, a non-read-only
    SQL judgement, and any tokenizer abstain.
    """
    result = tokenize(segment)
    # The tokenizer holds ALL expansion safety; its abstain is the recognizer's.
    if result.abstain_reason is not None:
        return None
    if len(result.tokens) != 1:
        return None

    tokens = [t.text for t in result.tokens[0].tokens]
    if not tokens or tokens[0] != "psql":
        return None

    rest = tokens[1:]

    # --- Stage 2: audit the WHOLE flag tail before any dispatch (cardinal). ---
    sql_raw: str | None = None
    c_count = 0
    i = 0
    n = len(rest)
    while i < n:
        tok = rest[i]

        # A captured -c value (split shape) and bare operands / redirect tokens
        # are handled below; only OPTION tokens are audited here.
        is_option = tok.startswith("-") and tok != "-"
        if not is_option:
            # A bare operand reaching here is a dangling token (e.g. an unquoted
            # multi-word -c value) or a redirect token. The redirect fence below
            # vets redirects; a stray operand will fall to the c_count gate or
            # the fence. Leave it for the fence and advance.
            i += 1
            continue

        # -c / --command : the ONE command-carrier; capture across three shapes.
        if tok == "-c" or tok == "--command":
            # split shape: the SQL is the NEXT token's raw text.
            if i + 1 >= n:
                return None  # dangling -c with no value
            sql_raw = rest[i + 1]
            c_count += 1
            i += 2
            continue
        if tok.startswith("-c") and len(tok) > 2:
            # glued short shape: token text is -c"SELECT 1"; value is text[2:].
            sql_raw = tok[2:]
            c_count += 1
            i += 1
            continue
        if tok.startswith("--command="):
            # =value shape: remainder after the first '='.
            sql_raw = tok.split("=", 1)[1]
            c_count += 1
            i += 1
            continue

        # Connection flags ride along.
        if tok in _CONN_VALUE_FLAGS:
            i += 2  # consume the opaque value token as well
            continue
        if tok in _CONN_VALUELESS_FLAGS:
            i += 1
            continue

        # Any other flag (-f/--file, -o/--output, -L/--log-file, unknown) ->
        # abstain by omission (allowlist polarity, D-16).
        return None

    # Exactly one -c (covers bare psql = 0 and the multi-c / -c+-f cases, since
    # -f abstained above and a second -c bumped the count).
    if c_count != 1 or sql_raw is None:
        return None

    # One-layer dequote BEFORE the backslash check + dispatch (reader.py:421).
    sql = strip_one_quote_layer(sql_raw)

    # Backslash meta-command pre-filter (D-03) on the same string pglast sees.
    if "\\" in sql:
        return None

    # Outer redirect fence over the FULL token tail (T-11-13).
    if not redirect_tail_is_safe(rest):
        return None

    # DISPATCH to the SQL analyzer (NOT a re-fold / engine re-entry, T-11-15).
    inner = ANALYZERS["sql"](sql)
    if inner is None or inner.decision == "ask":
        return None
    # Re-wrap with THIS recognizer's tag (the analyzer emits tag "sql").
    return Verdict("allow", "psql read-only sql", "psql")

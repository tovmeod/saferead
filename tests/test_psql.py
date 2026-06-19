r"""Boundary tests for the read-only ``psql`` recognizer (SQL-02 / TEST-02).

``recognize_psql`` owns the bash argv surface for ``psql``: it audits the flags
(allowlist polarity), captures the single ``-c``/``--command`` value across the
three shapes (split / glued / ``=value``), strips ONE shell-quote layer
(``strip_one_quote_layer``, the reader.py:421 analog) BEFORE the backslash check
and dispatch, and hands the dequoted SQL to ``ANALYZERS["sql"]`` (Plan 02). An
allow is re-wrapped with THIS recognizer's tag ``"psql"``. It does NOT re-fold /
engine-re-enter (no ``_fold_readonly`` — that is the adb trust-laundering seam,
T-11-15).

Allowlist polarity / abstain-by-omission: connection flags
(``-h``/``-U``/``-d``/``-p``/``-w``/``-W``) ride along; ``-f``/``-o``/``-L``,
more than one ``-c``, ``-c`` combined with ``-f``, and ANY unknown flag abstain.
A backslash anywhere in the DEQUOTED ``-c`` value abstains (meta-command escape:
``\copy``/``\!``/``\o``/``\i``/``\g``). An unsafe outer redirect tail abstains.

CARDINAL — the whole flag tail is audited BEFORE dispatch. ``psql -c "SELECT 1"
-c "DELETE FROM t"`` must abstain on the multi-``-c`` count, NOT false-allow on
the first read-only ``-c`` (early-dispatch trap).

Test-name contract (load-bearing, MEMORY.md silent-skip lesson, D8-09): the
``-k`` filter selects on the substrings ``psql`` + ``allow``/``abstain``. A test
whose name misses these substrings is silently NOT run. Tests assert the
recognizer VERDICT (the contract) — never a dequoted intermediate value.
"""

from __future__ import annotations

import pytest

from sash.context import Context
from sash.engine import fold
from sash.recognizers.psql import recognize_psql
from sash.tokenizer import tokenize


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- read-only -c extraction across the three shapes: allow ----------------
#
# split (``-c "SQL"``), glued quoted (``-c"SQL"`` -> single token text
# ``-c"SELECT 1"``, capture text[2:] then dequote), and ``--command="SQL"``
# (capture remainder after the first ``=`` then dequote). Connection flags
# ride along. NOTE: unquoted ``psql -cSELECT 1`` tokenizes to ``-cSELECT`` + ``1``
# (a dangling token) and is deliberately NOT in this corpus (it abstains).


@pytest.mark.parametrize(
    "segment",
    [
        'psql -c "SELECT 1"',
        'psql -c "SELECT id FROM t WHERE x = 1"',
        'psql -c "SELECT count(*) FROM t"',
        'psql -c "EXPLAIN SELECT 1"',
        'psql -c "SHOW search_path"',
        'psql -c"SELECT 1"',  # glued quoted: token text -c"SELECT 1"
        'psql --command="SELECT 1"',  # =value capture then one-layer dequote
        'psql -h db -U u -d d -c "SELECT 1"',  # connection flags ride along
    ],
)
def test_psql_readonly_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_psql(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "psql"


# --- file/output/log flags, multi-c, -c+-f, unknown flag: abstain ----------


@pytest.mark.parametrize(
    "segment",
    [
        "psql -f x.sql",  # file flag -> abstain
        'psql -c "SELECT 1" -o /etc/x',  # output flag
        'psql -c "SELECT 1" -L /tmp/log',  # log-file flag
        "psql -c a -c b",  # more than one -c
        # CARDINAL: read-only first -c then a mutating second -c. Abstains ONLY
        # if the whole tail is audited before dispatch (early-dispatch trap).
        'psql -c "SELECT 1" -c "DELETE FROM t"',
        'psql -c "SELECT 1" -f x.sql',  # -c combined with -f
        'psql --no-such-flag -c "SELECT 1"',  # unknown flag -> abstain
        "psql",  # bare psql, no -c
    ],
)
def test_psql_flag_audit_abstain(segment: str, ctx: Context) -> None:
    assert recognize_psql(segment, ctx) is None


# --- backslash meta-command in the dequoted -c value: abstain --------------


@pytest.mark.parametrize(
    "segment",
    [
        "psql -c \"\\copy t to '/x'\"",  # \copy meta-command
        'psql -c "\\! rm -rf /"',  # \! shell escape
    ],
)
def test_psql_backslash_metacommand_abstain(segment: str, ctx: Context) -> None:
    assert recognize_psql(segment, ctx) is None


# --- analyzer abstains on non-read-only SQL: abstain -----------------------


@pytest.mark.parametrize(
    "segment",
    [
        'psql -c "DELETE FROM t"',  # DML
        "psql -c \"SELECT nextval('s')\"",  # volatile function
        'psql -c "SELECT 1; DROP TABLE t"',  # multi-statement
    ],
)
def test_psql_analyzer_abstain(segment: str, ctx: Context) -> None:
    assert recognize_psql(segment, ctx) is None


# --- outer redirect fence: a host redirect outside the SQL abstains --------


@pytest.mark.parametrize(
    "segment",
    [
        'psql -c "SELECT 1" >/etc/passwd',  # outer redirect to a real file
    ],
)
def test_psql_outer_redirect_abstain(segment: str, ctx: Context) -> None:
    assert recognize_psql(segment, ctx) is None


# --- non-psql leading word: abstain ----------------------------------------


def test_psql_non_leading_word_abstain(ctx: Context) -> None:
    assert recognize_psql("cat foo", ctx) is None


# --- live fold-path wiring (mirrors test_adb.py:196-204) -------------------
#
# Assert THROUGH engine.fold — the path the hook actually takes.


def test_psql_allow_through_fold(ctx: Context) -> None:
    verdict = fold(tokenize('psql -c "SELECT 1"').segments, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "psql"


def test_psql_abstain_through_fold(ctx: Context) -> None:
    assert fold(tokenize('psql -c "DELETE FROM t"').segments, ctx) is None

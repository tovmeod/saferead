"""Boundary tests for the read-only SQL analyzer (SQL-01 / TEST-02).

``analyze_sql`` is the first real consumer of the Phase-4 analyzer seam: it
parses ONE SQL string with ``pglast`` (lazy-imported, abstain-never-crash) and
proves read-only by an ALLOWLIST over AST node TYPES + a function-name allowlist
+ an operator-name allowlist, abstaining on the FIRST unknown node/function/
operator (D-16 polarity). Statement type alone is NOT proof of read-only:
``SELECT ... INTO`` / ``FOR UPDATE`` / a data-modifying CTE / ``nextval`` /
``pg_read_file`` all parse as a plain ``SelectStmt`` (D-04, verified in
11-RESEARCH).

These tests exercise ``analyze_sql`` DIRECTLY (not through the psql recognizer —
that is Plan 03). The locked D-04 read-only-vs-abstain statement set:
ALLOW ``SELECT`` / ``EXPLAIN`` without options / ``SHOW`` / read-only ``WITH``;
ABSTAIN on every mutating/side-effecting/unprovable/multi-statement/unparseable
SQL.

Test-name contract (load-bearing, MEMORY.md silent-skip lesson, D8-09): the
``-k`` filter selects on the substrings ``sql`` + ``allow``/``abstain``/
``registered``. A test whose name misses these substrings is silently NOT run.
"""

from __future__ import annotations

import pytest

from safe_read_hook.analyzers import ANALYZERS
from safe_read_hook.analyzers.sql import analyze_sql
from safe_read_hook.verdict import Verdict

# --- ALLOW corpus: provably read-only single statements --------------------

_SQL_ALLOW = [
    "SELECT 1",
    "SELECT count(*) FROM t",
    "SELECT id FROM t WHERE x = 1",
    "EXPLAIN SELECT 1",
    "SHOW search_path",
    "WITH x AS (SELECT 1) SELECT * FROM x",
]


@pytest.mark.parametrize("source", _SQL_ALLOW)
def test_sql_readonly_allow(source: str) -> None:
    """A provably read-only single statement -> allow, tag ``sql``."""
    verdict = analyze_sql(source)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "sql"


# --- ABSTAIN corpus: the E2 mutating/side-effecting/unprovable vectors ------
#
# Every entry MUST abstain (return None). A false-allow here is the cardinal
# failure. Covers: EXPLAIN-that-executes, INTO/FOR UPDATE, DML-CTE, volatile/
# UDF/file functions, operator-backed volatile function, multi-statement, all
# DML/DDL/TRUNCATE/COPY/SET/GRANT/CALL/DO, unparseable, and empty input.

_SQL_ABSTAIN = [
    "EXPLAIN ANALYZE SELECT 1",
    "EXPLAIN (SERIALIZE) SELECT 1",
    "EXPLAIN (COSTS off) SELECT 1",
    "SELECT 1 INTO newtbl",
    "SELECT 1 FROM t FOR UPDATE",
    "WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
    "SELECT nextval('s')",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT my_udf()",
    "SELECT a # b FROM t",
    "SELECT 1; DROP TABLE t",
    "INSERT INTO t VALUES (1)",
    "UPDATE t SET x=1",
    "DELETE FROM t",
    "CREATE TABLE z (a int)",
    "DROP TABLE t",
    "TRUNCATE t",
    "COPY t TO '/tmp/f'",
    "SET search_path = x",
    "CALL proc()",
    "DO $$ BEGIN END $$",
    "GRANT SELECT ON t TO u",
    "not a sql statement at all",
    "",
]


@pytest.mark.parametrize("source", _SQL_ABSTAIN)
def test_sql_mutating_abstain(source: str) -> None:
    """Every mutating/side-effecting/unprovable/unparseable SQL -> abstain."""
    assert analyze_sql(source) is None


# --- registration: ANALYZERS["sql"] is wired and callable ------------------


def test_sql_registered_and_callable() -> None:
    """``ANALYZERS["sql"]`` is registered and returns ``Verdict | None``."""
    assert "sql" in ANALYZERS
    analyzer = ANALYZERS["sql"]
    assert callable(analyzer)
    result = analyzer("SELECT 1")
    assert result is None or isinstance(result, Verdict)

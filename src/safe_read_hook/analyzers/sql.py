"""Read-only PostgreSQL SQL analyzer (SQL-01).

``analyze_sql(source) -> Verdict | None`` is the first real consumer of the
Phase-4 analyzer seam (D4-08). It parses ONE SQL string with ``pglast``
(libpg_query — the actual PostgreSQL grammar, D-01) and proves the statement is
read-only by an ALLOWLIST over AST node TYPES + a function-name allowlist + an
operator-name allowlist, abstaining (returning ``None``) on the FIRST unknown
node / function / operator (D-16 polarity). It NEVER denies and never crashes.

Why a real parse tree (D-01): statement type alone is NOT proof of read-only.
``SELECT ... INTO`` (creates a table), ``SELECT ... FOR UPDATE`` (locks rows), a
data-modifying CTE (``WITH x AS (INSERT ...) SELECT ...``), ``SELECT
nextval('s')`` (advances a sequence) and ``SELECT pg_read_file(...)`` (reads a
server file) ALL parse as a plain ``SelectStmt`` (verified, 11-RESEARCH). Only a
walk of the whole tree proves read-only.

Why allowlist polarity (D-16, not a denylist): a denylist of mutation markers
defaults to ALLOW on any vector not enumerated. Two real vectors a FuncCall-only
denylist misses are caught here for free by the node-type allowlist: an
operator-backed volatile function (``a # b`` parses as ``A_Expr`` with NO
``FuncCall`` node) and ``EXPLAIN (SERIALIZE)`` (a PG17 option that executes the
query). The allowlist abstains on the first unenumerated node, so ``IntoClause``
/ ``LockingClause`` / DML-CTE bodies all fall out without being named.

Why static function allowlist (D-02 / D-02a): no offline mechanism can prove a
function's volatility (``pg_proc.provolatile`` and ``SET TRANSACTION READ ONLY``
both need a live DB connection the hook won't make). ``_ALLOWED_FUNCS`` is a
small hand-audited trust list of guaranteed-immutable/stable built-ins; every
UDF and every unknown built-in abstains. A miss is a cardinal false-allow, so
the set is deliberately small and grows example-by-example (D4-05). The accepted
residual: a UDF shadowing a built-in name via ``search_path`` is admitted by the
bare-name match (T-11-09 / D-02a, recorded in 11-ASSUMPTIONS.md).

``pglast`` is imported INSIDE the function (D-01a / Pitfall 4): the analyzer
registry is imported on every hook invocation, so a module-top ``import pglast``
(a C-extension package) would cost latency on every Bash call. The import and
the parse are both wrapped to abstain-never-crash on any error (D-01a / PKG-06):
``ImportError`` (dep missing) and a broad ``Exception`` around the parse
(``ParseError`` plus a defensive C-extension catch-all).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..verdict import Verdict

if TYPE_CHECKING:
    import pglast.ast as _ast

# --- The three locked allowlists (D-02 / D-04's planner deliverable) --------

#: Top-level statement node TYPES permitted as the read-only statement (D-04).
#: Any other top-level statement type -> abstain (DML/DDL/TRUNCATE/COPY/SET/
#: GRANT/CALL/DO all fall out here, not enumerated).
_ALLOWED_STMT: frozenset[str] = frozenset(
    {"SelectStmt", "VariableShowStmt", "ExplainStmt"}
)

#: Node TYPES permitted to APPEAR anywhere inside a read-only query. Derived
#: empirically from the locked SQL-01 allow corpus (the union of every
#: ``type(node).__name__`` produced by parsing it). Any node type NOT in this
#: set -> abstain: this is HOW IntoClause / LockingClause / InsertStmt /
#: UpdateStmt / DeleteStmt-in-CTE / CopyStmt etc. all fall out by construction
#: (D-16). Deliberately NOT padded with untested node types — over-abstain is
#: free; admitting a node no test exercises widens the false-allow surface.
_ALLOWED_NODE: frozenset[str] = frozenset(
    {
        "RawStmt",
        "SelectStmt",
        "VariableShowStmt",
        "ExplainStmt",
        "ResTarget",
        "ColumnRef",
        "A_Const",
        "A_Star",
        "FuncCall",
        "RangeVar",
        "A_Expr",
        "WithClause",
        "CommonTableExpr",
        "String",
        "Integer",
    }
)

#: Immutable/stable built-in functions admitted for a ``FuncCall`` (D-02).
#: Volatility classes are hand-audited (a miss is a cardinal false-allow).
#: EXPLICITLY EXCLUDED (must never be admitted): nextval, currval, setval,
#: random, clock_timestamp, txid_current, pg_read_file, pg_ls_dir,
#: pg_read_binary_file, and every UDF / unknown built-in.
_ALLOWED_FUNCS: frozenset[str] = frozenset(
    {
        "count",
        "sum",
        "avg",
        "min",
        "max",
        "length",
        "lower",
        "upper",
        "abs",
        "round",
        "trim",
        "btrim",
        "substr",
        "substring",
        "now",
    }
)

#: Built-in operator names admitted for an ``A_Expr`` node (D-04). LOAD-BEARING
#: for ``SELECT id FROM t WHERE x = 1`` (``x = 1`` is ``A_Expr`` name ``=``).
#: Still abstains on the volatile-operator vector ``a # b`` (``#`` not here).
_ALLOWED_OPERATORS: frozenset[str] = frozenset(
    {"=", "<", ">", "<=", ">=", "<>", "!=", "+", "-", "*", "/"}
)


def _funccall_admitted(node: _ast.FuncCall) -> bool:
    """A ``FuncCall`` is admitted iff its funcname is exactly ``[name]`` or
    ``['pg_catalog', name]`` with ``name`` on the immutable-builtin allowlist.

    Any other schema qualifier, multi-component shape, or unlisted name ->
    not admitted (the caller abstains). Children (``args``) are still walked by
    the caller AFTER admission, so ``count(nextval('s'))`` still abstains.
    """
    if node.funcname is None:
        return False
    comps = [c.sval for c in node.funcname]
    if len(comps) == 1:
        return comps[0] in _ALLOWED_FUNCS
    if len(comps) == 2 and comps[0] == "pg_catalog":
        return comps[1] in _ALLOWED_FUNCS
    return False


def _aexpr_admitted(node: _ast.A_Expr) -> bool:
    """An ``A_Expr`` is admitted iff its ``name`` is exactly one operator
    component on the built-in operator allowlist. A multi-component or
    unexpected shape -> not admitted (the caller abstains)."""
    if node.name is None:
        return False
    comps = [c.sval for c in node.name]
    return len(comps) == 1 and comps[0] in _ALLOWED_OPERATORS


def _walk_is_read_only(node: object) -> bool:
    """One-pass allowlist walk; ``True`` only after the ENTIRE tree walks clean.

    Abstain (return ``False``) on the FIRST violation. A per-node gate
    (FuncCall / A_Expr / ExplainStmt) never short-circuits descent: after a node
    is admitted, EVERY field is still iterated, so a dangerous child (e.g.
    ``count(nextval('s'))`` or an EXPLAIN wrapping a mutating query) is caught.
    """
    import pglast.ast as A

    if isinstance(node, A.Node):
        if type(node).__name__ not in _ALLOWED_NODE:
            return False
        if isinstance(node, A.FuncCall) and not _funccall_admitted(node):
            return False
        if isinstance(node, A.A_Expr) and not _aexpr_admitted(node):
            return False
        if isinstance(node, A.ExplainStmt) and node.options:
            # Non-empty options means an executing/altering EXPLAIN (ANALYZE,
            # PG17 SERIALIZE, COSTS, ...) -> abstain. Empty/None options is a
            # plain EXPLAIN; descend into stmt.query via the field iteration.
            return False
        # Descend into EVERY field of an admitted node (no short-circuit).
        for field in node:
            if not _walk_is_read_only(getattr(node, field)):
                return False
        return True
    if isinstance(node, (tuple, list)):
        for child in node:
            if not _walk_is_read_only(child):
                return False
        return True
    # Scalars (int / str / enum / None) are leaves.
    return True


def analyze_sql(source: str) -> Verdict | None:
    """Prove ``source`` is a single read-only SQL statement, else abstain.

    Returns ``Verdict("allow", "read-only sql", "sql")`` only when ``source``
    parses to EXACTLY one statement whose whole AST passes the allowlist walk;
    otherwise ``None`` (abstain). Never raises: a missing dep, a parse error, or
    any other failure abstains (D-01a / PKG-06).
    """
    try:
        import pglast
    except ImportError:
        return None  # dep missing -> abstain, never crash (D-01a/PKG-06)
    try:
        rawstmts = pglast.parse_sql(source)  # tuple[RawStmt, ...]
    except Exception:
        return None  # ParseError + defensive C-extension catch-all (D-15)
    if len(rawstmts) != 1:
        return None  # 0 = empty/comment-only; >=2 = multi-statement
    if type(rawstmts[0].stmt).__name__ not in _ALLOWED_STMT:
        return None  # top-level statement type not on the allowlist
    if not _walk_is_read_only(rawstmts[0]):
        return None  # a node/function/operator/EXPLAIN-option violated the walk
    return Verdict("allow", "read-only sql", "sql")

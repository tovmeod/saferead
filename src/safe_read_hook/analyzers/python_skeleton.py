"""Read-only Python source analyzer (PY-01).

``analyze_python(source) -> Verdict | None`` is the second real consumer of the
Phase-4 analyzer seam (after Phase 11's SQL analyzer, D4-08). It parses a Python
source string with stdlib ``ast`` and proves the source is read-only by an
ALLOWLIST over AST node TYPES + a builtin-call allowlist + a method-name
allowlist + a module allowlist, abstaining (returning ``None``) on the FIRST
unknown node / call / method / import (D-16 polarity). It NEVER denies and never
crashes.

Why allowlist polarity (D-16, not a denylist): a denylist of dangerous operations
defaults to ALLOW on any vector not enumerated. An allowlist polarity abstains
on the first unenumerated node, so ``open``, ``exec``, ``eval``, ``__import__``,
``getattr``, ``setattr`` all fall out by construction (not in the builtin
allowlist), ``os`` falls out by omission (not in the module allowlist), and
dunder attribute access is explicitly gated to fail regardless of the method
allowlist (SC#2).

Why a real parse tree (ast): an allowlist over node types + node-gate functions
closes genuinely dangerous surface (dunder attributes, rebind of builtins/modules,
Store-context mutations, subscript/call escapes) that a simpler regex cannot.

The module exposes a **parameterized core** ``_analyze_python(source, *,
allowed_builtins, allowed_methods, allowed_modules)`` AND a **floor-bound seam
entry** ``analyze_python(source)`` (the 1-arg form ``ANALYZERS["python"]``
binds, called by the reader). This split is the central architectural decision
of the phase — without it, PY-03/PY-04 config wiring (Plan 02/03) silently
no-ops (sql.py is parameterless; copying it gets this wrong).

``ast`` is imported INSIDE the function (Pitfall 5): the reader top-imports
``ANALYZERS`` and runs on every hook invocation, so a module-top ``import ast``
would pull ``ast`` onto the common read path and cost latency on every Bash
call. Keeping the import lazy honors the project's low-latency constraint.
Abstain-never-crash on any parse error or exception (D-15 / PKG-06).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..config import _BUILTIN_PY_METHODS, _BUILTIN_PY_MODULES
from ..verdict import Verdict

if TYPE_CHECKING:
    import ast

# --- The three locked allowlists (D-01 / D-02 / D-03's planner deliverable) --

#: Builtin function names admitted for bare-name calls (D-01).
#: Deliberately conservative/small; growth is example-by-example (D4-05).
#: EXPLICITLY EXCLUDED: open, exec, eval, compile, __import__, input,
#: globals, locals, vars, getattr, setattr.
_FLOOR_BUILTINS: frozenset[str] = frozenset(
    {
        "print",
        "len",
        "range",
        "sorted",
        "abs",
        "min",
        "max",
        "sum",
        "round",
    }
)

#: Method names admitted for attribute access (D-01). Per-method assertions
#: that the operation is read-only for the types that have it.
#: EXPLICITLY EXCLUDED: write, append, update, add, sort, pop, insert, remove,
#: clear, extend, discard, format, format_map.
#:
#: The method + module floors live in ``config`` as the SINGLE floor home (PY-03,
#: D-06): config wires the project-widenable ``[python]`` allowlists on top of
#: these exact sets, so re-export them here (no import cycle — config imports only
#: stdlib). ``test_python_floor_parity_no_drift`` pins this equality.
_FLOOR_METHODS: frozenset[str] = _BUILTIN_PY_METHODS

#: Module names admitted for import (D-02). Deliberately small and audited
#: per-module; growth is example-by-example. Single floor home in ``config``.
_FLOOR_MODULES: frozenset[str] = _BUILTIN_PY_MODULES

#: AST node TYPES permitted anywhere inside a read-only Python source
#: (D-03's planner deliverable). Derived from the locked PY-01 allow corpus
#: (the union of every ast node type produced by parsing it). Any node type
#: NOT in this set -> abstain (D-16). Deliberately NOT padded with untested
#: node types — over-abstain is free; admitting a node no test exercises
#: widens the false-allow surface. Deliberately ABSENT (over-abstain is free):
#: While, With, Try, FunctionDef, ClassDef, Lambda, Return, Global, Nonlocal,
#: Delete.
_ALLOWED_NODE: frozenset[str] = frozenset(
    {
        "Module",
        "Expr",
        "Constant",
        "Name",
        "Load",
        "Store",
        "Tuple",
        "List",
        "Set",
        "Dict",
        "BinOp",
        "BoolOp",
        "UnaryOp",
        "Compare",
        "Add",
        "Sub",
        "Mult",
        "Div",
        "FloorDiv",
        "Mod",
        "Pow",
        "And",
        "Or",
        "Not",
        "USub",
        "UAdd",
        "Eq",
        "NotEq",
        "Lt",
        "LtE",
        "Gt",
        "GtE",
        "Is",
        "IsNot",
        "In",
        "NotIn",
        "JoinedStr",
        "FormattedValue",
        "ListComp",
        "SetComp",
        "DictComp",
        "GeneratorExp",
        "comprehension",
        "Subscript",
        "Slice",
        "Call",
        "Attribute",
        "keyword",
        "Assign",
        "AugAssign",
        "NamedExpr",
        "For",
        "If",
        "Import",
        "ImportFrom",
        "alias",
    }
)


def _call_admitted(
    node: object, allowed_builtins, allowed_methods, allowed_modules
) -> bool:
    """A Call is admitted iff its callee is admitted.

    Callee rules:
    - Name: the id must be in allowed_builtins.
    - Attribute: attr must not start with "__"; if value is Name in
      allowed_modules, True (module method call); else attr must be in
      allowed_methods (object method call).
    - Any other callee (Subscript, Call, Lambda): False (escape).

    Returns True if admitted; the caller may still descend and find unsafe
    children (so a dangerous call like print(open(...)) is still caught).
    """
    import ast

    if isinstance(node, ast.Call):
        callee = node.func
    else:
        return False  # type narrowing

    if isinstance(callee, ast.Name):
        return callee.id in allowed_builtins
    if isinstance(callee, ast.Attribute):
        if callee.attr.startswith("__"):
            return False  # dunder always blocked
        if isinstance(callee.value, ast.Name):
            if callee.value.id in allowed_modules:
                return True  # module.method allowed
        return callee.attr in allowed_methods  # method allowed if in list
    # Subscript, Call, Lambda, or other -> escape attempt, deny
    return False


def _attribute_admitted(node: object, allowed_methods, allowed_modules) -> bool:
    """An Attribute is admitted iff it is Load-context, not dunder, and allowed.

    Context rule: must be Load (not Store/Del mutation).
    Dunder rule: attr must not start with "__" (SC#2 dunder always blocked).
    Then:
    - If value is Name in allowed_modules: True (module.attr allowed).
    - Else attr must be in allowed_methods.

    Returns True if admitted; the caller may still descend and find unsafe
    children.
    """
    import ast

    if not isinstance(node, ast.Attribute):
        return False  # type narrowing

    # Load-only context.
    if not isinstance(node.ctx, ast.Load):
        return False  # Store/Del -> mutation, block

    # No dunder attributes.
    if node.attr.startswith("__"):
        return False  # SC#2: dunder always blocked

    # Module attribute access.
    if isinstance(node.value, ast.Name):
        if node.value.id in allowed_modules:
            return True

    # Method name in allowlist.
    return node.attr in allowed_methods


def _import_admitted(node: object, allowed_modules) -> bool:
    """An Import or ImportFrom is admitted iff all imported modules are allowed.

    For Import: check each alias.name's top component.
    For ImportFrom: reject if relative (level > 0), reject if *, otherwise check
    the module top component.

    Returns True if admitted; False (abstain) otherwise.
    """
    import ast

    if isinstance(node, ast.Import):
        # Each alias.name is a module like "math" or "os.path"
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top not in allowed_modules:
                return False
        return True

    if isinstance(node, ast.ImportFrom):
        # Relative imports (from . import x) abstain.
        if node.level and node.level > 0:
            return False
        # from x import * abstains.
        if node.module is None:
            return False
        for alias in node.names:
            if alias.name == "*":
                return False
        # Check the module top component.
        top = node.module.split(".")[0]
        return top in allowed_modules

    return False


def _walk_is_read_only(
    node: ast.AST, allowed_builtins, allowed_methods, allowed_modules
) -> bool:
    """One-pass allowlist walk; True only after the ENTIRE tree walks clean.

    Abstain (return False) on the FIRST violation. A per-node gate
    (Call / Attribute / Name / Subscript / Import) never short-circuits descent:
    after a node is admitted, EVERY child is still iterated, so dangerous
    children are caught.

    Cardinal Pattern 3 gates on EVERY Name:
    - Abstain if id starts with "__" (dunder names like __builtins__, __import__).
    - Abstain if in Store context AND id is in allowed_builtins or allowed_modules
      (rebind gate: print = open, len = exec, math = __builtins__).

    Pattern 4: Subscript in non-Load context (d['k'] = 1) abstains.
    """
    import ast

    # Node type allowed?
    node_type_name = type(node).__name__
    if node_type_name not in _ALLOWED_NODE:
        return False

    # Per-node gates (none short-circuit; all descend after admission).

    # Call: callee must be admitted.
    if isinstance(node, ast.Call):
        if not _call_admitted(node, allowed_builtins, allowed_methods, allowed_modules):
            return False

    # Attribute: Load-only, not dunder, method/module in allowlist.
    if isinstance(node, ast.Attribute):
        if not _attribute_admitted(node, allowed_methods, allowed_modules):
            return False

    # Name (CARDINAL Pattern 3):
    # - Dunder names always abstain (bare __builtins__, __import__).
    # - Store-context rebind of builtin/module names abstains.
    if isinstance(node, ast.Name):
        if node.id.startswith("__"):
            return False  # dunder name -> abstain
        if isinstance(node.ctx, ast.Store):
            if node.id in allowed_builtins or node.id in allowed_modules:
                return False  # rebind of trusted name -> abstain

    # Subscript (Pattern 4): non-Load context (d['k'] = 1) abstains.
    if isinstance(node, ast.Subscript):
        if not isinstance(node.ctx, ast.Load):
            return False

    # Import/ImportFrom: modules in allowlist.
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        if not _import_admitted(node, allowed_modules):
            return False

    # Descend into EVERY child (using ast.iter_child_nodes to avoid getattr).
    for child in ast.iter_child_nodes(node):
        if not _walk_is_read_only(
            child, allowed_builtins, allowed_methods, allowed_modules
        ):
            return False

    return True


def _analyze_python(
    source: str,
    *,
    allowed_builtins: frozenset[str],
    allowed_methods: frozenset[str],
    allowed_modules: frozenset[str],
) -> Verdict | None:
    """Parameterized core analyzer.

    Parses source with ast and proves read-only via an ALLOWLIST walk,
    returning Verdict("allow", "read-only python", "python") only when the
    whole tree walks clean; otherwise None (abstain).

    Never raises: a parse error or any other exception abstains
    (D-15 / PKG-06).
    """
    import ast

    try:
        tree = ast.parse(source)
    except Exception:
        return None  # SyntaxError + defensive catch-all (D-15/PKG-06)

    if not _walk_is_read_only(tree, allowed_builtins, allowed_methods, allowed_modules):
        return None

    return Verdict("allow", "read-only python", "python")


def analyze_python(source: str) -> Verdict | None:
    """Floor-bound seam entry: analyze with the locked floor allowlists.

    This is the 1-arg form called via ANALYZERS["python"], using the
    floor-bound defaults. Phase 12 Plan 02 / PY-03 will add config wiring
    to override these defaults via _analyze_python.
    """
    return _analyze_python(
        source,
        allowed_builtins=_FLOOR_BUILTINS,
        allowed_methods=_FLOOR_METHODS,
        allowed_modules=_FLOOR_MODULES,
    )

"""Boundary tests for the read-only Python analyzer (PY-01 / TEST-02).

``analyze_python`` proves a Python source is read-only by an ALLOWLIST over AST
node TYPES + a builtin-call allowlist + a method-name allowlist + a module
allowlist, abstaining (returning ``None``) on the FIRST unknown node / call /
method / import (D-16 polarity).

These tests exercise ``analyze_python`` DIRECTLY (not through a python recognizer
— that is Phase 12, Plan 02). The locked D-01/D-02/D-03 read-only-vs-abstain set:
ALLOW provably read-only Python (literals, arithmetic, comprehensions, print,
allowlisted builtin/method calls, allowlisted-module import, assignment + for/if
control flow); ABSTAIN on every dangerous call (open, exec, eval, __import__,
getattr, setattr), dunder attribute access, obfuscation (rebind, subscript
escapes), mutation (assignment to attributes/subscripts, mutating methods), and
unparseable Python.

Test-name contract (load-bearing, MEMORY.md silent-skip lesson, D8-09): the
``-k`` filter selects on the substrings ``python`` + ``allow``/``abstain``. A
test whose name misses these substrings is silently NOT run.
"""

from __future__ import annotations

import pytest

from sash.analyzers import ANALYZERS
from sash.analyzers.python_skeleton import analyze_python
from sash.verdict import Verdict

# --- ALLOW corpus: provably read-only Python source -------------------------

_PY_ALLOW = [
    "42",
    "1 + 2 * 3",
    "a and b or not c",
    "1 < x <= 10",
    'f"{x} val {y!r:>3}"',
    "[i*2 for i in range(10) if i > 2]",
    "{k: v for k, v in items}",
    "{i for i in xs}",
    "sum(i for i in xs)",
    "print('hi', len([1,2]))",
    "'abc'.upper().strip()",
    "s.split(',')",
    "d.get('k')",
    "import math",
    "from datetime import date",
    "from json import dumps",
    "x = 1\ny = x + 2",
    "for i in range(3):\n    if i: print(i)",
    "a, b = 1, 2",
    "math.sqrt(2)",
    "math.pi",
    "(n := 10)",
]


@pytest.mark.parametrize("source", _PY_ALLOW)
def test_python_readonly_allow(source: str) -> None:
    """A provably read-only Python source -> allow, tag ``python``."""
    verdict = analyze_python(source)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "python"


# --- ABSTAIN corpus: the E2 dangerous/obfuscation/mutation/CARDINAL vectors --
#
# Every entry MUST abstain (return None). A false-allow here is the cardinal
# failure. Covers: dangerous imports, dangerous calls, dunder attributes,
# obfuscation (rebind/subscript), mutation (assignment/mutating methods),
# non-allowlisted calls/imports, and unparseable input.

_PY_ABSTAIN = [
    # Dangerous imports
    "import os",
    "import subprocess",
    "import sys",
    "import shutil",
    "import socket",
    "from os import path",
    "from . import x",
    "from json import *",
    # Dangerous calls
    "open('f','w')",
    "open('f')",
    "exec('x')",
    "eval('1')",
    "compile('','','exec')",
    "__import__('os')",
    "input()",
    "globals()",
    "locals()",
    "vars()",
    # Dunder attribute access (obfuscation)
    "getattr(o,'__class__')",
    "setattr(o,'x',1)",
    "x.__class__",
    "o.__class__.__globals__",
    "().__class__.__bases__",
    "''.__class__.__mro__",
    "'{0.__class__}'.format(o)",
    # CARDINAL rebind corpus
    "__builtins__",
    "math = __builtins__\nmath.open('f','w')",
    "(json := __builtins__)",
    "m = __import__\nm('os')",
    "import math\nmath = __builtins__\nmath.system('x')",
    "print = open\nprint('f','w')",
    "len = exec\nlen('x')",
    # Mutation (assignment to attributes/subscripts, mutating methods)
    "obj.x = 1",
    "d['k'] = 1",
    "obj.x += 1",
    "lst.append(1)",
    "s.add(1)",
    "d.update(x)",
    "lst.sort()",
    "lst.pop()",
    "f.write('x')",
    # Non-allowlisted / not-admitted
    "foo()",
    "obj.bogus()",
    "import numpy",
    "def f(): pass",
    "while True: pass",
    "with open('f') as h: pass",
    "lambda: 1",
    # Subscript-callee escape
    "[open][0]('f','w')",
    "d['o']('f','w')",
    # Syntax error
    "x = (",
]


@pytest.mark.parametrize("source", _PY_ABSTAIN)
def test_python_abstain(source: str) -> None:
    """Every dangerous/obfuscation/mutation/unparseable Python -> abstain."""
    assert analyze_python(source) is None


# --- SyntaxError should never raise; abstain instead -------------------------


def test_python_never_raises_on_syntaxerror() -> None:
    """SyntaxError -> abstain, never raise."""
    result = analyze_python("x = (")
    assert result is None


# --- registration: ANALYZERS["python"] is wired and callable ----------------


def test_python_registered_and_callable() -> None:
    """``ANALYZERS["python"]`` is registered and returns ``Verdict | None``."""
    assert "python" in ANALYZERS
    analyzer = ANALYZERS["python"]
    assert callable(analyzer)
    result = analyzer("42")
    assert result is None or isinstance(result, Verdict)


# --- End-to-end live-reader path (the vertical slice proof) ------------------


def test_python_fold_readonly_allows_end_to_end() -> None:
    """END-TO-END: python -c "1+1" auto-allows through engine.fold.

    This proves the vertical slice is live: the floor-bound Python analyzer
    goes LIVE the moment this policy lands, and `python -c "<floor-readonly>"`
    auto-allows end-to-end through `engine.fold` (tag `"python"`). This is the
    MVP vertical-slice claim: the reader's `_SUBLANG_CMDS` dispatch goes LIVE.
    """
    from sash.engine import Context, fold
    from sash.tokenizer import tokenize

    segments = tokenize('python -c "1+1"').segments
    verdict = fold(segments, Context(cwd="/x"))
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "python"


def test_python_fold_dangerous_abstains_end_to_end() -> None:
    """END-TO-END: python -c "import os" abstains through engine.fold.

    Proves the analyzer's import gate works through the live path.
    """
    from sash.engine import Context, fold
    from sash.tokenizer import tokenize

    segments = tokenize('python -c "import os"').segments
    verdict = fold(segments, Context(cwd="/x"))
    assert verdict is None  # abstain

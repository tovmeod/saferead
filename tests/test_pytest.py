"""Boundary tests for the ``pytest`` recognizer (REC-07 / TEST-02).

The cardinal axis is the allow/abstain BOUNDARY for ``pytest``: a recognized
LAUNCHER shape (bare/path ``pytest``; ``python[3] -m pytest``; ``uv run
[flags] pytest``; ``uv run python -m pytest``; any with an env-assign prefix)
auto-allows arbitrary tasks/flags EXCEPT a redirection/injection DENYLIST
(``-p``/``-c``/``--config-file``/``--rootdir``/``-o``/``--override-ini``/
``--pdb``/``--pdbcls``/``--basetemp``) matched in split / glued / ``=value``
forms (D8-04). ``allow`` here is OPT-IN TRUST (D8-01) — pytest executes project
code — NOT a proof of read-only-ness.

D8-03 ACCEPTED RESIDUALS that MUST stay ALLOW (do not "fix" them):
``uv run --with <pkg> pytest`` (network install) and env-assign injection
prefixes (``PYTHONPATH=``/``LD_PRELOAD=``/``PYTHONSTARTUP=``).

Test-name contract (load-bearing, MEMORY.md silent-skip lesson): the ``-k``
filter selects on the substrings ``pytest``, ``allow``, ``abstain``,
``launcher``, ``redirection``. A test whose name misses every substring is
silently NOT run.
"""

from __future__ import annotations

import pytest

from sash.context import Context
from sash.engine import fold
from sash.recognizers.pytest_runner import recognize_pytest


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- launcher shapes allow ------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        # bare / path / python-m / uv launcher shapes (D8-02)
        "pytest",
        "pytest tests/",
        "pytest foo.py::test_x",
        ".venv/bin/pytest",
        "python -m pytest",
        "python3 -m pytest",
        "/usr/bin/python3 -m pytest -v",
        "uv run pytest",
        "uv run -q pytest",
        "uv run python -m pytest",
        "PYTEST_ADDOPTS=-q pytest",
        "FOO=bar pytest -k x",
        # benign flags (NOT redirection) — arbitrary args trusted (D8-04)
        "pytest -k mytest",
        "pytest -m slow -x -v",
        "pytest -q --tb=short",
        "pytest --maxfail=1",
    ],
)
def test_pytest_launcher_allow(segment: str, ctx: Context) -> None:
    v = recognize_pytest(segment, ctx)
    assert v is not None
    assert v.decision == "allow"
    assert v.tag == "pytest"


@pytest.mark.parametrize(
    "segment",
    [
        # D8-03 ACCEPTED RESIDUALS — these MUST stay allow, do not "fix"
        "uv run --with requests pytest",
        "PYTHONPATH=/x pytest",
        "LD_PRELOAD=/x.so pytest",
        "PYTHONSTARTUP=/x pytest",
    ],
)
def test_pytest_launcher_accepted_residual_allow(segment: str, ctx: Context) -> None:
    v = recognize_pytest(segment, ctx)
    assert v is not None
    assert v.decision == "allow"
    assert v.tag == "pytest"


@pytest.mark.parametrize(
    "segment",
    [
        # over-block DISCRIMINATION pins (must NOT match the denylist)
        "pytest --pyargs pkg",  # --pyargs is NOT --pdb
        "pytest -k pdbtest",  # -k value, NOT --pdb
    ],
)
def test_pytest_launcher_no_overblock_allow(segment: str, ctx: Context) -> None:
    v = recognize_pytest(segment, ctx)
    assert v is not None
    assert v.decision == "allow"
    assert v.tag == "pytest"


@pytest.mark.parametrize(
    "segment",
    [
        "pytest >/dev/null",
        "pytest 2>&1",
        "pytest >/tmp/log",
    ],
)
def test_pytest_redirection_safe_tail_allow(segment: str, ctx: Context) -> None:
    v = recognize_pytest(segment, ctx)
    assert v is not None
    assert v.decision == "allow"
    assert v.tag == "pytest"


# --- redirection / injection denylist abstain (three token forms) ---------


@pytest.mark.parametrize(
    "segment",
    [
        # -p plugin load: split + glued
        "pytest -p myplugin",
        "pytest -pmyplugin",
        # -c / --config-file: split + glued + =value + long split
        "pytest -c custom.ini",
        "pytest -ccustom.ini",
        "pytest --config-file=custom.ini",
        "pytest --config-file custom.ini",
        # --rootdir: =value + split
        "pytest --rootdir=/x",
        "pytest --rootdir /x",
        # -o / --override-ini: split + glued + =value
        "pytest -o addopts=x",
        "pytest -oaddopts=x",
        "pytest --override-ini=addopts=x",
        # --pdb / --pdbcls: bare + =value + split
        "pytest --pdb",
        "pytest --pdbcls=mod:Cls",
        "pytest --pdbcls mod:Cls",
        # --basetemp: =value + split
        "pytest --basetemp=/x",
        "pytest --basetemp /x",
        # a blocked flag reached THROUGH a launcher prefix
        "uv run pytest -p plug",
        "python -m pytest --rootdir /x",
    ],
)
def test_pytest_redirection_denylist_abstain(segment: str, ctx: Context) -> None:
    assert recognize_pytest(segment, ctx) is None


@pytest.mark.parametrize(
    "segment",
    [
        'pytest "$(id)"',  # tokenizer abstains on the expansion
        "pylint foo",  # non-pytest leading word -> wrong tool
    ],
)
def test_pytest_launcher_non_pytest_abstain(segment: str, ctx: Context) -> None:
    assert recognize_pytest(segment, ctx) is None


# --- live fold-path wiring (mirrors test_find.py:103-111) ------------------


def test_pytest_allow_through_fold_launcher(ctx: Context) -> None:
    v = fold(["pytest -k x"], ctx)
    assert v is not None
    assert v.decision == "allow"


def test_pytest_redirection_through_fold_abstain(ctx: Context) -> None:
    assert fold(["pytest -p evil"], ctx) is None

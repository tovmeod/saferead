r"""Boundary tests for the ``python`` recognizer (PY-02 / TEST-02).

``recognize_python`` owns the bash argv surface for Python invocation: it scans
the launcher prefix (direct ``python``/``python3``/versioned ``python3.NN``;
``uv run`` python forms; ``uv run <script.py>`` direct), audits the post-exe
tail (benign interpreter flags ride along; ``-c`` captured exactly once; a
single readable script path read + bounded), strips ONE shell-quote layer off a
``-c`` value, fences the redirect tail, and DISPATCHES the extracted source to
the PARAMETERIZED core ``_analyze_python`` with ``ctx.config.python_allowed_*``.
An allow is re-wrapped with THIS recognizer's tag ``"python"`` (dispatch, NOT
engine re-fold — T-11-15).

CARDINAL abstains complete from this slice: ``uv run --with`` (install),
``uvx``/``uv tool run``, ``python -m``, stdin/REPL, other runner prefixes,
env-assign prefix, unknown flags, multi-``-c``, unsafe outer redirect, and a
non-regular / oversized / unreadable script file.

Test-name contract (MEMORY.md silent-skip lesson): ``-k`` selects on the
substrings ``python`` + ``allow``/``abstain``. Tests assert the recognizer
VERDICT (the contract) — never an intermediate extracted source.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from safe_read_hook.config import builtin_config
from safe_read_hook.context import Context
from safe_read_hook.recognizers.python import recognize_python


@pytest.fixture
def ctx() -> Context:
    """Floor config: python_allowed_modules == the built-in floor (no os)."""
    return Context(cwd="/x")


@pytest.fixture
def ctx_widened() -> Context:
    """A ctx whose project-widened config admits ``os`` (PY-04 path)."""
    base = builtin_config()
    widened = replace(
        base, python_allowed_modules=base.python_allowed_modules | {"os"}
    )
    return Context(cwd="/x", config=widened)


@pytest.fixture
def readonly_script(tmp_path) -> str:
    """A readable, floor-read-only .py script."""
    p = tmp_path / "ro.py"
    p.write_text("print(1)\nx = 1\n", encoding="utf-8")
    return str(p)


@pytest.fixture
def oversized_script(tmp_path) -> str:
    """A readable .py script larger than the 64 KiB read cap."""
    p = tmp_path / "big.py"
    p.write_text("x = 1\n" + ("# pad\n" * 20000), encoding="utf-8")  # > 65536 B
    return str(p)


@pytest.fixture
def missing_script(tmp_path) -> str:
    """A path that does not exist (stat fails -> abstain)."""
    return str(tmp_path / "nope.py")


# --- ALLOW: -c shapes, versioned exe, benign flag, uv run ------------------


@pytest.mark.parametrize(
    "segment",
    [
        'python -c "1+1"',
        'python3 -c "print(1)"',
        'python3.12 -c "len([1])"',
        'python -O -c "1"',
        'uv run python -c "1"',
    ],
)
def test_python_recognizer_allow_inline(segment: str, ctx: Context) -> None:
    verdict = recognize_python(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "python"


# --- ALLOW: readable read-only script-file paths ---------------------------


@pytest.mark.parametrize("template", ["python {p}", "uv run python {p}", "uv run {p}"])
def test_python_recognizer_allow_script(
    template: str, readonly_script: str, ctx: Context
) -> None:
    verdict = recognize_python(template.format(p=readonly_script), ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "python"


# --- ABSTAIN: the CARDINAL rejection set (static segments) -----------------


@pytest.mark.parametrize(
    "segment",
    [
        'uv run --with requests python -c "1"',  # install = state mutation
        "uvx ruff",  # downloads + runs a tool
        "uv tool run x",  # downloads + runs a tool
        "python -m json.tool",  # arbitrary module
        "python -",  # stdin
        "python",  # bare REPL
        'poetry run python -c "1"',  # other runner prefix
        'PYTHONPATH=/x python -c "1"',  # env-assign prefix (tighter than pytest)
        'python --badflag -c "1"',  # unknown flag (allowlist polarity)
        'python -c "1" >/etc/passwd',  # unsafe outer redirect
        'python -c "import os"',  # read-only-fail through the floor analyzer
        'python -c "1" -c "2"',  # multi -c (early-dispatch trap)
    ],
)
def test_python_recognizer_abstain_static(segment: str, ctx: Context) -> None:
    assert recognize_python(segment, ctx) is None


# --- ABSTAIN: bounded script-file read -------------------------------------


def test_python_recognizer_abstain_missing_script(
    missing_script: str, ctx: Context
) -> None:
    assert recognize_python(f"python {missing_script}", ctx) is None


def test_python_recognizer_abstain_non_regular_script(ctx: Context) -> None:
    # /dev/zero is a character device, not S_ISREG -> abstain (no hot-path hang).
    assert recognize_python("python /dev/zero", ctx) is None


def test_python_recognizer_abstain_oversized_script(
    oversized_script: str, ctx: Context
) -> None:
    assert recognize_python(f"python {oversized_script}", ctx) is None


# --- Coexistence with the byte-locked reader path --------------------------


def test_python_recognizer_coexistence_tag(ctx: Context) -> None:
    """Plain ``python -c`` allow carries tag ``"python"`` from this recognizer."""
    verdict = recognize_python('python -c "1+1"', ctx)
    assert verdict is not None
    assert verdict.tag == "python"


# --- Config-widened dispatch threads ctx.config through the core -----------


def test_python_recognizer_config_widened_module_allow_vs_floor_abstain(
    ctx: Context, ctx_widened: Context
) -> None:
    """With a widened config ``import os`` allows; with the floor it abstains."""
    segment = 'python -c "import os"'
    widened = recognize_python(segment, ctx_widened)
    assert widened is not None
    assert widened.decision == "allow"
    assert widened.tag == "python"
    assert recognize_python(segment, ctx) is None

"""Boundary tests for the read-only ``find`` recognizer (REC-04 / TEST-02).

The cardinal axis is the allow/abstain BOUNDARY for ``find``: a command whose
predicates are ALL on a read-only allowlist (test predicates + stdout actions
``-print``/``-print0``/``-ls``/``-quit``/``-prune``) auto-allows, while EVERY
mutating or exec action abstains by ALLOWLIST OMISSION (D-04) — there is no
``-exec``/``-delete``/``-fprint*`` denylist. A predicate word not on the
allowlist is the abstain trigger, which closes the file-writing ``-fprint``/
``-fprintf``/``-fprint0``/``-fls`` (B4) family AND any future GNU action by
construction.

Value-bearing predicates (``-mtime -7``, ``-size +100M``) consume their next
token as an OPAQUE value (Pitfall 3) so a value starting with ``-``/``+`` is
never mis-evaluated as a predicate.

Test-name contract (load-bearing, MEMORY.md silent-skip lesson): the ``-k``
filter selects on the substrings ``find``, ``readonly``/``allow``, ``abstain``,
``mutating``. A test whose name misses every substring is silently NOT run.
"""

from __future__ import annotations

import pytest

from safe_read_hook.config import ResolvedConfig
from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers.find import recognize_find


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- read-only allow ------------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "find .",
        "find . -name '*.py'",
        "find /x -type f -print",
        "find . -type f -print0",
        "find . -mtime -7",
        "find . -size +100M -print0",
        "find . -maxdepth 2 -ls",
        r"find . \( -name a -o -name b \)",
        "find . -empty -print",
        "find . -newer x -print",
        "find . -type f >/tmp/list",
    ],
)
def test_find_readonly_predicates_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_find(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "find"


# --- mutating / exec / write actions abstain ------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "find . -delete",
        r"find . -exec rm {} \;",
        r"find . -execdir sh -c x \;",
        r"find . -ok rm {} \;",
        r"find . -okdir rm {} \;",
        "find . -fprint out",
        "find . -fprintf out fmt",
        "find . -fprint0 out",
        "find . -fls out",
        r"find . -newer x -exec rm {} \;",
    ],
)
def test_find_mutating_actions_abstain(segment: str, ctx: Context) -> None:
    assert recognize_find(segment, ctx) is None


# --- unknown predicate + tokenizer abstain --------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "find . -bogus",
        "find . -files0-from list",
        "find . -name",  # value-bearing predicate with no value -> malformed
        'find . -name "$(id)"',  # tokenizer abstains on the expansion
        "find . -type f >/etc/passwd",  # non-safe redirect target
    ],
)
def test_find_unknown_or_ambiguous_abstain(segment: str, ctx: Context) -> None:
    assert recognize_find(segment, ctx) is None


# --- live fold-path wiring (Task 2 analog) --------------------------------


def test_find_allow_through_fold_readonly(ctx: Context) -> None:
    verdict = fold(["find . -name x"], ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


def test_find_mutating_through_fold_abstain(ctx: Context) -> None:
    assert fold(["find . -delete"], ctx) is None


# ---------------------------------------------------------------------------
# REC-08: read-root gating in find.py (14-02)
# Test names contain "root" so -k "root" selects them all.
# ---------------------------------------------------------------------------


def _find_root_ctx(roots: frozenset[str] | None, cwd: str = "/work") -> Context:
    """Return a Context with local_allowed_roots set for root-gate tests."""
    return Context(
        cwd=cwd,
        config=ResolvedConfig(
            protected_branches=frozenset({"master", "main"}),
            gated_subcommands=frozenset({"add", "commit", "stash"}),
            disabled_recognizers=frozenset(),
            local_allowed_roots=roots,
        ),
    )


# --- root: starting path under allowed root -> allow ---


def test_find_root_allow_absolute_starting_path_under_root() -> None:
    """find /allowed -name x with root={'/allowed'} -> allow."""
    ctx = _find_root_ctx(frozenset({"/allowed"}), cwd="/work")
    verdict = recognize_find("find /allowed -name x", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: starting path outside any root -> abstain ---


def test_find_root_abstain_absolute_starting_path_outside_root() -> None:
    """find /etc -name x with root={'/allowed'} -> abstain."""
    ctx = _find_root_ctx(frozenset({"/allowed"}), cwd="/work")
    assert recognize_find("find /etc -name x", ctx) is None


# --- root: unset (None) root list -> allow-any (no regression, D-02) ---


def test_find_root_unset_list_allows_any_path() -> None:
    """Unset roots (None) -> allow-any: find /etc -name x still allows."""
    ctx = _find_root_ctx(None, cwd="/work")
    verdict = recognize_find("find /etc -name x", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: relative starting path resolved against cwd -> allow under root ---


def test_find_root_allow_relative_starting_path_under_root() -> None:
    """find . -name x from cwd=/allowed resolves to /allowed -> allow under /allowed."""
    ctx = _find_root_ctx(frozenset({"/allowed"}), cwd="/allowed")
    verdict = recognize_find("find . -name x", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: relative starting path resolves OUTSIDE root -> abstain ---


def test_find_root_abstain_relative_starting_path_outside_root() -> None:
    """find . -name x from cwd=/outside (not under /allowed) -> abstain."""
    ctx = _find_root_ctx(frozenset({"/allowed"}), cwd="/outside")
    assert recognize_find("find . -name x", ctx) is None


# --- root: a bare path AFTER a flag predicate is still gated (WR-01 bypass) ---


def test_find_root_abstain_path_after_flag_predicate() -> None:
    """find /allowed -empty /etc/shadow: post-flag-predicate path is gated -> abstain.

    Regression for WR-01: -empty (a no-value flag predicate) must not open a hole
    that lets a following out-of-root path escape the REC-08 gate.
    """
    ctx = _find_root_ctx(frozenset({"/allowed"}), cwd="/work")
    assert recognize_find("find /allowed -empty /etc/shadow", ctx) is None


def test_find_root_allow_flag_predicate_no_extra_path() -> None:
    """find /allowed -empty (no trailing path) with root={'/allowed'} -> allow."""
    ctx = _find_root_ctx(frozenset({"/allowed"}), cwd="/work")
    verdict = recognize_find("find /allowed -empty", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: operand identification — -name VALUE not gated (D-05) ---


def test_find_root_operand_predicate_value_not_gated() -> None:
    """find /allowed -name /etc/passwd: -name's value is NOT gated as a path (D-05).

    The value '/etc/passwd' is a -name pattern, not a starting path.
    Only the starting path '/allowed' is gated; it is under root -> allow.
    """
    ctx = _find_root_ctx(frozenset({"/allowed"}), cwd="/work")
    verdict = recognize_find("find /allowed -name /etc/passwd", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: relative starting path with cwd=None -> abstain (unresolvable) ---


def test_find_root_abstain_unresolved_relative_cwd_none() -> None:
    """find . with cwd=None and set root -> abstain (relative path unresolvable)."""
    ctx = Context(
        cwd=None,
        config=ResolvedConfig(
            protected_branches=frozenset({"master", "main"}),
            gated_subcommands=frozenset({"add", "commit", "stash"}),
            disabled_recognizers=frozenset(),
            local_allowed_roots=frozenset({"/allowed"}),
        ),
    )
    assert recognize_find("find . -name x", ctx) is None


# --- root: ssh scope — relative starting path abstains pre-resolution (SC#3) ---


def test_find_root_scope_ssh_relative_starting_path_abstains() -> None:
    """read_scope='ssh': a RELATIVE starting path abstains before resolution (SC#3)."""
    ctx = Context(
        cwd="/allowed",
        config=ResolvedConfig(
            protected_branches=frozenset({"master", "main"}),
            gated_subcommands=frozenset({"add", "commit", "stash"}),
            disabled_recognizers=frozenset(),
            ssh_allowed_roots=frozenset({"/allowed"}),
        ),
        read_scope="ssh",
    )
    assert recognize_find("find . -name x", ctx) is None


def test_find_root_scope_ssh_absolute_under_root_allows() -> None:
    """read_scope='ssh': an absolute starting path under ssh_allowed_roots -> allow."""
    ctx = Context(
        cwd="/work",
        config=ResolvedConfig(
            protected_branches=frozenset({"master", "main"}),
            gated_subcommands=frozenset({"add", "commit", "stash"}),
            disabled_recognizers=frozenset(),
            ssh_allowed_roots=frozenset({"/allowed"}),
        ),
        read_scope="ssh",
    )
    verdict = recognize_find("find /allowed -name x", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"

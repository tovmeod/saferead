"""Unit tests for recognizers._pathscope: resolve_lexical + under_any_root (REC-08).

Test-name contract (MEMORY.md silent-skip lesson): the ``-k`` filter selects on
the substrings ``root``, ``resolve``, ``scope``. Every test below includes at
least one of those substrings in its name so documented filters catch them.

Behavior specification (from 14-01-PLAN.md Task 1):

resolve_lexical:
  - abs path + any cwd  -> normpath(operand)         (collapses ..  etc.)
  - rel path + cwd str  -> normpath(join(cwd, rel))
  - rel path + cwd None -> None                      (unresolvable; caller abstains)

under_any_root:
  - roots=None          -> True  (unset = allow-any, D-02)
  - resolved under root -> True  (component-boundary safe)
  - resolved == root    -> True  (exact match)
  - partial-name match  -> False (/home/me/.planningEVIL vs /home/me/.planning)
  - outside root        -> False
  - trailing slash root -> True  (normpath strips the slash; still matches children)
"""

from __future__ import annotations

from safe_read_hook.recognizers._pathscope import resolve_lexical, under_any_root

# ---------------------------------------------------------------------------
# resolve_lexical
# ---------------------------------------------------------------------------


def test_resolve_lexical_abs_path_returns_normpath_any_cwd() -> None:
    """Absolute operand -> normpath; cwd is irrelevant."""
    assert resolve_lexical("/a/../b", "/cwd") == "/b"
    assert resolve_lexical("/a/../b", None) == "/b"


def test_resolve_lexical_abs_path_collapses_dotdot() -> None:
    """Absolute operand with .. is lexically collapsed (D-04: normpath only, no FS)."""
    assert resolve_lexical("/home/user/../../etc/passwd", None) == "/etc/passwd"


def test_resolve_lexical_relative_path_joined_to_cwd() -> None:
    """Relative operand + known cwd -> normpath(join(cwd, operand))."""
    assert resolve_lexical("x/y", "/cwd") == "/cwd/x/y"


def test_resolve_lexical_relative_dotdot_collapses_against_cwd() -> None:
    """Relative .. traversal is lexically collapsed (D-04)."""
    assert resolve_lexical("../z", "/cwd/sub") == "/cwd/z"


def test_resolve_lexical_relative_path_cwd_none_returns_none() -> None:
    """Relative operand + unknown cwd -> None (unresolvable -> caller abstains)."""
    assert resolve_lexical("rel", None) is None
    assert resolve_lexical("x/y", None) is None
    assert resolve_lexical("../x", None) is None


def test_resolve_lexical_abs_path_is_already_normalized() -> None:
    """A clean absolute path is returned normalized (no change)."""
    assert resolve_lexical("/home/user/file.txt", "/other") == "/home/user/file.txt"


# ---------------------------------------------------------------------------
# under_any_root
# ---------------------------------------------------------------------------


def test_under_any_root_none_roots_is_allow_any() -> None:
    """roots=None -> True for any resolved path (D-02: unset list = allow any)."""
    assert under_any_root("/anything", None) is True
    assert under_any_root("/etc/passwd", None) is True
    assert under_any_root("/", None) is True


def test_under_any_root_path_under_root_returns_true() -> None:
    """Resolved path is a child of a root entry -> True."""
    assert (
        under_any_root("/home/me/.planning/x", frozenset({"/home/me/.planning"}))
        is True
    )


def test_under_any_root_exact_root_match_returns_true() -> None:
    """resolved == root exactly -> True (D-02 exact-equal case)."""
    assert (
        under_any_root("/home/me/.planning", frozenset({"/home/me/.planning"})) is True
    )


def test_under_any_root_component_boundary_evil_sibling_false() -> None:
    """Component-boundary check: /foo is NOT a child of /foobar (T-14-02 mitigation).

    This test pins the ANTI-PATTERN: bare startswith would wrongly return True
    for '/home/me/.planningEVIL' against root '/home/me/.planning'.
    The guarded form (startswith(root + os.sep)) must return False here.
    """
    assert (
        under_any_root("/home/me/.planningEVIL", frozenset({"/home/me/.planning"}))
        is False
    )


def test_under_any_root_outside_root_returns_false() -> None:
    """Resolved path outside the roots frozenset -> False."""
    assert under_any_root("/etc/passwd", frozenset({"/home/me"})) is False


def test_under_any_root_trailing_slash_root_normalizes_and_matches() -> None:
    """A root with a trailing slash is normpath'd; children still match."""
    assert under_any_root("/home/me/x", frozenset({"/home/me/"})) is True


def test_under_any_root_nested_child_under_root() -> None:
    """Deeply nested child of a root -> True."""
    assert (
        under_any_root(
            "/home/me/.planning/phases/14/PLAN.md", frozenset({"/home/me/.planning"})
        )
        is True
    )


def test_under_any_root_multiple_roots_one_matches() -> None:
    """Multiple roots: True when the resolved path is under at least one."""
    roots = frozenset({"/home/me/.planning", "/tmp/scratch"})
    assert under_any_root("/tmp/scratch/work.txt", roots) is True
    assert under_any_root("/home/me/.planning/x", roots) is True
    assert under_any_root("/etc/passwd", roots) is False


def test_under_any_root_empty_frozenset_returns_false() -> None:
    """Explicit empty frozenset -> False (set list restricts to zero allowed roots)."""
    assert under_any_root("/home/me/.planning/x", frozenset()) is False

"""Unit tests for the single-layer TOML config loader + ResolvedConfig (CFG-01).

Pins the built-in floor (D-08 case 1 / D-09), D-05 REPLACE-not-floor, and the
CARDINAL absent-vs-empty distinction (D-05/D-07 boundary): in a PRESENT global,
an ABSENT ``protected_branches`` key falls back to the built-in master/main
(never silently empties the protected set → no ``git commit`` false-allow), while
an EXPLICIT empty list ``[]`` is honored as the trusted user's chosen empty set.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from safe_read_hook.config import ResolvedConfig, builtin_config, load_layer


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_builtin_config_is_the_floor() -> None:
    """builtin_config() == the master/main + add/commit/stash floor (D-08 / D-09)."""
    cfg = builtin_config()
    assert cfg.protected_branches == frozenset({"master", "main"})
    assert cfg.gated_subcommands == frozenset({"add", "commit", "stash"})
    assert cfg.disabled_recognizers == frozenset()


def test_resolved_config_locked_field_names() -> None:
    """ResolvedConfig uses the LOCKED long field names (Plans 02/03 consume them)."""
    cfg = ResolvedConfig(
        protected_branches=frozenset({"release"}),
        gated_subcommands=frozenset({"commit"}),
        disabled_recognizers=frozenset({"pytest"}),
    )
    assert cfg.protected_branches == frozenset({"release"})
    assert cfg.gated_subcommands == frozenset({"commit"})
    assert cfg.disabled_recognizers == frozenset({"pytest"})


def test_resolved_config_is_frozen() -> None:
    """ResolvedConfig is immutable (frozen+slots value object)."""
    cfg = builtin_config()
    with pytest.raises(FrozenInstanceError):
        cfg.protected_branches = frozenset({"x"})  # type: ignore[misc]


def test_present_global_replaces_protected_not_unions(tmp_path: Path) -> None:
    """A present [git] protected_branches=["release"] REPLACES built-in (D-05).

    "master"/"main" are NOT present — this is replace, not a union floor.
    """
    path = _write(
        tmp_path,
        '[git]\nprotected_branches = ["release"]\n',
    )
    cfg = load_layer(path)
    assert cfg.protected_branches == frozenset({"release"})
    # gated_subcommands key is absent -> built-in fallback (cardinal, below).
    assert cfg.gated_subcommands == frozenset({"add", "commit", "stash"})


def test_absent_protected_key_falls_back_to_builtin(tmp_path: Path) -> None:
    """CARDINAL: a present global that omits protected_branches keeps master/main.

    A global that customizes only gated_subcommands must NOT silently empty the
    protected set — git commit on main must still ASK, never auto-allow.
    """
    path = _write(
        tmp_path,
        '[git]\ngated_subcommands = ["push"]\n',
    )
    cfg = load_layer(path)
    assert cfg.protected_branches == frozenset({"master", "main"})
    assert cfg.gated_subcommands == frozenset({"push"})


def test_explicit_empty_protected_is_honored(tmp_path: Path) -> None:
    """An EXPLICIT protected_branches=[] is honored as the chosen empty set (D-05)."""
    path = _write(
        tmp_path,
        "[git]\nprotected_branches = []\n",
    )
    cfg = load_layer(path)
    assert cfg.protected_branches == frozenset()
    # gated absent -> built-in.
    assert cfg.gated_subcommands == frozenset({"add", "commit", "stash"})


def test_absent_git_table_is_full_builtin(tmp_path: Path) -> None:
    """No [git] table at all -> both keys fall back to built-in."""
    path = _write(tmp_path, "[recognizers]\ndisabled = []\n")
    cfg = load_layer(path)
    assert cfg.protected_branches == frozenset({"master", "main"})
    assert cfg.gated_subcommands == frozenset({"add", "commit", "stash"})


def test_disabled_recognizers_parsed(tmp_path: Path) -> None:
    """[recognizers].disabled is coerced to a frozenset of tags."""
    path = _write(
        tmp_path,
        '[recognizers]\ndisabled = ["pytest", "gradle"]\n',
    )
    cfg = load_layer(path)
    assert cfg.disabled_recognizers == frozenset({"pytest", "gradle"})


def test_disabled_defaults_to_empty_when_absent(tmp_path: Path) -> None:
    """An absent [recognizers] table -> disabled_recognizers is empty."""
    path = _write(tmp_path, '[git]\nprotected_branches = ["main"]\n')
    cfg = load_layer(path)
    assert cfg.disabled_recognizers == frozenset()


def test_empty_file_is_full_builtin(tmp_path: Path) -> None:
    """An empty (but well-formed) TOML file resolves to the built-in floor."""
    path = _write(tmp_path, "")
    cfg = load_layer(path)
    assert cfg == builtin_config()


def test_non_list_value_raises(tmp_path: Path) -> None:
    """A malformed protected_branches (not a list) raises (entrypoint degrades)."""
    path = _write(tmp_path, '[git]\nprotected_branches = "main"\n')
    with pytest.raises((TypeError, ValueError)):
        load_layer(path)


def test_non_str_element_raises(tmp_path: Path) -> None:
    """A list with a non-string element raises (entrypoint degrades)."""
    path = _write(tmp_path, "[git]\ngated_subcommands = [1, 2]\n")
    with pytest.raises((TypeError, ValueError)):
        load_layer(path)


def test_load_layer_uses_binary_handle(tmp_path: Path) -> None:
    """load_layer feeds tomllib a BINARY handle (a text handle raises TypeError).

    ``tomllib.load`` requires bytes; a text-mode handle raises TypeError. This
    pins the PATTERNS gotcha by sentinel: had load_layer opened in text mode, a
    plain parse below would raise TypeError instead of resolving cleanly.
    """
    path = _write(tmp_path, '[git]\nprotected_branches = ["main"]\n')
    cfg = load_layer(path)  # would raise TypeError if opened in text mode
    assert cfg.protected_branches == frozenset({"main"})

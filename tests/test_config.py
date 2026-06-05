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

from safe_read_hook.config import (
    RawLayer,
    ResolvedConfig,
    builtin_config,
    load_layer,
    merge,
    resolve_config,
)


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


# --- Plan 02: narrow-only merge (CFG-02 / CFG-03) -------------------------


def _base() -> ResolvedConfig:
    """A representative resolved base: protected main, gated commit, disabled sed."""
    return ResolvedConfig(
        protected_branches=frozenset({"master", "main"}),
        gated_subcommands=frozenset({"add", "commit", "stash"}),
        disabled_recognizers=frozenset({"sed"}),
    )


def test_merge_unions_protected_branches() -> None:
    """merge unions protected_branches; base members are RETAINED (D-04)."""
    base = builtin_config()
    project = RawLayer(
        protected_branches=frozenset({"release"}),
        gated_subcommands=None,
        disabled_recognizers=None,
    )
    result = merge(base, project)
    assert result.protected_branches == frozenset({"master", "main", "release"})


def test_merge_drops_untrusted_project_gated() -> None:
    """merge IGNORES the untrusted project's gated_subcommands (CR-01).

    The gated path is NOT pure-ASK: ``recognize_git`` ALLOWs a gated subcommand on
    a non-protected branch, so a project ADD to the gated set would WIDEN the
    allow-set for state-mutating git ops (a cardinal false-allow). The project's
    ``gated_subcommands`` must therefore have ZERO effect — the merged set equals
    the trusted base exactly, with ``push`` NOT present.
    """
    base = _base()
    project = RawLayer(
        protected_branches=None,
        gated_subcommands=frozenset({"push"}),
        disabled_recognizers=None,
    )
    result = merge(base, project)
    assert result.gated_subcommands == base.gated_subcommands
    assert "push" not in result.gated_subcommands


def test_merge_adds_disabled_recognizers() -> None:
    """merge adds project disabled tags onto the base disabled set (add-only)."""
    base = _base()
    project = RawLayer(
        protected_branches=None,
        gated_subcommands=None,
        disabled_recognizers=frozenset({"pytest"}),
    )
    result = merge(base, project)
    assert result.disabled_recognizers == frozenset({"sed", "pytest"})


def test_merge_absent_keys_are_additive_identity() -> None:
    """A project layer with NO present keys -> result == base exactly (D-07/D-04).

    An absent project key contributes the EMPTY set (additive identity), the
    OPPOSITE polarity to the global layer's built-in fallback. The criterion-3
    seed: a project that supplies nothing has ZERO effect.
    """
    base = _base()
    project = RawLayer(
        protected_branches=None,
        gated_subcommands=None,
        disabled_recognizers=None,
    )
    result = merge(base, project)
    assert result == base


def test_merge_explicit_empty_sets_are_additive_identity() -> None:
    """Explicit empty project sets also contribute nothing (union with {} = base)."""
    base = _base()
    project = RawLayer(
        protected_branches=frozenset(),
        gated_subcommands=frozenset(),
        disabled_recognizers=frozenset(),
    )
    result = merge(base, project)
    assert result == base


def test_merge_never_shrinks_any_set() -> None:
    """criterion-3 invariant: every base member survives ANY project layer (D-04).

    A hostile project layer cannot remove ``main`` from protected, ``commit``
    from gated, nor ``sed`` from disabled — the schema has no remove operator,
    so union/add can only retain or add base members.
    """
    base = _base()
    # A project layer that "tries" to drop everything can only present ADD-only
    # values; absent keys are empty, so the base is fully retained.
    project = RawLayer(
        protected_branches=frozenset(),  # tries (and fails) to "clear" protected
        gated_subcommands=frozenset(),
        disabled_recognizers=frozenset(),
    )
    result = merge(base, project)
    assert base.protected_branches <= result.protected_branches
    assert base.gated_subcommands <= result.gated_subcommands
    assert base.disabled_recognizers <= result.disabled_recognizers
    assert result == base


# --- Plan 03: resolve_config never-raising D-08/D-09 orchestrator (CFG-04) ---


def _write_named(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_resolve_config_absent_both_is_builtin(tmp_path: Path) -> None:
    """D-08 case 1+2: absent global FILE + absent project FILE -> builtin_config()."""
    result = resolve_config(
        tmp_path / "no-global.toml",
        tmp_path / "no-project.toml",
    )
    assert result == builtin_config()


def test_resolve_config_absent_project_is_none(tmp_path: Path) -> None:
    """A None project_path (CLAUDE_PROJECT_DIR skipped) -> resolved base unchanged."""
    global_path = _write_named(
        tmp_path, "global.toml", '[git]\nprotected_branches = ["release"]\n'
    )
    result = resolve_config(global_path, None)
    assert result.protected_branches == frozenset({"release"})


def test_resolve_config_malformed_global_falls_to_builtin(tmp_path: Path) -> None:
    """D-09/D-10: a malformed global degrades to the built-in floor; never raises.

    Safe defaults (D-10): master/main + add/commit/stash present — the built-in
    floor restored, NOT "treat all branches as protected".
    """
    global_path = _write_named(tmp_path, "global.toml", "this is not = toml [[[")
    result = resolve_config(global_path, None)  # must not raise
    assert result == builtin_config()
    assert result.protected_branches == frozenset({"master", "main"})
    assert result.gated_subcommands == frozenset({"add", "commit", "stash"})


def test_resolve_config_malformed_project_keeps_global(tmp_path: Path) -> None:
    """D-09 per-layer blast radius: a malformed project drops, the GOOD global survives.

    The trusted global protecting only "release" survives; the malformed project
    is dropped (not crashed). Proves the project-layer blast radius.
    """
    global_path = _write_named(
        tmp_path, "global.toml", '[git]\nprotected_branches = ["release"]\n'
    )
    project_path = _write_named(tmp_path, "project.toml", "broken = = = [[[")
    result = resolve_config(global_path, project_path)  # must not raise
    assert result.protected_branches == frozenset({"release"})


def test_resolve_config_malformed_global_still_narrows_with_project(
    tmp_path: Path,
) -> None:
    """D-09: a malformed GLOBAL falls to built-in, a VALID project STILL narrows on top.

    The global try/except must fall to builtin_config() and CONTINUE to the
    project merge (not early-return) — built-in {master,main} UNION project
    {release}.
    """
    global_path = _write_named(tmp_path, "global.toml", "broken [[[ not toml")
    project_path = _write_named(
        tmp_path, "project.toml", '[git]\nprotected_branches = ["release"]\n'
    )
    result = resolve_config(global_path, project_path)
    assert result.protected_branches == frozenset({"master", "main", "release"})


def test_resolve_config_malformed_project_never_enables_disabled(
    tmp_path: Path,
) -> None:
    """A broken project that "tries" to re-enable a globally-disabled recognizer fails.

    The global disables "pytest"; the malformed project is dropped WITH its
    disabled list, so "pytest" stays disabled (a broken layer never enables a
    trusted-disabled recognizer — D-09 recognizer dimension).
    """
    global_path = _write_named(
        tmp_path, "global.toml", '[recognizers]\ndisabled = ["pytest"]\n'
    )
    project_path = _write_named(tmp_path, "project.toml", "garbage = = [[[")
    result = resolve_config(global_path, project_path)
    assert "pytest" in result.disabled_recognizers


def test_resolve_config_absent_git_table_not_malformed(tmp_path: Path) -> None:
    """D-07: an absent [git] table in an OTHERWISE-VALID global is NOT malformed.

    It resolves WITHOUT falling back to built-in via the fail-closed path — the
    absent-protected-key built-in fallback (Plan 01) holds, so protected stays
    master/main and the config is NOT dropped as if broken.
    """
    global_path = _write_named(
        tmp_path, "global.toml", '[recognizers]\ndisabled = ["sed"]\n'
    )
    result = resolve_config(global_path, None)
    # Absent [git] -> built-in protected/gated (Plan 01 fallback), NOT a drop.
    assert result.protected_branches == frozenset({"master", "main"})
    assert result.gated_subcommands == frozenset({"add", "commit", "stash"})
    # And the valid [recognizers] table was honored (proves it wasn't dropped).
    assert result.disabled_recognizers == frozenset({"sed"})

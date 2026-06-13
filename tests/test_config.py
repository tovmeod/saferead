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

_DEFAULT_AUDIT_PATH = Path("/tmp/claude-hook-audit.log")


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


# --- Phase 10 Plan 01: [logging] table (LOG-01 / D-04..D-06) --------------


def test_builtin_config_has_logging_defaults() -> None:
    """builtin_config() carries the logging defaults: enabled True, default path."""
    cfg = builtin_config()
    assert cfg.log_enabled is True
    assert cfg.log_path == _DEFAULT_AUDIT_PATH


def test_resolved_config_logging_fields_default_when_omitted() -> None:
    """Existing 3-field ResolvedConfig(...) constructors inherit logging defaults.

    Pitfall 6: the logging fields are DEFAULTED so the pre-Phase-10 construction
    sites keep compiling and inherit enabled=True + the default audit path.
    """
    cfg = ResolvedConfig(
        protected_branches=frozenset({"release"}),
        gated_subcommands=frozenset({"commit"}),
        disabled_recognizers=frozenset({"pytest"}),
    )
    assert cfg.log_enabled is True
    assert cfg.log_path == _DEFAULT_AUDIT_PATH


def test_merge_logging_project_overrides_base() -> None:
    """merge: a present project [logging] FULLY overrides base (coalesce, D-04/D-05).

    Logging is non-trust-affecting (changes no allow/ask/abstain verdict), so the
    project layer is allowed full scalar override — NOT a union with the base.
    """
    base = ResolvedConfig(
        protected_branches=frozenset({"main"}),
        gated_subcommands=frozenset({"commit"}),
        disabled_recognizers=frozenset(),
        log_enabled=True,
        log_path=Path("/var/log/base-audit.log"),
    )
    project = RawLayer(
        protected_branches=None,
        gated_subcommands=None,
        disabled_recognizers=None,
        log_enabled=False,
        log_path=Path("/p/project-audit.log"),
    )
    result = merge(base, project)
    assert result.log_enabled is False
    assert result.log_path == Path("/p/project-audit.log")


def test_merge_logging_absent_keeps_base() -> None:
    """merge: absent project logging keys (None) keep the base values (coalesce)."""
    base = ResolvedConfig(
        protected_branches=frozenset({"main"}),
        gated_subcommands=frozenset({"commit"}),
        disabled_recognizers=frozenset(),
        log_enabled=False,
        log_path=Path("/var/log/base-audit.log"),
    )
    project = RawLayer(
        protected_branches=None,
        gated_subcommands=None,
        disabled_recognizers=None,
        log_enabled=None,
        log_path=None,
    )
    result = merge(base, project)
    assert result.log_enabled is False
    assert result.log_path == Path("/var/log/base-audit.log")


def test_load_layer_absent_logging_table_is_builtin_default(tmp_path: Path) -> None:
    """D-06: a TOML with no [logging] table -> enabled True, default audit path."""
    path = _write(tmp_path, '[git]\nprotected_branches = ["main"]\n')
    cfg = load_layer(path)
    assert cfg.log_enabled is True
    assert cfg.log_path == _DEFAULT_AUDIT_PATH


def test_load_layer_logging_table_honored(tmp_path: Path) -> None:
    """A present [logging] path/enabled is honored verbatim (D-04)."""
    path = _write(
        tmp_path,
        '[logging]\npath = "/tmp/x.log"\nenabled = false\n',
    )
    cfg = load_layer(path)
    assert cfg.log_path == Path("/tmp/x.log")
    assert cfg.log_enabled is False


def test_load_layer_logging_partial_path_only(tmp_path: Path) -> None:
    """[logging] with only path set keeps enabled at the built-in default."""
    path = _write(tmp_path, '[logging]\npath = "/tmp/only-path.log"\n')
    cfg = load_layer(path)
    assert cfg.log_path == Path("/tmp/only-path.log")
    assert cfg.log_enabled is True


def test_load_layer_logging_enabled_non_bool_raises(tmp_path: Path) -> None:
    """A non-bool [logging] enabled RAISES (entrypoint degrades fail-closed)."""
    path = _write(tmp_path, '[logging]\nenabled = "yes"\n')
    with pytest.raises((TypeError, ValueError)):
        load_layer(path)


def test_load_layer_logging_path_non_str_raises(tmp_path: Path) -> None:
    """A non-str [logging] path RAISES (entrypoint degrades fail-closed)."""
    path = _write(tmp_path, "[logging]\npath = 5\n")
    with pytest.raises((TypeError, ValueError)):
        load_layer(path)


def test_load_layer_logging_not_a_table_raises(tmp_path: Path) -> None:
    """A [logging] that is not a table RAISES (mirrors [git]/[recognizers])."""
    path = _write(tmp_path, 'logging = "nope"\n')
    with pytest.raises((TypeError, ValueError)):
        load_layer(path)


def test_resolve_config_malformed_logging_global_fails_closed(tmp_path: Path) -> None:
    """D-06/CORE-06: a malformed [logging] in the GLOBAL degrades to built-in default.

    The never-raising ladder drops the broken global to builtin_config(), so the
    logging default (enabled True, default path) is restored — no exception.
    """
    global_path = _write_named(tmp_path, "global.toml", '[logging]\nenabled = "yes"\n')
    result = resolve_config(global_path, None)  # must not raise
    assert result.log_enabled is True
    assert result.log_path == _DEFAULT_AUDIT_PATH


# --- PY-03 / PY-04: [python] allowlist config wiring (Phase 12 Plan 02) --------
#
# PY-03 wires two new [python] keys (allowed_methods, allowed_modules) through the
# config layers with the SAME absent-vs-floor / REPLACE-on-present model as the git
# keys. PY-04 is the DELIBERATE POLARITY INVERSION: the untrusted PROJECT layer
# UNIONS (widens) the two python keys, while gated_subcommands stays narrow-only in
# the very same merge. This is the FIRST project-widenable allow-affecting key — a
# user-ratified accepted-risk cardinal override (D-05, ratified at project altitude,
# commit 2719284). These tests pin both polarities holding simultaneously, plus the
# floor-parity guard (config owns the single floor home; the analyzer references it).


def test_python_global_replace_changes_effective_allowlist(tmp_path: Path) -> None:
    """PY-03: a present global [python] REPLACES the floor for both python keys."""
    path = _write(
        tmp_path,
        '[python]\nallowed_methods = ["custom_m"]\nallowed_modules = ["custom_mod"]\n',
    )
    cfg = load_layer(path)
    assert cfg.python_allowed_methods == frozenset({"custom_m"})
    assert cfg.python_allowed_modules == frozenset({"custom_mod"})


def test_python_absent_key_falls_back_to_floor(tmp_path: Path) -> None:
    """PY-03: an absent [python] key resolves to the built-in floor, never empty."""
    from safe_read_hook.config import _BUILTIN_PY_METHODS, _BUILTIN_PY_MODULES

    # A global that customizes only [git] — no [python] table at all.
    path = _write(tmp_path, '[git]\nprotected_branches = ["release"]\n')
    cfg = load_layer(path)
    assert cfg.python_allowed_methods == _BUILTIN_PY_METHODS
    assert cfg.python_allowed_modules == _BUILTIN_PY_MODULES
    assert cfg.python_allowed_methods  # non-empty (never empty-by-omission)
    assert cfg.python_allowed_modules


def test_python_project_layer_widens_allowlist(tmp_path: Path) -> None:
    """PY-04: a project [python] ADD UNIONS into (widens) the effective allowlist."""
    base = builtin_config()
    project_path = _write(tmp_path, '[python]\nallowed_modules = ["os"]\n')
    result = merge(base, parse_layer(project_path))
    assert "os" in result.python_allowed_modules
    assert result.python_allowed_modules == base.python_allowed_modules | {"os"}


def test_python_widen_while_gated_stays_narrow_same_merge(tmp_path: Path) -> None:
    """PY-04 vs CR-01: in ONE merge, python WIDENS but gated stays narrow-only.

    The deliberately OPPOSITE polarities must both hold in the same merge call:
    the untrusted project widens the python allowlist (accepted risk) yet cannot
    widen gated_subcommands (cardinal false-allow CR-01 stays closed).
    """
    base = builtin_config()
    project_path = _write(
        tmp_path,
        '[python]\nallowed_modules = ["os"]\n[git]\ngated_subcommands = ["push"]\n',
    )
    result = merge(base, parse_layer(project_path))
    # python: WIDENED (PY-04 accepted risk)
    assert "os" in result.python_allowed_modules
    # gated: NARROW-ONLY, unchanged (CR-01 — opposite polarity, same merge)
    assert "push" not in result.gated_subcommands
    assert result.gated_subcommands == base.gated_subcommands


def test_python_floor_parity_no_drift() -> None:
    """Drift guard: the analyzer floor == the config floor (single floor home)."""
    from safe_read_hook.analyzers.python_skeleton import (
        _FLOOR_METHODS,
        _FLOOR_MODULES,
    )
    from safe_read_hook.config import _BUILTIN_PY_METHODS, _BUILTIN_PY_MODULES

    assert _BUILTIN_PY_METHODS == _FLOOR_METHODS
    assert _BUILTIN_PY_MODULES == _FLOOR_MODULES

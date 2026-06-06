"""Single-layer TOML config loader + the ResolvedConfig value object (CFG-01).

The hook's protected-branch and gated-subcommand sets, plus the disabled
recognizer set, move out of the hardcoded ``_PROTECTED``/``_GATED`` constants in
``git.py`` and into human-editable TOML (stdlib ``tomllib``). This module owns
the *parse + single-layer resolve*; it does NOT merge layers (Plan 02) nor run
the multi-layer fail-closed orchestration (Plan 03).

The built-in floor (``builtin_config``) is the proven-safe default a missing or
broken config degrades toward (D-08 case 1 / D-09): protected ``master``/``main``,
gated ``add``/``commit``/``stash``, nothing disabled.

:func:`resolve_config` (Plan 03) is the never-raising orchestrator that applies
the full D-08 three-case + D-09 per-layer fail-closed matrix across both layers,
falling toward the built-in floor (D-10 safe defaults) and never crashing the
hook (CORE-06). The entrypoint owns the I/O (path/env resolution) and calls this
single total function.

CARDINAL absent-vs-empty distinction (D-05/D-07 boundary) — the whole point of
this loader:

* A PRESENT global config REPLACES the built-in defaults (D-05). The trusted
  user has full control of the baseline.
* But a PRESENT global that simply OMITS the ``protected_branches`` key must NOT
  resolve to an EMPTY protected set — that would auto-allow ``git commit`` on
  ``main`` (a cardinal false-allow). So an ABSENT key falls back to that key's
  built-in value, while an EXPLICIT empty list ``[]`` is honored as the user's
  chosen empty set. ``tomllib`` distinguishes these via key PRESENCE
  (``"protected_branches" in git_table``), never truthiness.

IMPORTANT polarity note for Plan 02: the absent-key→built-in fallback here is a
SINGLE-LAYER (global/standalone) resolution detail — NOT a union floor. When Plan
02 loads a PROJECT layer to MERGE, an absent project key must contribute the
EMPTY set (additive identity, D-07), because the project layer NARROWS an
already-resolved base. The two polarities are opposite, so Plan 02 must read the
project layer's RAW present/absent keys rather than this fully-resolved view:
:func:`parse_layer` exposes exactly those raw key presences for that purpose.
"""

from __future__ import annotations

import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

#: The built-in protected branches — the floor a broken/absent config falls to.
_BUILTIN_PROTECTED = frozenset({"master", "main"})
#: The built-in gated subcommands — the floor a broken/absent config falls to.
_BUILTIN_GATED = frozenset({"add", "commit", "stash"})
#: The built-in audit-log path — distinct from the error log (/tmp/claude-hook.log).
_BUILTIN_AUDIT_PATH = Path("/tmp/claude-hook-audit.log")
#: Audit logging is on by default (LOG-01).
_BUILTIN_LOG_ENABLED = True


@dataclass(frozen=True, slots=True)
class ResolvedConfig:
    """An immutable resolved config: the effective protected/gated/disabled sets.

    Field names are LOCKED (Plans 02/03 consume ``ctx.config.protected_branches``
    / ``.gated_subcommands`` / ``.disabled_recognizers``).

    Attributes:
        protected_branches: Branches on which a gated git write ASKs.
        gated_subcommands: Git subcommands gated on the working branch.
        disabled_recognizers: Recognizer tags disabled for the run (carried this
            plan; consumed in a later plan).
        log_enabled: Whether to append an audit record per emitted decision
            (LOG-01). DEFAULTED so the pre-Phase-10 3-field constructors keep
            compiling and inherit the built-in default.
        log_path: Audit-log file the per-decision JSON-lines records append to —
            distinct from the error log. DEFAULTED (see ``log_enabled``).
    """

    protected_branches: frozenset[str]
    gated_subcommands: frozenset[str]
    disabled_recognizers: frozenset[str]
    log_enabled: bool = _BUILTIN_LOG_ENABLED
    log_path: Path = field(default=_BUILTIN_AUDIT_PATH)


def builtin_config() -> ResolvedConfig:
    """Return the built-in floor: master/main + add/commit/stash, nothing disabled.

    This is the proven-safe default an absent global config resolves to (D-08
    case 1) and a broken layer degrades toward (D-09). The literals are the same
    values that lived in ``git.py``'s ``_PROTECTED``/``_GATED`` constants.
    """
    return ResolvedConfig(
        protected_branches=_BUILTIN_PROTECTED,
        gated_subcommands=_BUILTIN_GATED,
        disabled_recognizers=frozenset(),
        log_enabled=_BUILTIN_LOG_ENABLED,
        log_path=_BUILTIN_AUDIT_PATH,
    )


@dataclass(frozen=True, slots=True)
class RawLayer:
    """The RAW parsed view of one TOML layer, preserving key PRESENCE.

    Plan 02 needs to know which keys a (narrowing) project layer actually set —
    an absent project key is additive-identity-empty, the OPPOSITE polarity to
    this module's single-layer built-in fallback. A field is ``None`` when its
    key was ABSENT and a ``frozenset`` (possibly empty) when the key was PRESENT.
    """

    protected_branches: frozenset[str] | None
    gated_subcommands: frozenset[str] | None
    disabled_recognizers: frozenset[str] | None
    log_path: Path | None = None
    log_enabled: bool | None = None


def _coerce_str_set(value: object, key: str) -> frozenset[str]:
    """Coerce a TOML value to a ``frozenset[str]`` or raise on a malformed value.

    A non-list, or a list with a non-string element, raises (the entrypoint /
    Plan 03 catches and degrades fail-closed). A well-formed list — including an
    explicit empty list — is honored verbatim.
    """
    if not isinstance(value, list):
        raise TypeError(f"{key} must be a list of strings, got {type(value).__name__}")
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{key} entries must be strings, got {type(item).__name__}")
    return frozenset(value)


def _coerce_path(value: object, key: str) -> Path:
    """Coerce a TOML value to a ``Path`` or raise on a malformed (non-str) value.

    Mirrors :func:`_coerce_str_set`'s raise-on-malformed so the never-raising
    ladder degrades fail-closed (D-06).
    """
    if not isinstance(value, str):
        raise TypeError(f"{key} must be a string, got {type(value).__name__}")
    return Path(value)


def _coerce_bool(value: object, key: str) -> bool:
    """Coerce a TOML value to a ``bool`` or raise on a malformed value.

    ``bool`` is checked BEFORE any truthiness shortcut so a stray string/int fails
    closed rather than silently enabling/disabling logging.
    """
    if not isinstance(value, bool):
        raise TypeError(f"{key} must be a boolean, got {type(value).__name__}")
    return value


def parse_layer(path: Path) -> RawLayer:
    """Parse ONE TOML file into a :class:`RawLayer` preserving key presence.

    Opens ``path`` with a BINARY handle (``tomllib.load`` requires bytes, not
    text). Raises on a malformed file (parse error) or a malformed value; the
    caller degrades fail-closed. The raw present/absent distinction is what lets
    a single-layer resolve fall an absent key back to built-in (here) while Plan
    02 treats an absent project key as additive-identity-empty.
    """
    with open(path, "rb") as f:
        data = tomllib.load(f)

    git_table = data.get("git", {})
    if not isinstance(git_table, dict):
        raise TypeError("[git] must be a table")
    rec_table = data.get("recognizers", {})
    if not isinstance(rec_table, dict):
        raise TypeError("[recognizers] must be a table")
    log_table = data.get("logging", {})
    if not isinstance(log_table, dict):
        raise TypeError("[logging] must be a table")

    protected = (
        _coerce_str_set(git_table["protected_branches"], "protected_branches")
        if "protected_branches" in git_table
        else None
    )
    gated = (
        _coerce_str_set(git_table["gated_subcommands"], "gated_subcommands")
        if "gated_subcommands" in git_table
        else None
    )
    disabled = (
        _coerce_str_set(rec_table["disabled"], "disabled")
        if "disabled" in rec_table
        else None
    )
    log_path = (
        _coerce_path(log_table["path"], "[logging] path")
        if "path" in log_table
        else None
    )
    log_enabled = (
        _coerce_bool(log_table["enabled"], "[logging] enabled")
        if "enabled" in log_table
        else None
    )
    return RawLayer(
        protected_branches=protected,
        gated_subcommands=gated,
        disabled_recognizers=disabled,
        log_path=log_path,
        log_enabled=log_enabled,
    )


def merge(base: ResolvedConfig, project: RawLayer) -> ResolvedConfig:
    """Narrow an already-resolved ``base`` with an untrusted PROJECT layer (D-04).

    The merge is narrow-only BY CONSTRUCTION — there is no remove/replace/enable
    operation. The INVARIANT every merged dimension must satisfy: a project ADD to
    the set may only move verdicts toward ask/abstain, NEVER toward allow.

    * ``protected_branches`` = ``base ∪ project`` (project ADD → more ASK; safe).
    * ``disabled_recognizers`` = ``base ∪ project`` (project ADD → more abstain;
      there is no ``enabled`` key, so a project can never re-enable a tag the base
      disabled; safe).
    * ``gated_subcommands`` = ``base`` ONLY — the project does NOT contribute.
      Unlike the other two, the gated path is NOT pure-ASK: ``recognize_git`` has
      an ALLOW arm for a gated subcommand on a NON-protected branch (git.py). So a
      project ADD to the gated set WIDENS the allow-set for state-mutating git ops
      on feature branches — a cardinal false-allow (CR-01). A union can only grow
      the set; it can never narrow gated trust toward abstain. The trusted GLOBAL
      layer may still set gated via :func:`load_layer`; the untrusted PROJECT layer
      may not. This OVERRIDES locked decision D-04 ("gated by union") and ROADMAP
      criterion-3 ("project can add gated subcommands"): the cardinal "never widen
      the allow-set" constraint outranks both.

    POLARITY (the opposite of :func:`load_layer`): an ABSENT project key (``None``
    in the :class:`RawLayer`) is the additive identity — the EMPTY set — so the
    base value passes through unchanged (D-07). This differs deliberately from the
    single-layer built-in fallback, because the project layer narrows an
    already-resolved base rather than standing alone.

    criterion-3 (CFG-03) follows directly: every member of ``base`` survives ANY
    project layer (union/add can only retain or add), so a hostile project value
    that "tries" to drop ``main`` / un-gate ``commit`` / re-enable a recognizer has
    ZERO effect. Pure (no I/O).

    LOGGING is the deliberate EXCEPTION to the union/narrow-only mechanism above.
    ``log_path``/``log_enabled`` use SCALAR COALESCE — a present project value FULLY
    overrides the base (``project value if not None else base``), NOT a union. This
    is intentional (D-05): logging is non-trust-affecting — it changes NO
    allow/ask/abstain verdict, so it sits OUTSIDE the narrow-only invariant and is
    cardinal-safe (a hostile project can disable/redirect THIS repo's audit trail,
    an ACCEPTED tradeoff, T-10-01). Do NOT unify it with the trust-set union and do
    NOT add path validation.
    """
    project_protected = (
        project.protected_branches
        if project.protected_branches is not None
        else frozenset()
    )
    project_disabled = (
        project.disabled_recognizers
        if project.disabled_recognizers is not None
        else frozenset()
    )
    log_path = project.log_path if project.log_path is not None else base.log_path
    log_enabled = (
        project.log_enabled if project.log_enabled is not None else base.log_enabled
    )
    return ResolvedConfig(
        protected_branches=base.protected_branches | project_protected,
        # gated_subcommands: base ONLY — the untrusted project must NOT contribute
        # (a project ADD widens the gated ALLOW arm on non-protected branches:
        # cardinal false-allow CR-01). See the docstring for the D-04/criterion-3
        # override rationale.
        gated_subcommands=base.gated_subcommands,
        disabled_recognizers=base.disabled_recognizers | project_disabled,
        log_path=log_path,
        log_enabled=log_enabled,
    )


def load_layer(path: Path) -> ResolvedConfig:
    """Load + resolve a SINGLE global/standalone TOML layer to a ResolvedConfig.

    Key-presence semantics (CARDINAL): a PRESENT key (including an explicit empty
    list) is honored verbatim; an ABSENT key falls back to that key's BUILT-IN
    value (master/main resp. add/commit/stash) so a global that customizes only
    one key never silently empties the other. ``[recognizers].disabled`` defaults
    to the empty set when absent.

    This single-layer fallback is NOT a merge — see the module docstring's Plan 02
    polarity note. Raises on a malformed file/value; the entrypoint catches and
    degrades to :func:`builtin_config`.
    """
    raw = parse_layer(path)
    return ResolvedConfig(
        protected_branches=(
            raw.protected_branches
            if raw.protected_branches is not None
            else _BUILTIN_PROTECTED
        ),
        gated_subcommands=(
            raw.gated_subcommands
            if raw.gated_subcommands is not None
            else _BUILTIN_GATED
        ),
        disabled_recognizers=(
            raw.disabled_recognizers
            if raw.disabled_recognizers is not None
            else frozenset()
        ),
        log_path=(
            raw.log_path if raw.log_path is not None else _BUILTIN_AUDIT_PATH
        ),
        log_enabled=(
            raw.log_enabled if raw.log_enabled is not None else _BUILTIN_LOG_ENABLED
        ),
    )


def resolve_config(
    global_path: Path,
    project_path: Path | None,
    log: Callable[[str], None] = lambda _msg: None,
) -> ResolvedConfig:
    """Resolve the effective config across both layers; NEVER raises (CFG-04).

    The total never-raising orchestrator of the D-08 three-case distinction and
    the D-09 per-layer fail-closed matrix. Any error anywhere degrades toward the
    built-in floor (D-10 safe defaults) — a malformed/unreadable config never
    crashes the hook (CORE-06) and never silently WIDENS trust below built-in.

    Resolution ladder (most→least trusted):

    1. **Base (global layer).**
       * D-08 case 1 — ``global_path`` does not exist → :func:`builtin_config`.
       * Present → :func:`load_layer` (a present global REPLACES built-in, D-05;
         an absent key inside it falls back to that key's built-in value, Plan 01
         — NOT a malformed signal, D-07).
       * D-09 malformed/unreadable global → log + DROP the global layer → fall
         back to :func:`builtin_config`. Resolution CONTINUES to the project
         layer: a valid project still narrows on top of the built-in floor.

    2. **Narrow (project layer).**
       * D-03 / D-08 case 2 — ``project_path`` is ``None`` (CLAUDE_PROJECT_DIR
         skipped) or the file does not exist → return ``base`` unchanged.
       * Present → :func:`parse_layer` (RAW present/absent keys, D-07 polarity) +
         :func:`merge` (narrow-only union/add, CFG-02/CFG-03).
       * D-09 malformed/unreadable project → log + DROP the project layer →
         return ``base`` (per-layer blast radius; the project layer can only
         narrow, so dropping it never widens trust below ``base``). The dropped
         layer's ``disabled`` list goes with it — a broken layer never ENABLES a
         recognizer the trusted base disabled (D-09 recognizer dimension).

    3. **Outer backstop.** Any unexpected error in the whole orchestration falls
       to :func:`builtin_config` rather than propagating (CORE-06 total function).

    ``log`` is injected (default no-op) so this function never touches stdout and
    has no import dependency on the entrypoint; the entrypoint passes its own
    best-effort ``log``. Pure aside from the two file reads (both guarded).
    """
    try:
        # 1. Base: the trusted global/built-in layer (D-08 case 1 / D-09 global).
        try:
            base = load_layer(global_path) if global_path.exists() else builtin_config()
        except Exception:
            log("global config load failed; using built-in floor (D-09)")
            base = builtin_config()

        # 2. Narrow: the untrusted project layer (D-08 case 2 / D-03 / D-09 project).
        if project_path is None:
            return base  # CLAUDE_PROJECT_DIR skipped (D-03) -> base only.
        try:
            if not project_path.exists():
                return base  # absent project FILE -> base only (D-08 case 2).
            return merge(base, parse_layer(project_path))
        except Exception:
            log("project config load failed; keeping global/built-in base (D-09)")
            return base
    except Exception:
        # 3. Total-function backstop: never propagate (CORE-06).
        log("config resolution failed; using built-in floor (D-09/CORE-06)")
        return builtin_config()

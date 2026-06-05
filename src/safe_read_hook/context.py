"""The Context value object passed to every recognizer.

``Context`` carries the command's working directory plus a *lazy*, per-cwd
memoized branch-resolver seam (D-05/D-06). Most recognizers (the reader, for
one) ignore the branch entirely; only the git recognizer (a later phase) needs
it. Resolving the current branch can shell out, so it is deferred behind
``_resolver`` and computed at most once per cwd via :meth:`branch`. Phase 2
ships only the no-op resolver — there is NO git logic here.

The dataclass is intentionally NON-frozen: it holds the mutable ``_branch_cache``.
``functools.cached_property`` is deliberately NOT used (RESEARCH Pitfall 2 —
it conflicts with ``slots`` and caches at the wrong granularity).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .config import ResolvedConfig, builtin_config


def _no_branch(_cwd: str | None) -> str | None:
    """Default branch resolver: the Phase 2 seam with no git logic (D-05)."""
    return None


@dataclass
class Context:
    """Per-segment context handed to a recognizer.

    Attributes:
        cwd: The command's working directory (or ``None`` when unknown).
        _resolver: Branch resolver, called lazily and memoized per cwd by
            :meth:`branch`. Defaults to :func:`_no_branch` (returns ``None``).
        _branch_cache: Per-cwd memoization store for resolved branch names.
        config: The resolved protected/gated/disabled sets (Phase 9). Injected
            once at the entrypoint, read by the git recognizer (``ctx.config.*``)
            instead of the deleted ``_PROTECTED``/``_GATED`` module constants.
            Defaulted via :func:`builtin_config` so an un-injected Context
            degrades to the built-in master/main floor — NOT "no protection"
            (D-09 fail-closed). LOCKED single-field shape (Plans 02/03 consume
            ``ctx.config.protected_branches`` / ``.gated_subcommands`` /
            ``.disabled_recognizers``).
    """

    cwd: str | None
    _resolver: Callable[[str | None], str | None] = _no_branch
    _branch_cache: dict[str, str | None] = field(default_factory=dict)
    config: ResolvedConfig = field(default_factory=builtin_config)

    def branch(self, cwd: str | None = None) -> str | None:
        """Return the branch for ``cwd`` (or ``self.cwd``), resolving once per cwd.

        The resolver runs at most once per distinct cwd key; subsequent calls
        return the memoized value, including a memoized ``None``.
        """
        effective = cwd if cwd is not None else self.cwd
        key = effective or ""
        if key not in self._branch_cache:
            self._branch_cache[key] = self._resolver(effective)
        return self._branch_cache[key]

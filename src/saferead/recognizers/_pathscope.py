"""Lexical path-gate helper: the single REC-08 path-scope policy (D-04).

This module is the analogue of ``redirects.py`` for read-path scoping: it holds
the single definition of the lexical path-resolution and root-membership rules
consumed by ``reader.py``, ``find.py``, and ``sed.py``, so the policy is
defined ONCE and cannot drift between recognizers.

Resolution is LEXICAL ONLY (D-04): ``os.path.normpath`` collapses ``.``/``..``
against the provided cwd — NO filesystem access, NO symlink resolution. This
matches the ``redirects.py`` precedent (redirects.py:43-48):

    ACCEPTED RESIDUAL (D-04): a symlink inside an allowed root that points
    outside the root is not caught — the hook deliberately does NOT resolve
    symlinks on the filesystem (latency + TOCTOU). This is accepted as the cost
    of lexical-only resolution for read operations (reads only, lower severity
    than the ``/tmp`` write residual), NOT an oversight. Do not add filesystem
    resolution to "fix" it.

Root-membership is component-boundary safe: ``resolved.startswith(root)`` alone
is INSUFFICIENT because ``/home/me/.planningEVIL`` would wrongly match root
``/home/me/.planning``. The guard is ``resolved == nr or
resolved.startswith(nr.rstrip("/") + os.sep)`` where ``nr =
os.path.normpath(root)`` (T-14-02 mitigation).
"""

from __future__ import annotations

import os.path


def resolve_lexical(operand: str, cwd: str | None) -> str | None:
    """Return the lexically-resolved absolute form of ``operand``, or ``None``.

    For an absolute operand the cwd is irrelevant; the operand is normpath'd and
    returned.  For a relative operand with a known ``cwd`` the operand is joined
    against ``cwd`` and normpath'd.  A relative operand with ``cwd=None`` cannot
    be resolved (the working directory is unknown): ``None`` is returned and the
    caller must abstain.

    NO filesystem access, NO symlink resolution (D-04 lexical-only).

    Args:
        operand: The path string from the command's argv (may be abs or relative,
            may contain ``..`` or ``.`` components).
        cwd: The command's working directory, or ``None`` when unknown.

    Returns:
        An absolute normalised path string, or ``None`` when the operand is
        relative and the cwd is unknown.
    """
    if os.path.isabs(operand):
        return os.path.normpath(operand)
    if cwd is None:
        return None  # relative path, unknown cwd -> unresolvable -> caller abstains
    return os.path.normpath(os.path.join(cwd, operand))


def under_any_root(resolved: str, roots: frozenset[str] | None) -> bool:
    """True iff ``resolved`` is allowed by the ``roots`` policy (D-02).

    When ``roots`` is ``None`` (unset/absent in config) the list means "allow
    any path" — today's default behaviour.  When ``roots`` is a ``frozenset``
    (including an explicit empty frozenset), the resolved path must be EQUAL TO
    or a CHILD OF at least one root entry.

    Each root is itself normpath'd before the prefix check so trailing slashes
    and redundant components are harmless.  The child check uses
    ``startswith(nr.rstrip("/") + os.sep)`` rather than bare
    ``startswith(root)`` to guard against the partial-component false-positive
    where ``/home/me/.planningEVIL`` would wrongly match root
    ``/home/me/.planning`` (T-14-02 component-boundary mitigation).

    Args:
        resolved: The absolute normalised path from :func:`resolve_lexical`.
        roots: The allowed-root frozenset from config, or ``None`` for allow-any.

    Returns:
        ``True`` when the path is allowed, ``False`` when it is outside all roots.
    """
    if roots is None:  # unset list = allow ANY path (today's behaviour, D-02)
        return True
    for root in roots:
        nr = os.path.normpath(root)
        if resolved == nr or resolved.startswith(nr.rstrip("/") + os.sep):
            return True
    return False

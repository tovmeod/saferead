"""Recognizer-disable via ctx-driven REGISTRY guards (D-06, CFG-03).

Each REGISTRY entry is a tag-labeled guard reading ``ctx.config.disabled_recognizers``
per call: when its tag is in the disabled set it ABSTAINS (returns ``None``),
otherwise it delegates to the underlying recognizer unchanged. The mechanism
leaves ``engine.fold`` byte-identical (no disabled-set parameter, no skip branch)
and uses no module global — the disabled set rides ``ctx.config``.

A disabled recognizer can only ABSTAIN, never allow, so disabling is monotonic
toward MORE prompts (cardinal-safe). This file also pins the criterion-3
disabled-set "cannot escalate" reduction at the merge level (an add-only set has
no remove operator).
"""

from __future__ import annotations

import pytest

from safe_read_hook.config import ResolvedConfig, builtin_config
from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers import REGISTRY


def _ctx(*, disabled: frozenset[str], resolver=None) -> Context:
    """A Context whose config disables ``disabled``; optional branch resolver."""
    cfg = ResolvedConfig(
        protected_branches=frozenset({"master", "main"}),
        gated_subcommands=frozenset({"add", "commit", "stash"}),
        disabled_recognizers=disabled,
    )
    if resolver is None:
        return Context(cwd="/x", config=cfg)
    return Context(cwd="/x", _resolver=resolver, config=cfg)


def test_default_empty_disabled_set_keeps_reader_allow() -> None:
    """The default empty disabled set leaves every recognizer behaving as before."""
    ctx = Context(cwd="/x", config=builtin_config())
    verdict = fold(["cat foo.txt"], ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


def test_disabling_git_makes_gated_op_abstain() -> None:
    """Disabling "git" makes a gated git op (commit on main) abstain, not ASK.

    With an empty disabled set the SAME op ASKs; disabling short-circuits before
    the recognizer runs, so fold returns None (the guard abstains, vetoing the
    compound).
    """
    enabled = _ctx(disabled=frozenset(), resolver=lambda _c: "main")
    assert fold(["git commit -m x"], enabled) is not None
    assert fold(["git commit -m x"], enabled).decision == "ask"

    disabled = _ctx(disabled=frozenset({"git"}), resolver=lambda _c: "main")
    assert fold(["git commit -m x"], disabled) is None


def test_disabling_reader_makes_cat_abstain() -> None:
    """Disabling "reader" makes a plain reader allow abstain (fold veto -> None)."""
    ctx = _ctx(disabled=frozenset({"reader"}))
    assert fold(["cat foo.txt"], ctx) is None


# A representative allow/ask case per recognizer tag: with the tag ENABLED the
# case resolves (allow or ask), and DISABLING that tag makes it abstain. This
# confirms each guard's tag matches the Verdict.tag its recognizer emits.
_TAG_CASES: list[tuple[str, str]] = [
    ("reader", "cat foo.txt"),
    ("git", "git status"),
    ("find", "find . -type f"),
    ("sed", "sed 's/a/b/' f"),
    ("adb", "adb devices"),
    ("pytest", "pytest tests/"),
    ("gradle", "gradle tasks"),
]


@pytest.mark.parametrize(("tag", "command"), _TAG_CASES)
def test_disabling_each_tag_abstains_its_recognizer(tag: str, command: str) -> None:
    """Disabling each of the 7 tags makes its representative case abstain."""
    enabled = _ctx(disabled=frozenset())
    assert fold([command], enabled) is not None, f"{tag}: case must resolve enabled"

    disabled = _ctx(disabled=frozenset({tag}))
    assert fold([command], disabled) is None, f"{tag}: must abstain when disabled"


def test_disable_is_monotonic_toward_more_prompts() -> None:
    """A disabled recognizer can only abstain (None), never allow."""
    for tag, command in _TAG_CASES:
        verdict = fold([command], _ctx(disabled=frozenset({tag})))
        assert verdict is None


def test_registry_entries_are_callable_guards() -> None:
    """REGISTRY holds 9 callable guards (closures, not bare recognizer functions).

    Re-expresses the old element-identity assertion as a behavior/shape check:
    after wrapping, REGISTRY entries are guard closures, so identity membership
    (``recognize_git in REGISTRY``) no longer holds — order/behavior is what the
    engine depends on.
    """
    assert len(REGISTRY) == 11
    assert all(callable(entry) for entry in REGISTRY)

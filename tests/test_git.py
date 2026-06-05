"""Boundary tests for the read-only git recognizer (REC-01 / TEST-02).

The cardinal axis here is the allow/abstain BOUNDARY for git: read-only
subcommands auto-allow (honoring ``-C <path>``), while ``-c key=val`` config
injection (corpus bypass #5) and EVERY mutating form abstain. A subcommand-word
match is never sufficient — recognition is per-subcommand argument SHAPE.

Cardinal dangerous-flag coverage (the class this phase exists to close): a
read-only subcommand with a write/exec flag that contains no ``>``/``&`` token
(``git diff --output=PATH`` writes a file; ``git grep -O<cmd>`` execs a pager)
must NOT be approved. The recognizer rejects any unrecognized ``-``-leading
token by allowlist polarity, not a ``>``/``&`` fence alone.

Test-name contract (load-bearing): the Task 1 ``-k`` filter selects on the
substrings ``readonly``, ``dash_C``, ``config_injection``, ``mutating``,
``abstain``. A test whose name misses every substring is silently NOT run.
"""

from __future__ import annotations

import pytest

from safe_read_hook.config import ResolvedConfig
from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers import REGISTRY
from safe_read_hook.recognizers.git import recognize_git
from safe_read_hook.verdict import Verdict


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- read-only allow ------------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "git status",
        "git log",
        "git diff",
        "git show",
        "git blame f",
        "git branch -l",
        "git branch --show-current",
        "git tag -l",
        "git remote -v",
        "git config --get user.name",
        "git worktree list",
        "git notes show",
        "git reflog show",
        "git stash list",
        "git stash show",
    ],
)
def test_git_readonly_allows(segment: str, ctx: Context) -> None:
    verdict = recognize_git(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "git"


def test_git_readonly_returns_verdict_object(ctx: Context) -> None:
    """A read-only form returns a Verdict (allow, tag 'git'), not None."""
    verdict = recognize_git("git status", ctx)
    assert isinstance(verdict, Verdict)
    assert verdict.decision == "allow"
    assert verdict.tag == "git"


# --- -C honored -----------------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "git -C /some/path log",
        "git -C /a -C /b status",  # last-C-wins, no crash
        "git -C /some/path status",
    ],
)
def test_git_dash_C_honored(segment: str, ctx: Context) -> None:
    verdict = recognize_git(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "git"


def test_git_dash_C_no_path_abstains(ctx: Context) -> None:
    """``git -C`` with no following token cannot be classified -> abstain."""
    assert recognize_git("git -C", ctx) is None


@pytest.mark.parametrize(
    "segment",
    [
        "git -C x&id log",  # &id execs arbitrary command (backgrounds git -C x)
        "git -C >/tmp/pwned status",  # > truncates an arbitrary file
        "git -C a&id -C /safe log",  # non-final -C value also fenced
    ],
)
def test_git_dash_C_redirect_value_abstains(segment: str, ctx: Context) -> None:
    """A ``>``/``&`` glued into the ``-C`` value must NOT be approved (CR-01).

    The ``-C`` value token is consumed before the post-subcommand fence, so the
    fence is applied at capture time instead. ``git -C x&id`` execs ``id`` and
    ``git -C >/tmp/x`` truncates a file in real bash — both are false-allows of
    command execution / file write absent this fence (cardinal zero-false-allow).
    """
    assert recognize_git(segment, ctx) is None


def test_git_gated_dash_C_redirect_value_abstains() -> None:
    """The gated path is also fenced: ``git -C x&id commit`` abstains BEFORE probe.

    The fence sits in the leading-option scan (above the gated branch probe), so
    a redirect/control ``-C`` value aborts before ctx.branch is ever touched.
    """
    ctx = Context(cwd="/x", _resolver=_fail_if_called)
    assert recognize_git("git -C x&id commit -m x", ctx) is None


# --- config injection / leading-option abstain ----------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "git -c core.fsmonitor=touch status",  # corpus bypass #5
        "git --paginate status",
        "git --exec-path=/x status",
        "git --config-env=core.pager=ENV status",
        "git --work-tree=/x status",
        "git --namespace=ns status",
        "git -- status",  # bare -- leading option
    ],
)
def test_git_config_injection_abstains(segment: str, ctx: Context) -> None:
    """``-c`` and every non-``-C`` leading option abstain (allowlist polarity).

    Direct is-None (Pitfall 5) — ``!= allow`` is insufficient since ``ask``
    would also pass it.
    """
    assert recognize_git(segment, ctx) is None


# --- mutating forms abstain -----------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "git branch -d feature",
        "git branch -D feature",
        "git branch newfeature",  # bare positional CREATES a ref
        "git branch -m old new",
        "git tag v1",  # bare positional CREATES a tag
        "git tag -d v1",
        "git remote add origin url",
        "git remote remove origin",
        "git remote set-url origin url",
        "git config user.name bob",  # bare key value pair
        "git config --add user.name bob",
        "git config --unset user.name",
        "git worktree add /x",
        "git worktree remove /x",
        "git notes add",
        "git reflog delete",
        "git reflog expire",
        "git ls-remote origin",  # D-09 network egress
    ],
)
def test_git_mutating_forms_abstain(segment: str, ctx: Context) -> None:
    assert recognize_git(segment, ctx) is None


# --- dangerous flags on read-only subcommands abstain (cardinal) ----------


@pytest.mark.parametrize(
    "segment",
    [
        "git diff --output=/tmp/x",  # writes a file, no > token
        "git log --output=/etc/passwd",  # writes a file, no > token
        "git diff --output /tmp/x",  # separated value form
        "git grep -Otouch pattern",  # opens pager (exec) via -O<cmd>
        "git grep --open-files-in-pager=touch pattern",
        "git config --file /etc/passwd --get x",  # reads arbitrary file
        "git show --output=/tmp/x",
    ],
)
def test_git_dangerous_flag_abstains(segment: str, ctx: Context) -> None:
    """A write/exec flag with no ``>``/``&`` token must NOT be approved.

    Allowlist polarity: an unrecognized ``-``-leading token on any read-only
    subcommand abstains by construction (mirrors reader's ``file`` discipline).
    """
    assert recognize_git(segment, ctx) is None


# --- remote network egress (D-09 polarity) --------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "git remote show origin",  # queries the remote over the network (egress)
        "git remote show",  # bare show still queries every remote
    ],
)
def test_git_remote_show_network_abstains(segment: str, ctx: Context) -> None:
    """``git remote show <name>`` queries the remote (egress) -> abstain (WR-03).

    Without ``-n``/``--no-query`` git runs the equivalent of ``git ls-remote``,
    the same network egress the line-250 ``ls-remote`` abstain already blocks
    (D-09). Allowing it inverted the policy polarity.
    """
    assert recognize_git(segment, ctx) is None


@pytest.mark.parametrize(
    "segment",
    [
        "git remote show -n origin",  # -n => local, no network query
        "git remote show --no-query origin",
        "git remote get-url origin",  # local lookup, no egress
        "git remote -v",
    ],
)
def test_git_remote_local_forms_readonly_allow(segment: str, ctx: Context) -> None:
    """Local remote reads (``-n`` show, ``get-url``, ``-v``) stay allow (WR-03).

    Named with ``readonly`` so the documented Task-1 ``-k`` filter selects it —
    a positive allow-test that matches no filter substring would be silently
    deselected (the WR-01 failure class this same review iteration closed).
    """
    verdict = recognize_git(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "git"


# --- redirect / control fence (cardinal) ----------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "git log >/tmp/x",  # redirect git output to a real file
        "git diff > out.txt",  # redirect to a user file
        "git show >/etc/x",  # redirect to a system file
        "git status >/tmp/../etc/passwd",  # path-escaping redirect
        "git status &",  # background control operator
        "git branch -l >/tmp/x",  # fence applies to per-subcommand groups too
        "git config --get user.name >/tmp/x",
    ],
)
def test_git_redirect_abstains(segment: str, ctx: Context) -> None:
    """A redirect to a real file or a background op must NOT be approved.

    The tokenizer keeps ``>``/``&`` glued into a word token, so a ``-``-leading
    flag check alone would pass ``git log >/tmp/x`` as a positional. The
    redirect/control fence (mirroring reader._tail_is_safe) closes it.
    """
    assert recognize_git(segment, ctx) is None


@pytest.mark.parametrize(
    "segment",
    [
        "git log >/dev/null",  # discard redirect never touches a user file
        "git status 2>&1",
        "git diff 2>/dev/null",
    ],
)
def test_git_discard_redirect_readonly_allows(segment: str, ctx: Context) -> None:
    """A discard redirect (>/dev/null, 2>&1) on a read-only form stays allow."""
    verdict = recognize_git(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "git"


# --- gated branch-gate verdict (05-02) ------------------------------------
#
# Test-name contract (load-bearing): the Task 1 ``-k "gated or unresolved"``
# filter selects on the substrings ``gated`` and ``unresolved``. EVERY gated/
# unresolved test below MUST contain one of those substrings, or it is silently
# NOT run (and a filter substring matching zero tests false-passes via pytest
# exit 5). Deterministic fixed-return fake ``_resolver`` — NO real subprocess.


def _fail_if_called(_cwd: str | None) -> str | None:
    """A resolver that must NEVER run on the read-only path (Pitfall 1)."""
    raise AssertionError("branch resolver called on the read-only path")


@pytest.mark.parametrize(
    "segment",
    [
        "git commit -m x",
        "git add .",
    ],
)
def test_git_gated_asks_on_protected(segment: str) -> None:
    """A gated add/commit on a protected branch (master/main) -> ask (D-01)."""
    ctx = Context(cwd="/x", _resolver=lambda _c: "main")
    verdict = recognize_git(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.tag == "git"


@pytest.mark.parametrize(
    ("segment", "branch"),
    [
        ("git commit -m x", "feature/foo"),
        ("git add .", "feature/x"),
    ],
)
def test_git_gated_allows_on_feature(segment: str, branch: str) -> None:
    """A gated add/commit on a feature branch -> allow (D-01)."""
    ctx = Context(cwd="/x", _resolver=lambda _c: branch)
    verdict = recognize_git(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "git"


def test_git_gated_stash_asks_on_protected() -> None:
    """Bare ``git stash`` is GATED: ask on protected, allow on feature.

    ``git stash list``/``stash show`` stay on the 05-01 read-only path and must
    NOT probe the branch (re-pinned here with a fail-if-called resolver).
    """
    ask_ctx = Context(cwd="/x", _resolver=lambda _c: "main")
    ask_v = recognize_git("git stash", ask_ctx)
    assert ask_v is not None
    assert ask_v.decision == "ask"
    assert ask_v.tag == "git"

    allow_ctx = Context(cwd="/x", _resolver=lambda _c: "feature")
    allow_v = recognize_git("git stash", allow_ctx)
    assert allow_v is not None
    assert allow_v.decision == "allow"

    # stash list is read-only — never probes the branch.
    ro_ctx = Context(cwd="/x", _resolver=_fail_if_called)
    ro_v = recognize_git("git stash list", ro_ctx)
    assert ro_v is not None
    assert ro_v.decision == "allow"


def test_git_unresolved_branch_asks() -> None:
    """A gated write whose branch is unresolvable (None) -> ask, NOT abstain.

    D-02 (Pitfall 4): detached HEAD / not-a-repo / probe error -> resolver
    returns None -> treat unknown like protected -> ASK (fail-safe visible).
    Diverges from the seed's abstain.
    """
    ctx = Context(cwd="/x", _resolver=lambda _c: None)
    verdict = recognize_git("git commit -m x", ctx)
    assert verdict is not None
    assert verdict.decision == "ask"
    assert verdict.tag == "git"
    assert "unresolved" in verdict.reason


def test_git_gated_dash_C_probes_effective_cwd() -> None:
    """``git -C /p commit`` gates against THAT cwd's branch (last-C-wins)."""
    seen: list[str | None] = []

    def _capture(cwd: str | None) -> str | None:
        seen.append(cwd)
        return "main"

    ctx = Context(cwd="/default", _resolver=_capture)
    verdict = recognize_git("git -C /p commit -m x", ctx)
    assert verdict is not None
    assert verdict.decision == "ask"
    assert seen == ["/p"]


def test_git_gated_path_only_readonly_no_probe() -> None:
    """The read-only path NEVER resolves the branch (Pitfall 1).

    ``git status`` allows without ever calling the resolver — the gated branch
    is the ONLY place recognize_git touches ctx.branch.
    """
    ctx = Context(cwd="/x", _resolver=_fail_if_called)
    verdict = recognize_git("git status", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "git"


# --- probe-counting: memoization + D-08 fold reconciliation ---------------
#
# The branch probe is lazy + per-cwd memoized in Context, and the engine fold
# short-circuits on an unrecognized segment. These tests pin the D-08 sign-off:
# same-cwd add&&commit probes ONCE; unrecognized-first probes ZERO; gated-first
# then unrecognized pays EXACTLY ONE discarded probe (accepted residual). Use a
# counting fake resolver — NO real subprocess.


def test_git_gated_memoizes_one_probe_per_cwd() -> None:
    """``git add`` then ``git commit`` on the SAME ctx probes exactly once (D-08).

    Named with ``gated`` so the documented ``-k "gated or unresolved"`` selection
    filter collects it (WR-01) — under the bare ``memoizes`` name it was silently
    deselected, so this memoization safety pin never ran under the CI filter.
    """
    calls: list[str | None] = []
    ctx = Context(cwd="/x", _resolver=lambda c: calls.append(c) or "main")
    recognize_git("git add .", ctx)
    recognize_git("git commit -m x", ctx)
    assert len(calls) == 1


def test_git_gated_short_circuit_zero_probe() -> None:
    """Unrecognized-first (``rm -rf x && git commit``) -> veto, ZERO probes (D-08).

    The engine short-circuits on the first unrecognized segment, so the git
    recognizer never runs and the resolver is never called.

    Named with ``gated`` so the documented ``-k "gated or unresolved"`` selection
    filter collects it (WR-01) — under the bare ``short_circuit`` name it was
    silently deselected, so this zero-probe safety pin never ran under the filter.
    """
    calls: list[str | None] = []
    ctx = Context(cwd="/x", _resolver=lambda c: calls.append(c) or "feature/foo")
    result = fold(["rm -rf x", "git commit -m x"], ctx)
    assert result is None
    assert len(calls) == 0


def test_git_gated_first_one_discarded_probe() -> None:
    """Gated-first then unrecognized -> abstain-veto, EXACTLY ONE discarded probe.

    D-08 accepted reconciled residual: the gated segment fires one bounded probe
    before the later unrecognized segment vetoes (None). NOT a bug — the
    lazy-.decision "no probe" trick is a rejected false fix (RESEARCH Pattern 1).
    """
    calls: list[str | None] = []
    ctx = Context(cwd="/x", _resolver=lambda c: calls.append(c) or "feature/foo")
    result = fold(["git commit -m x", "definitelyunrecognizedcmd"], ctx)
    assert result is None
    assert len(calls) == 1


# --- non-git / bare git abstain -------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "ls -la /tmp",  # leading token not 'git'
        "git",  # bare git, no subcommand
        "gitk",  # not 'git'
    ],
)
def test_git_non_git_abstains(segment: str, ctx: Context) -> None:
    assert recognize_git(segment, ctx) is None


# --- config injection: git.py reads ctx.config, not the module constants ---
#
# Proves the gated branch-gate verdict consults ctx.config.protected_branches /
# ctx.config.gated_subcommands rather than the (deleted) _PROTECTED/_GATED
# constants. Naming includes "config_injection" so the documented -k filter
# selects these.


def _cfg(protected: set[str], gated: set[str]) -> ResolvedConfig:
    return ResolvedConfig(
        protected_branches=frozenset(protected),
        gated_subcommands=frozenset(gated),
        disabled_recognizers=frozenset(),
    )


def test_git_config_injection_main_not_protected_allows() -> None:
    """Inject protected={release}: a gated commit on 'main' ALLOWs (main unprotected).

    Cardinal proof the verdict reads ctx.config.protected_branches — with the
    deleted _PROTECTED constant this would have ASKed.
    """
    ctx = Context(
        cwd="/x",
        config=_cfg({"release"}, {"commit"}),
        _resolver=lambda _c: "main",
    )
    verdict = recognize_git("git commit -m x", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "git"


def test_git_config_injection_release_protected_asks() -> None:
    """Inject protected={release} + resolver 'release': a gated commit ASKs."""
    ctx = Context(
        cwd="/x",
        config=_cfg({"release"}, {"commit"}),
        _resolver=lambda _c: "release",
    )
    verdict = recognize_git("git commit -m x", ctx)
    assert verdict is not None
    assert verdict.decision == "ask"


def test_git_config_injection_subcommand_not_gated_abstains() -> None:
    """Inject gated={push} (not commit): a bare 'git commit' falls through to None.

    Proves the gate membership test reads ctx.config.gated_subcommands — with
    'commit' absent from the injected gated set the recognizer no longer gates it.
    """
    ctx = Context(
        cwd="/x",
        config=_cfg({"main"}, {"push"}),
        _resolver=_fail_if_called,
    )
    assert recognize_git("git commit -m x", ctx) is None


def test_git_default_config_is_builtin_floor() -> None:
    """An un-injected Context(cwd=...) defaults to the built-in floor (D-09).

    Without config injection a gated commit on 'main' still ASKs — the default
    must be the master/main floor, NOT 'no protection'.
    """
    ctx = Context(cwd="/x", _resolver=lambda _c: "main")
    verdict = recognize_git("git commit -m x", ctx)
    assert verdict is not None
    assert verdict.decision == "ask"


# --- REGISTRY wiring (Task 2) ---------------------------------------------


def test_git_registered_after_reader(ctx: Context) -> None:
    """git is wired into the REGISTRY, with reader still reachable first.

    REGISTRY entries are now tag-labeled guard CLOSURES (Plan 02 disable
    mechanism), so the old element-identity assertion (``recognize_git in
    REGISTRY``) no longer holds — re-expressed as BEHAVIOR: a reader segment
    still allows through the registry (reader is reachable, stays first), and a
    git segment resolves via the git guard (git is wired in). CORE-04 ordering
    invariant — one list edit, no engine change.
    """
    assert len(REGISTRY) == 7
    # Reader is reachable through the registry (the common read path, first).
    reader_verdict = fold(["cat foo.txt"], ctx)
    assert reader_verdict is not None and reader_verdict.tag == "reader"
    # git is wired in: a read-only git segment resolves via the git guard.
    git_verdict = fold(["git status"], ctx)
    assert git_verdict is not None and git_verdict.tag == "git"


def test_git_config_injection_corpus_consistency(ctx: Context) -> None:
    """Pitfall 5: the corpus ``!= allow`` green is explained by an explicit abstain.

    The corpus ``git -c core.fsmonitor=touch status`` vector passes its
    ``!= allow`` guard whether the recognizer abstains OR asks — so the corpus
    green alone does not prove the recognizer abstains. Re-pin the direct
    ``is None`` here so the corpus green is attributable to recognize_git's
    explicit ``-c`` abstain, not coincidence.
    """
    assert recognize_git("git -c core.fsmonitor=touch status", ctx) is None

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

from safe_read_hook.context import Context
from safe_read_hook.recognizers import REGISTRY, recognize_reader
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


# --- transitional gated pins (gated path lands in 05-02) -------------------


@pytest.mark.parametrize(
    "segment",
    [
        "git commit -m x",
        "git add .",
        "git stash",  # bare stash is GATED, not read-only
        "git stash push",
    ],
)
def test_git_gated_forms_abstain(segment: str, ctx: Context) -> None:
    """05-01 does NOT implement the gated branch-gate verdict -> abstain.

    05-02 replaces these with branch-gate (allow/ask) tests.
    """
    assert recognize_git(segment, ctx) is None


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


# --- REGISTRY wiring (Task 2) ---------------------------------------------


def test_git_registered_after_reader() -> None:
    """recognize_git is in the ordered REGISTRY, after recognize_reader.

    Reader stays FIRST (the common read path); the git recognizer follows
    (CORE-04 ordering invariant — one list edit, no engine change).
    """
    assert recognize_git in REGISTRY
    assert REGISTRY.index(recognize_reader) < REGISTRY.index(recognize_git)


def test_git_config_injection_corpus_consistency(ctx: Context) -> None:
    """Pitfall 5: the corpus ``!= allow`` green is explained by an explicit abstain.

    The corpus ``git -c core.fsmonitor=touch status`` vector passes its
    ``!= allow`` guard whether the recognizer abstains OR asks — so the corpus
    green alone does not prove the recognizer abstains. Re-pin the direct
    ``is None`` here so the corpus green is attributable to recognize_git's
    explicit ``-c`` abstain, not coincidence.
    """
    assert recognize_git("git -c core.fsmonitor=touch status", ctx) is None

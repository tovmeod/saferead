"""Boundary tests for the read-only ``adb`` recognizer (REC-07 / TEST-02).

``adb`` is the ONLY tool in this phase where ``allow`` is a genuine read-only
proof (unlike pytest/gradle, which execute project code). Two surfaces:

1. A subcommand ALLOWLIST (``_SAFE_ADB``): the six proven-safe read-only
   subcommands (``logcat``/``devices``/``get-state``/``get-serialno``/
   ``version``/``help``) auto-allow in their BARE form, plus the audited
   read-only flags per subcommand (only ``devices -l``/``--long``). Any other
   subcommand — push/pull/install/uninstall/sync/start-server/kill-server/
   root/unroot/remount/connect/disconnect/forward/reverse/bugreport — abstains
   BY OMISSION (D8-05). A mutating FLAG on an allowlisted subcommand also
   abstains: ``adb logcat -c``/``--clear`` clears the device log buffer,
   ``-f``/``--file``/``-r``/``-n`` write/rotate device files (T-08-01b).

2. ``adb shell <cmd>``: the remote command string is RE-DECOMPOSED through the
   SAME core engine ``fold`` (D8-06 — the seam Phase 13's ssh-journalctl
   recognizer inherits). Allow only when every inner segment is recognized
   read-only; bare ``adb shell`` (interactive), an inner mutation, an inner
   operator/redirect, an outer host-redirect, a shell option, or a tokenizer
   abstain all abstain. Lossy token re-join can only OVER-segment (never merge),
   so the re-decompose cannot create a false-allow.

Test-name contract (load-bearing, MEMORY.md silent-skip lesson, D8-09): the
``-k`` filter selects on the substrings ``adb`` + ``allow``/``abstain`` (+
``shell`` for the re-entry cases). A test whose name misses these substrings is
silently NOT run.
"""

from __future__ import annotations

import pytest

from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers.adb import recognize_adb


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- read-only subcommand allowlist: bare form allow ----------------------


@pytest.mark.parametrize(
    "segment",
    [
        "adb logcat",
        "adb devices",
        "adb get-state",
        "adb get-serialno",
        "adb version",
        "adb help",
        "adb devices -l",  # audited read-only flag (long listing)
        "adb logcat >/dev/null",  # discard redirect on the outer tail
    ],
)
def test_adb_readonly_subcommand_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_adb(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "adb"


# --- write / daemon / connection subcommands abstain ----------------------


@pytest.mark.parametrize(
    "segment",
    [
        "adb push a b",
        "adb pull a",
        "adb install a.apk",
        "adb uninstall pkg",
        "adb sync",
        "adb start-server",
        "adb kill-server",
        "adb root",
        "adb unroot",
        "adb remount",
        "adb connect h",
        "adb disconnect",
        "adb forward x y",
        "adb reverse x y",
        "adb bugreport",
    ],
)
def test_adb_mutating_subcommand_abstain(segment: str, ctx: Context) -> None:
    assert recognize_adb(segment, ctx) is None


# --- mutating / unaudited FLAGS on an allowlisted subcommand abstain -------


@pytest.mark.parametrize(
    "segment",
    [
        "adb logcat -c",  # clears the device log buffer (mutation)
        "adb logcat --clear",  # long form
        "adb logcat -f /sdcard/x",  # writes a device file
        "adb logcat --file=/sdcard/x",  # =value form
        "adb logcat -r 16",  # --rotate-kbytes (writes/rotates)
        "adb logcat -n 5",  # rotate count
        "adb devices --bogus",  # unaudited flag -> abstain by omission
    ],
)
def test_adb_mutating_flag_abstain(segment: str, ctx: Context) -> None:
    assert recognize_adb(segment, ctx) is None


# --- global options + bare adb abstain (free coverage loss) ----------------


@pytest.mark.parametrize(
    "segment",
    [
        "adb -s SERIAL logcat",  # global option not handled -> abstain
        "adb",  # bare adb (no subcommand)
    ],
)
def test_adb_global_option_abstain(segment: str, ctx: Context) -> None:
    assert recognize_adb(segment, ctx) is None


# --- adb shell re-entry: read-only remote command allow --------------------


@pytest.mark.parametrize(
    "segment",
    [
        "adb shell cat /x",
        "adb shell ls -la",
        "adb shell grep foo /x",
    ],
)
def test_adb_shell_readonly_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_adb(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "adb"


# --- adb shell re-entry: mutation / interactive / option abstain -----------


@pytest.mark.parametrize(
    "segment",
    [
        "adb shell",  # bare interactive shell -> abstain
        "adb shell rm -rf /",  # inner engine veto (unrecognized segment)
        "adb shell getprop",  # Android reader not in our recognizers (accepted)
        "adb shell -t cat /x",  # shell option -> abstain (no shell-opt allowlist)
    ],
)
def test_adb_shell_mutating_abstain(segment: str, ctx: Context) -> None:
    assert recognize_adb(segment, ctx) is None


# --- adb shell re-entry: inner operator / redirect re-fold abstain ---------


@pytest.mark.parametrize(
    "segment",
    [
        'adb shell "ls && rm -rf /"',  # inner && operator splits to a mutation
        'adb shell "rm -rf /; reboot"',  # inner ; operator
        'adb shell "cat >/etc/passwd"',  # inner redirect to a real file
        "adb shell 'echo a;b'",  # inner ; operator (single-quoted)
        'adb shell "$(id)"',  # tokenizer abstains on the expansion
    ],
)
def test_adb_shell_inner_operator_abstain(segment: str, ctx: Context) -> None:
    assert recognize_adb(segment, ctx) is None


# --- outer-tail fence: a host redirect OUTSIDE the remote string abstains ---


@pytest.mark.parametrize(
    "segment",
    [
        'adb shell "echo hi" >/etc/passwd',  # redirect outside the quotes
        "adb logcat >/etc/passwd",  # non-safe redirect on a bare subcommand
    ],
)
def test_adb_outer_redirect_abstain(segment: str, ctx: Context) -> None:
    assert recognize_adb(segment, ctx) is None


# --- live fold-path wiring (Task 2 analog, mirrors test_find.py:103-111) ----


def test_adb_allow_through_fold(ctx: Context) -> None:
    verdict = fold(["adb devices"], ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


def test_adb_shell_mutating_through_fold_abstain(ctx: Context) -> None:
    assert fold(["adb shell rm -rf /"], ctx) is None

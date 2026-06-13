"""Boundary tests for the read-only ``ssh`` recognizer (SSH-02 / TEST-02).

Two surfaces:

1. **SSH option gate (D-06/D-07):** A minimal audited connection option
   allowlist (``-p``/``-i``/``-l``/``-F``, each consuming a value token); hard
   rejects (``-o``, ``-L``/``-R``/``-D`` forwards, ``-t`` pty); bare interactive
   ``ssh host`` (no remote command) abstains.

2. **Remote re-fold (D-01/D-02/CR-01):** The remote command string is sliced
   RAW from the segment (quoting preserved) and re-folded through
   ``_fold_readonly_ssh`` — a SCOPED allowlist (reader/find/sed/git/journalctl).
   The scoped fold MUST NOT include pytest/gradle/adb/psql/python — those whose
   ``allow`` is an opt-in TRUST grant, not a genuine read-only proof. Folding
   through the full REGISTRY would launder that local trust into an ssh-side
   genuine-read-only allow — the cardinal false-allow (CR-01, D-02,
   [[engine-reentry-trust-laundering]]).

Test-name contract (load-bearing, MEMORY.md silent-skip lesson, D8-09): the
``-k`` filter selects on substrings ``ssh`` + ``allow``/``abstain`` (+
``fold``/``trust_laundering``). A test whose name misses these substrings is
silently NOT run.
"""

from __future__ import annotations

import pytest

from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers.ssh import recognize_ssh
from safe_read_hook.tokenizer import tokenize


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- ssh remote read-only allow -------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "ssh host journalctl",
        "ssh host journalctl -u nginx",
        "ssh host journalctl --unit=sshd",
        "ssh host journalctl -n 50 --no-pager",
        "ssh host cat /var/log/syslog",
        "ssh host grep foo /var/log/syslog",
        "ssh host ls /var/log",
        "ssh host find /var/log -name '*.log'",
        "ssh host git log",
        "ssh host git status",
        "ssh host sed -n '1p' /var/log/syslog",
    ],
)
def test_ssh_remote_readonly_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_ssh(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "ssh"


# --- ssh with admitted connection options allow ----------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "ssh -p 2222 host journalctl -u nginx",
        "ssh -i ~/.ssh/id_rsa host cat /var/log/syslog",
        "ssh -l root host journalctl",
        "ssh -F /etc/ssh/config host git log",
        "ssh -p 22 user@host journalctl -u sshd",
    ],
)
def test_ssh_connection_opts_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_ssh(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "ssh"


# --- ssh hard-reject option abstain (D-07) ---------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "ssh -L 8080:localhost:8080 host journalctl -u nginx",
        "ssh -R 9090:host:9090 host journalctl",
        "ssh -D 1080 host journalctl",
        "ssh -t host journalctl",
        "ssh -o ProxyCommand=evil host journalctl",
        "ssh -o RemoteCommand=id host journalctl",
        "ssh -o LocalCommand=id host journalctl",
        "ssh -X host journalctl",  # unaudited option -> abstain
    ],
)
def test_ssh_hard_reject_option_abstain(segment: str, ctx: Context) -> None:
    assert recognize_ssh(segment, ctx) is None


# --- bare interactive ssh abstain (D-07) ----------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "ssh host",  # no remote command
        "ssh user@host",  # no remote command
    ],
)
def test_ssh_bare_interactive_abstain(segment: str, ctx: Context) -> None:
    assert recognize_ssh(segment, ctx) is None


# --- remote mutation / unrecognized abstain --------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "ssh host rm -rf /",  # inner unrecognized -> abstain
        "ssh host tee /tmp/x",  # inner write
        "ssh host journalctl --vacuum-size=1M",
        "ssh host journalctl -f",
        "ssh host journalctl --rotate",
        "ssh host journalctl --flush",
        "ssh host journalctl --bogus",  # unaudited flag
    ],
)
def test_ssh_remote_mutation_abstain(segment: str, ctx: Context) -> None:
    assert recognize_ssh(segment, ctx) is None


# --- CR-01 trust-laundering abstain (D-02) ---------------------------------
#
# These MUST NOT allow even though adb/pytest/gradle allow locally. The
# ssh re-fold uses a SCOPED allowlist (reader/find/sed/git/journalctl) and
# MUST exclude trust-grant recognizers. Tested through the live engine fold
# (the path the hook actually takes), mirroring test_adb.py trust-laundering
# section.


@pytest.mark.parametrize(
    "segment",
    [
        "ssh host pytest",
        "ssh host gradle build",
        "ssh host ./gradlew assembleRelease",
        "ssh host adb devices",
        "ssh host psql -c 'SELECT 1'",
        "ssh host python -c 'print(1)'",
    ],
)
def test_ssh_trust_laundering_abstain(segment: str, ctx: Context) -> None:
    assert fold(tokenize(segment).segments, ctx) is None


# --- outer redirect abstain (D-08) ----------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "ssh host journalctl -u nginx >/etc/passwd",
        "ssh host cat /var/log >/etc/passwd",
    ],
)
def test_ssh_outer_redirect_abstain(segment: str, ctx: Context) -> None:
    assert recognize_ssh(segment, ctx) is None


# --- live fold-path wiring ------------------------------------------------


def test_ssh_allow_through_fold(ctx: Context) -> None:
    verdict = fold(["ssh host journalctl -u nginx"], ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "ssh"


def test_ssh_mutating_through_fold_abstain(ctx: Context) -> None:
    assert fold(["ssh host rm -rf /"], ctx) is None


# --- journalctl also allows locally (D-03: standalone REGISTRY entry) ------


def test_journalctl_local_allow_through_fold(ctx: Context) -> None:
    """D-03: local journalctl auto-allows via the standalone REGISTRY entry."""
    verdict = fold(["journalctl -u nginx"], ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "journalctl"

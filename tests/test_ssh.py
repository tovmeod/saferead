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
``fold``/``trust_laundering``). REC-08 ssh-scope tests use ``root``/``scope``
so ``-k "root or scope"`` selects them (14-03 scope-wiring tests).
"""

from __future__ import annotations

import pytest

from safe_read_hook.config import ResolvedConfig, builtin_config
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


# --- REC-08 / 14-03: ssh-scope wiring + ssh_allowed_roots gate -------------
#
# These tests verify the 14-03 change: _fold_readonly_ssh must pass a derived
# Context with read_scope="ssh" so the inner reader/find/sed gate consults
# ssh_allowed_roots (not local_allowed_roots) and abstains on relative remote
# operands before resolution (SC#3 / T-14-08 / T-14-09 / T-14-10).
#
# Test-name contract: names contain "root" and/or "scope" so
#   pytest -k "root or scope"
# selects the new REC-08 scope tests.


def _ssh_cfg(
    *,
    ssh_roots: frozenset[str] | None,
    local_roots: frozenset[str] | None = None,
) -> ResolvedConfig:
    """Return a ResolvedConfig with the given root lists; other fields = builtin."""
    base = builtin_config()
    return ResolvedConfig(
        protected_branches=base.protected_branches,
        gated_subcommands=base.gated_subcommands,
        disabled_recognizers=base.disabled_recognizers,
        log_enabled=base.log_enabled,
        log_path=base.log_path,
        python_allowed_methods=base.python_allowed_methods,
        python_allowed_modules=base.python_allowed_modules,
        local_allowed_roots=local_roots,
        ssh_allowed_roots=ssh_roots,
    )


# T-14-09: absolute remote path under ssh_allowed_roots -> allow
@pytest.mark.parametrize(
    "segment",
    [
        "ssh host cat /remote/allowed/file.log",
        "ssh host ls /remote/allowed",
        "ssh host find /remote/allowed -name '*.log'",
        "ssh host grep foo /remote/allowed/file.log",
        "ssh host sed -n '1p' /remote/allowed/file.log",
    ],
)
def test_ssh_root_scope_absolute_under_ssh_root_allow(segment: str) -> None:
    """Absolute remote path under ssh_allowed_roots allows (T-14-09)."""
    cfg = _ssh_cfg(ssh_roots=frozenset({"/remote/allowed"}))
    ctx = Context(cwd="/local/cwd", config=cfg)
    verdict = recognize_ssh(segment, ctx)
    assert verdict is not None, f"Expected allow; got abstain for: {segment!r}"
    assert verdict.decision == "allow"
    assert verdict.tag == "ssh"


# T-14-09: absolute remote path NOT under ssh_allowed_roots -> abstain
@pytest.mark.parametrize(
    "segment",
    [
        "ssh host cat /etc/passwd",
        "ssh host ls /var/log",
        "ssh host find /home/user -name '*.conf'",
    ],
)
def test_ssh_root_scope_absolute_outside_ssh_root_abstain(segment: str) -> None:
    """Absolute remote path outside ssh_allowed_roots abstains (T-14-09)."""
    cfg = _ssh_cfg(ssh_roots=frozenset({"/remote/allowed"}))
    ctx = Context(cwd="/local/cwd", config=cfg)
    assert recognize_ssh(segment, ctx) is None, (
        f"Expected abstain (outside ssh root); got allow for: {segment!r}"
    )


# T-14-08: remote RELATIVE path operand -> ABSTAIN (SC#3, login dir unknowable)
@pytest.mark.parametrize(
    "segment",
    [
        "ssh host cat relative/file.log",
        "ssh host cat some/path/to/file",
        "ssh host ls logs",
        "ssh host find . -name '*.log'",
        "ssh host grep foo relative/file",
        "ssh host sed -n '1p' relative/file",
    ],
)
def test_ssh_root_scope_relative_remote_operand_abstain(segment: str) -> None:
    """Remote relative path abstains before resolution (T-14-08 / SC#3).

    The remote login dir is unknowable; local cwd resolution would be wrong.
    """
    # Even a permissive ssh root list must NOT allow relative remote operands.
    cfg = _ssh_cfg(ssh_roots=None)  # None = allow-any; still must abstain on relative
    ctx = Context(cwd="/local/cwd", config=cfg)
    assert recognize_ssh(segment, ctx) is None, (
        f"Expected abstain (relative remote operand); got allow for: {segment!r}"
    )


# T-14-09: LOCAL list covers the path, SSH list does NOT -> abstain
# Proves the re-fold consults ssh_allowed_roots, not local_allowed_roots.
@pytest.mark.parametrize(
    "segment",
    [
        "ssh host cat /etc/passwd",
        "ssh host ls /etc",
        "ssh host cat /var/log/syslog",
    ],
)
def test_ssh_root_scope_local_root_not_consulted_abstain(segment: str) -> None:
    """Local root covering the path does NOT allow under ssh scope (T-14-09)."""
    # /etc and /var are under local_roots but NOT under ssh_roots.
    cfg = _ssh_cfg(
        local_roots=frozenset({"/etc", "/var"}),
        ssh_roots=frozenset({"/remote/allowed"}),
    )
    ctx = Context(cwd="/local/cwd", config=cfg)
    assert recognize_ssh(segment, ctx) is None, (
        f"Expected abstain (local root consulted instead of ssh root); "
        f"got allow for: {segment!r}"
    )


# T-14-10: ssh scope does NOT leak to the outer (non-ssh) local segment
def test_ssh_scope_does_not_leak_to_outer_local_segment() -> None:
    """read_scope='ssh' set inside _fold_readonly_ssh must not affect the outer ctx."""
    # After recognize_ssh returns, a follow-up local read with local_allowed_roots
    # should still use local_allowed_roots (not ssh_allowed_roots).
    from safe_read_hook.recognizers.reader import recognize_reader

    cfg = _ssh_cfg(
        local_roots=frozenset({"/local/allowed"}),
        ssh_roots=frozenset({"/remote/allowed"}),
    )
    outer_ctx = Context(cwd="/local/cwd", config=cfg)

    # First: run ssh recognition (this must not mutate outer_ctx.read_scope).
    _ = recognize_ssh("ssh host cat /remote/allowed/file", outer_ctx)

    # Now verify outer_ctx.read_scope is still "local" (not "ssh").
    assert outer_ctx.read_scope == "local", (
        f"ssh re-fold leaked read_scope='ssh' into outer ctx; "
        f"outer_ctx.read_scope={outer_ctx.read_scope!r}"
    )

    # Also verify: a local read of /local/allowed/f still allows with the outer ctx.
    verdict = recognize_reader("cat /local/allowed/file.txt", outer_ctx)
    assert verdict is not None, (
        "Local read under local root should allow after ssh re-fold"
    )
    assert verdict.decision == "allow"


# D-02: unset ssh_allowed_roots -> ssh absolute path allows (no regression)
@pytest.mark.parametrize(
    "segment",
    [
        "ssh host cat /any/absolute/path",
        "ssh host ls /etc",
        "ssh host journalctl -u nginx",
    ],
)
def test_ssh_root_scope_unset_ssh_roots_allow(segment: str) -> None:
    """Unset ssh_allowed_roots = allow-any for absolute paths (D-02 no regression)."""
    cfg = _ssh_cfg(ssh_roots=None)  # None = allow-any
    ctx = Context(cwd="/local/cwd", config=cfg)
    verdict = recognize_ssh(segment, ctx)
    assert verdict is not None, (
        f"Expected allow (unset ssh_roots = allow-any); got abstain for: {segment!r}"
    )
    assert verdict.decision == "allow"

"""Boundary tests for the read-only ``journalctl`` recognizer (SSH-01 / 13-01).

``journalctl`` is a genuine read-only tool: ``allow`` is a read-only proof (not
opt-in trust). Two policy layers:

1. FLAG ALLOWLIST (D-04): only audited read-only flags pass — ``-u``/``--unit``,
   ``--since``/``--until``, ``-n``/``--lines``, ``-p``/``--priority``,
   ``-o``/``--output``, ``-r``/``--reverse``, ``-k``/``--dmesg``,
   ``-b``/``--boot``, ``-g``/``--grep``, ``--no-pager``, ``-e``/``--pager-end``.
   Any unaudited flag abstains BY OMISSION (allowlist polarity).

2. HARD REJECTS (D-05): ``-f``/``--follow`` (streaming), ``--vacuum*``/
   ``--rotate``/``--flush`` (mutations). These are absent from the allowlist so
   abstain by construction.

The standalone recognizer is also imported by the Phase 13 Plan 02 ssh recognizer
for the scoped re-fold allowlist (D-03 — single source of truth, no duplicated
logic).

Test-name contract (load-bearing, MEMORY.md silent-skip lesson): the ``-k``
filter selects on the substrings ``journalctl`` + ``allow``/``abstain``. A test
whose name misses these substrings is silently NOT run.
"""

from __future__ import annotations

import pytest

from saferead.context import Context
from saferead.recognizers.journalctl import recognize_journalctl


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- read-only allow cases (D-04 flag allowlist) ----------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "journalctl",  # bare form (no flags)
        "journalctl -u nginx",  # unit filter
        "journalctl --unit=sshd",  # long =value form
        "journalctl -n 50",  # last N lines
        "journalctl --lines=100",
        "journalctl -p err",  # priority
        "journalctl --priority=warning",
        "journalctl -o json",  # output format (read)
        "journalctl --output=short",
        "journalctl -r",  # reverse (read)
        "journalctl --reverse",
        "journalctl -k",  # kernel messages (dmesg)
        "journalctl --dmesg",
        "journalctl -b",  # current boot
        "journalctl --boot",
        "journalctl -b -1",  # previous boot (-1 is a numeric operand, not a flag)
        "journalctl -g foo",  # grep pattern
        "journalctl --grep=ERROR",
        "journalctl --no-pager",
        "journalctl -e",  # jump to end
        "journalctl --pager-end",
        "journalctl --since yesterday",  # time range
        "journalctl --until '2026-01-01'",
        "journalctl -u nginx -n 100 --no-pager",  # combined
        "journalctl -n100",  # glued VALUE short flag (-n + value) still admitted
        "journalctl -unginx",  # glued VALUE short flag (-u + value) still admitted
    ],
)
def test_journalctl_readonly_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_journalctl(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "journalctl"


# --- abstain cases (D-05 hard rejects + unaudited flags) --------------------


@pytest.mark.parametrize(
    "segment",
    [
        "journalctl -f",  # D-05: follow/stream
        "journalctl --follow",
        "journalctl --vacuum-size=1G",  # D-05: mutation
        "journalctl --vacuum-time=1week",
        "journalctl --vacuum-files=5",
        "journalctl --rotate",  # D-05: mutation
        "journalctl --flush",  # D-05: mutation
        "journalctl --bogus",  # unaudited -> abstain by omission
        "journalctl -z",  # unknown short -> abstain
        "journalctl -ef",  # CR-01: POSIX bundle (-e + -f); -f is a D-05 reject
        "journalctl -kf",  # CR-01: bundle hides --follow behind boolean head -k
        "journalctl -rf",  # CR-01: bundle hides --follow behind boolean head -r
    ],
)
def test_journalctl_readonly_abstain(segment: str, ctx: Context) -> None:
    assert recognize_journalctl(segment, ctx) is None


# --- outer redirect abstain --------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "journalctl -u nginx >/etc/passwd",  # non-safe redirect
        "journalctl >/etc/passwd",
    ],
)
def test_journalctl_outer_redirect_abstain(segment: str, ctx: Context) -> None:
    assert recognize_journalctl(segment, ctx) is None

"""Boundary tests for the read-only ``sed`` recognizer (REC-05 / TEST-02).

The cardinal axis is the allow/abstain BOUNDARY for ``sed``: a command whose
options are ALL on an EXACT-MATCH allowlist and whose script(s) classify as
provably read-only auto-allow, while EVERY in-place form, ``-f`` scriptfile,
write/exec/read-arbitrary script command, and the ``s///w``/``s///e`` hidden
flags abstain (D-01/D-02). "Reject ``-i`` only" is a cardinal false-allow — sed
writes/execs independent of ``-i`` — so the recognizer parses the script as a
real mini-language and abstains the moment it is unsure.

Exact-match option matching (Pitfall 2 / C1 closure): ``-ie``/``-i.bak``/``-i``/
``--in-place``/the getopt bundle ``-ni`` all fail exact-match against the safe
option allowlist and abstain BY CONSTRUCTION — no ``-i`` substring/word-boundary
reasoning anywhere.

Test-name contract (load-bearing, MEMORY.md silent-skip lesson): the ``-k``
filter selects on the substrings ``sed``, ``readonly``/``allow``, ``abstain``,
``inplace``, ``script``. A test whose name misses every substring is silently
NOT run.
"""

from __future__ import annotations

import pytest

from safe_read_hook.config import ResolvedConfig
from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers.sed import recognize_sed


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- read-only scripts / options allow ------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "sed 's/a/b/' f",
        "sed -n '1,10p' f",
        "sed -n '2,5p' f",
        "sed -E 's/(a)/[\\1]/g' f",
        "sed -r 's/a/b/g' f",
        "sed -e 's/a/b/' -e 's/c/d/' f",
        "sed 'y/abc/xyz/' f",
        "sed -n '$=' f",
        "sed '/re/d' f",
        "sed 's/a/b/gp' f",
        "sed 's/a/b/2' f",
        "sed -n 'p' f",
        "sed '1d' f",
        "sed -n '/start/,/end/p' f",
        "sed 'b end; s/a/b/' f",  # label stops at ';' then a safe command
        "sed ':loop' f",
    ],
)
def test_sed_readonly_script_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_sed(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "sed"


# --- in-place forms abstain (the C1 exact-match closure) ------------------


@pytest.mark.parametrize(
    "segment",
    [
        "sed -i s/a/b/ f",
        "sed -ie s/a/b/ f",
        "sed -i.bak s/a/b/ f",
        "sed --in-place s/a/b/ f",
        "sed --in-place=.bak s/a/b/ f",
        "sed -ni s/a/b/ f",  # getopt bundle: -ni not on the allowlist
    ],
)
def test_sed_inplace_forms_abstain(segment: str, ctx: Context) -> None:
    assert recognize_sed(segment, ctx) is None


# --- -f scriptfile abstains (script body unseeable) -----------------------


@pytest.mark.parametrize(
    "segment",
    [
        "sed -f script.sed f",
        "sed --file=script.sed f",
    ],
)
def test_sed_scriptfile_abstain(segment: str, ctx: Context) -> None:
    assert recognize_sed(segment, ctx) is None


# --- write / exec / read-arbitrary script commands abstain ----------------


@pytest.mark.parametrize(
    "segment",
    [
        "sed '1,5w out' f",
        "sed 'w out' f",
        "sed 'W out' f",
        "sed 'r /etc/passwd' f",
        "sed 'R f' f",
        "sed 'F' f",
        "sed 'e cmd' f",
        "sed 'a\\text' f",  # append (parse-hostile continuation -> abstain)
        "sed 'i\\text' f",
        "sed 'c\\text' f",
        "sed 'b end w out' f",  # label must NOT swallow the trailing w
        "sed 'b end; w out' f",
    ],
)
def test_sed_write_exec_script_abstain(segment: str, ctx: Context) -> None:
    assert recognize_sed(segment, ctx) is None


# --- s/// hidden-write/exec flags abstain (incl. exotic delimiters) -------


@pytest.mark.parametrize(
    "segment",
    [
        "sed 's/a/b/w out' f",
        "sed 's/a/b/e' f",
        "sed 's|a|b|w /etc/x' f",
        "sed 's#a#b#e' f",
        "sed 's/a/b/W out' f",
    ],
)
def test_sed_substitution_hidden_flag_script_abstain(
    segment: str, ctx: Context
) -> None:
    assert recognize_sed(segment, ctx) is None


# --- discriminating cardinal-boundary: a real command vs literal field data


@pytest.mark.parametrize(
    "segment",
    [
        # A ``w`` / ``;`` inside the s/// replacement FIELD is literal data, so
        # the script is still a single read-only substitution -> allow.
        "sed 's/x/yz; w out/' f",
        "sed '{p;d}' f",  # a BARE command group classifies its read-only contents
    ],
)
def test_sed_literal_field_data_script_allow(segment: str, ctx: Context) -> None:
    verdict = recognize_sed(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


@pytest.mark.parametrize(
    "segment",
    [
        "sed 's/x/y/; w out' f",  # a real w command AFTER a complete s/// -> abstain
        "sed 's/a\\/b/c/w out' f",  # escaped delimiter, the trailing w is a real flag
        "sed 'p;d;e cmd' f",  # an exec reached after read-only commands -> abstain
        # An ADDRESSED command group (``/re/{...}``) abstains: the parser admits
        # bare ``{`` between commands but not after an address. Coverage loss,
        # NOT a false-allow (the cardinal-safe direction).
        "sed '/re/{p;d}' f",
    ],
)
def test_sed_real_command_after_field_script_abstain(
    segment: str, ctx: Context
) -> None:
    assert recognize_sed(segment, ctx) is None


# --- unknown command / tokenizer abstain ----------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        'sed "$(id)" f',  # tokenizer abstains on the expansion (D-06)
        "sed 's/a/b' f",  # unbalanced s/// -> abstain (D-02)
        "sed 'Z' f",  # unknown command letter -> abstain
        "sed 's/a/b/x' f",  # unknown s/// flag -> abstain
        "sed 's/a/b/' >/etc/passwd",  # non-safe redirect target
    ],
)
def test_sed_unknown_or_ambiguous_script_abstain(segment: str, ctx: Context) -> None:
    assert recognize_sed(segment, ctx) is None


# --- /tmp redirect tail allows (shared helper) ----------------------------


def test_sed_readonly_tmp_redirect_allow(ctx: Context) -> None:
    verdict = recognize_sed("sed 's/a/b/' f >/tmp/out", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- live fold-path wiring (Task 2 analog: D-07 corpus flip) --------------


def test_sed_inplace_corpus_flip_through_fold_abstain(ctx: Context) -> None:
    # The live corpus vector ``sed -ie s/a/b/ f`` observably abstains through
    # tokenize -> recognize -> fold (D-07).
    assert fold(["sed -ie s/a/b/ f"], ctx) is None


def test_sed_readonly_allow_through_fold(ctx: Context) -> None:
    verdict = fold(["sed 's/a/b/' f"], ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# ---------------------------------------------------------------------------
# REC-08: read-root gating in sed.py (14-02)
# Test names contain "root" so -k "root" selects them all.
# ---------------------------------------------------------------------------


def _sed_root_ctx(roots: frozenset[str] | None, cwd: str = "/work") -> Context:
    """Return a Context with local_allowed_roots set for root-gate tests."""
    return Context(
        cwd=cwd,
        config=ResolvedConfig(
            protected_branches=frozenset({"master", "main"}),
            gated_subcommands=frozenset({"add", "commit", "stash"}),
            disabled_recognizers=frozenset(),
            local_allowed_roots=roots,
        ),
    )


# --- root: file operand under allowed root -> allow ---


def test_sed_root_allow_file_operand_under_root() -> None:
    """sed -n p /allowed/f with root={'/allowed'} -> allow."""
    ctx = _sed_root_ctx(frozenset({"/allowed"}), cwd="/work")
    verdict = recognize_sed("sed -n p /allowed/f", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: file operand outside any root -> abstain ---


def test_sed_root_abstain_file_operand_outside_root() -> None:
    """sed -n p /etc/passwd with root={'/allowed'} -> abstain."""
    ctx = _sed_root_ctx(frozenset({"/allowed"}), cwd="/work")
    assert recognize_sed("sed -n p /etc/passwd", ctx) is None


# --- root: unset (None) root list -> allow-any (no regression, D-02) ---


def test_sed_root_unset_list_allows_any_file() -> None:
    """Unset roots (None) -> allow-any: sed -n p /etc/passwd still allows."""
    ctx = _sed_root_ctx(None, cwd="/work")
    verdict = recognize_sed("sed -n p /etc/passwd", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: operand identification — sed SCRIPT is NOT gated as a path ---


def test_sed_root_operand_script_not_gated_as_path() -> None:
    """The sed script (s/a/b/) is NEVER treated as a path operand.

    D-05: the script is excluded from file_operands before the gate runs.
    A file under root with a script -> allow.
    """
    ctx = _sed_root_ctx(frozenset({"/allowed"}), cwd="/work")
    verdict = recognize_sed("sed 's/a/b/' /allowed/f", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: no file operand (reads stdin) with set root -> allow (D-06) ---


def test_sed_root_no_file_operand_stdin_allow() -> None:
    """sed -n p (no file, reads stdin) with set root -> allow (D-06 no-path unaffected)."""
    ctx = _sed_root_ctx(frozenset({"/allowed"}), cwd="/work")
    verdict = recognize_sed("sed -n p", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: multiple file_operands all under root -> allow ---


def test_sed_root_multiple_file_operands_all_under_root_allow() -> None:
    """Multiple file_operands all under root -> allow."""
    ctx = _sed_root_ctx(frozenset({"/allowed"}), cwd="/work")
    verdict = recognize_sed("sed -e 's/a/b/' /allowed/f1 /allowed/f2", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- root: multiple file_operands — any one outside root -> abstain ---


def test_sed_root_one_file_operand_outside_root_abstains() -> None:
    """Multiple file_operands but one outside root -> abstain."""
    ctx = _sed_root_ctx(frozenset({"/allowed"}), cwd="/work")
    assert recognize_sed("sed -e 's/a/b/' /allowed/f1 /etc/passwd", ctx) is None


# --- root: ssh scope — relative file operand abstains pre-resolution (SC#3) ---


def test_sed_root_scope_ssh_relative_file_operand_abstains() -> None:
    """With read_scope='ssh', a RELATIVE file operand abstains before resolution (SC#3)."""
    ctx = Context(
        cwd="/allowed",
        config=ResolvedConfig(
            protected_branches=frozenset({"master", "main"}),
            gated_subcommands=frozenset({"add", "commit", "stash"}),
            disabled_recognizers=frozenset(),
            ssh_allowed_roots=frozenset({"/allowed"}),
        ),
        read_scope="ssh",
    )
    assert recognize_sed("sed -n p rel/file", ctx) is None


def test_sed_root_scope_ssh_absolute_file_under_root_allows() -> None:
    """With read_scope='ssh', an absolute file operand under ssh_allowed_roots -> allow."""
    ctx = Context(
        cwd="/work",
        config=ResolvedConfig(
            protected_branches=frozenset({"master", "main"}),
            gated_subcommands=frozenset({"add", "commit", "stash"}),
            disabled_recognizers=frozenset(),
            ssh_allowed_roots=frozenset({"/allowed"}),
        ),
        read_scope="ssh",
    )
    verdict = recognize_sed("sed -n p /allowed/f", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"

"""Boundary tests for the minimal reader recognizer.

The point of these tests is the allow/abstain BOUNDARY: the reader must claim a
narrow read-only set and abstain on everything else — especially on write-mode
commands and on redirects to real files (the cardinal zero-false-allow cases).
"""

from __future__ import annotations

import pytest

from safe_read_hook.analyzers import ANALYZERS
from safe_read_hook.context import Context
from safe_read_hook.recognizers.reader import recognize_reader
from safe_read_hook.verdict import Verdict


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- allow cases ----------------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "cat foo.txt",
        "echo hi",
        "printf '%s' x",
        "head -5 f",
        "grep x f",
        "wc -l f",
        "ls -la",
        "echo hi >/dev/null",
        "grep x f 2>&1",
        # CR-02: common safe-flag reads stay allow via the per-command allowlist.
        "grep -i needle f",
        "head -n 5 f",
        "tail -n 20 f",
        "df -h",
        "du -sh d",
        "cut -d: -f1 f",  # value-bearing short flags (2-char-head match)
        "tail -5 f",  # historic -NUM line-count form
        "file /etc/hosts",  # bare file PATH stays allow
        # sort read-only forms (D-04/D-05) — separate-token and glued value flags
        "sort -n f",
        "sort -r f",
        "sort -u f",
        "sort -c f",
        "sort -k2 f",  # glued value-bearing head (-k)
        "sort -t: f",  # glued value-bearing head (-t)
        "sort -S 2M f",  # separate-token buffer size (D-05 admit)
        "sort -S2M f",  # glued value-bearing head (-S)
        "sort --reverse f",  # long form
        # single-operand / stdin reads preserved under the W3 fence (D-10)
        "uniq f",
        "uniq -",  # stdin
        "xxd f",
    ],
)
def test_reader_allows_read_only(segment: str, ctx: Context) -> None:
    verdict = recognize_reader(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "reader"


def test_reader_cat_is_allow_prover(ctx: Context) -> None:
    """The D-11 prover: cat foo.txt -> allow with tag 'reader'."""
    verdict = recognize_reader("cat foo.txt", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "reader"


# --- abstain (no-match) cases ---------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "rm -rf x",  # not read-only -> the veto input for the compound proof
        "tee f",  # write-mode command, not claimed (deferred phase)
        "sort -o f",  # write-mode command, not claimed (deferred phase)
        "echo x >/tmp/foo",  # redirect to a real file -> no false-allow (999.1 #7)
        "echo x >/tmp/../etc/passwd",  # path-escaping redirect -> no false-allow
        "cat foo.txt > out.txt",  # redirect to a user file -> no false-allow
        "ls &",  # background control op -> no false-allow (rewrite regression guard)
        'cat "$(id)"',  # cmdsub: tokenizer abstains; reader carries no $-logic
        'cat "${x@P}"',  # brace-body transform: tokenizer abstains
        "echo $((1 << 2))",  # arithmetic: tokenizer allowlist holds the abstain
        # sort hidden-write/exec forms (D-04/D-05/D-11) — never claimed
        "sort -o f",  # W2 output-redirect flag
        "sort --output=f",  # W2 long form
        "sort -ofile f",  # W2 glued long form
        "sort -ro f",  # W4 bundle smuggle (LV-3) — the cardinal close
        "sort -T /x f",  # D-05 omit — temp-dir redirect
        "sort --compress-program=gzip f",  # W6 exec
        # W3 positional output-operand writes (LV-1/LV-2 — D-10)
        "uniq a b",  # uniq IN OUT writes OUT
        "xxd a b",  # xxd in out writes outfile
        # awk: Turing-complete, every invocation abstains (D-01/D-03)
        "awk '{print $1}'",
        'awk \'BEGIN{print > "/etc/x"}\'',
        # tee writes files — unclaimed -> abstain (D-09)
        "tee f",
        "tee out.txt",
    ],
)
def test_reader_abstains(segment: str, ctx: Context) -> None:
    assert recognize_reader(segment, ctx) is None


def test_reader_abstains_on_sort_output_forms(ctx: Context) -> None:
    """W2/W4/W6/LV-3: sort write/exec forms never allow.

    `-o`/`--output`/`-ofile` write a file (W2). `-ro` smuggles `-o` past the
    allowlist via a short-flag bundle (W4/LV-3 — the `sed -ie`/C2 class).
    `--compress-program` execs an arbitrary program (W6). All must abstain.
    """
    for segment in (
        "sort -o f",
        "sort --output=f",
        "sort -ofile f",
        "sort -ro f",
        "sort -no f",
        "sort -uo f",
        "sort --compress-program=gzip f",
        "sort -T /x f",
    ):
        assert recognize_reader(segment, ctx) is None, segment


def test_reader_abstains_on_rm(ctx: Context) -> None:
    """The cardinal no-match: rm -rf x -> None (feeds the engine abstain-veto)."""
    assert recognize_reader("rm -rf x", ctx) is None


# --- CR-01: pagers removed from the read-only allowlist -------------------


@pytest.mark.parametrize(
    "segment",
    [
        "less /etc/passwd",  # LESSOPEN/lesspipe preprocessor exec (live vector)
        "less f",
        "more f",  # ! / v interactive shell-escape
        "bat f",  # pages via less -> inherits LESSOPEN exposure
    ],
)
def test_reader_abstains_on_pagers(segment: str, ctx: Context) -> None:
    """CR-01: less/more/bat are no longer claimed -> abstain (not read-only)."""
    assert recognize_reader(segment, ctx) is None


# --- CR-02: write/exec-capable flags abstain ------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "file -C -m /tmp/mymagic",  # writes /tmp/mymagic.mgc (live vector)
        "file -m /tmp/x",
        "file -s /dev/sda",
        "file -C f",  # any file -<flag> abstains (file = bare form only)
    ],
)
def test_reader_abstains_on_file_flags(segment: str, ctx: Context) -> None:
    """CR-02: `file` has no read-only flag entry -> every `file -<flag>` abstains."""
    assert recognize_reader(segment, ctx) is None


@pytest.mark.parametrize(
    "segment",
    [
        "cat --definitely-not-a-real-flag f",  # unknown long flag
        "cat -x f",  # unknown short flag (cat has no flag entry)
        "tail -f f",  # follow blocks — NOT on tail's read-only list
        "ls -Z",  # unknown flag for ls
        "grep --binary-files=text f",  # unlisted long flag for grep
    ],
)
def test_reader_abstains_on_unknown_flag(segment: str, ctx: Context) -> None:
    """CR-02: a flag NOT on the command's read-only allowlist -> abstain."""
    assert recognize_reader(segment, ctx) is None


def test_reader_discard_redirect_stays_allow(ctx: Context) -> None:
    """A discard redirect never touches a user file -> safe to keep as allow."""
    verdict = recognize_reader("echo hi >/dev/null", ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


# --- analyzer dispatch seam (TOK-03) --------------------------------------


def test_reader_dispatches_python_to_analyzer(
    ctx: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``python -c "<code>"`` shape ROUTES the source to ANALYZERS["python"].

    Proves the seam FIRES (not merely that the shape abstains): the stub
    analyzer returns a sentinel Verdict, and the reader must return exactly
    that — observable only if dispatch actually occurred. The production
    skeleton returns None, so a real ``python -c`` shape abstains.
    """
    sentinel = Verdict("allow", "stub-dispatch", "test.analyzer")
    monkeypatch.setitem(ANALYZERS, "python", lambda source: sentinel)
    verdict = recognize_reader('python -c "import os"', ctx)
    assert verdict is sentinel


def test_reader_python_shape_abstains_with_skeleton(ctx: Context) -> None:
    """With the real skeleton (returns None), a python -c shape -> abstain."""
    assert recognize_reader('python -c "import os"', ctx) is None


# --- W3 positional output-operand fence (D-10) ----------------------------


def test_reader_abstains_on_uniq_positional_write(ctx: Context) -> None:
    """LV-1: `uniq IN OUT` writes its second positional operand -> abstain.

    The live false-allow this fence closes: `_tail_is_safe` accepted any
    non-flag token as a bare path, so `uniq a b` reached `Verdict('allow')`
    today and wrote `b`. Single-operand / stdin reads stay allow.
    """
    assert recognize_reader("uniq a b", ctx) is None
    assert recognize_reader("uniq /tmp/in /tmp/out", ctx) is None
    allowed = recognize_reader("uniq f", ctx)
    assert allowed is not None and allowed.decision == "allow"
    stdin = recognize_reader("uniq -", ctx)
    assert stdin is not None and stdin.decision == "allow"


def test_reader_abstains_on_xxd_positional_write(ctx: Context) -> None:
    """LV-2: `xxd in out` writes its second positional operand -> abstain."""
    assert recognize_reader("xxd a b", ctx) is None
    allowed = recognize_reader("xxd f", ctx)
    assert allowed is not None and allowed.decision == "allow"


# --- awk: unclaimed, Turing-complete -> abstain (D-01/D-03) ----------------


def test_reader_abstains_on_awk(ctx: Context) -> None:
    """D-01/D-03: every awk invocation abstains (no awk allow this phase).

    awk is Turing-complete (`print > file`, `print | "cmd"`, `system()`,
    `getline`); no surface form proves it read-only. Even a benign-looking
    `awk '{print $1}'` abstains, and the corpus output-redirect vector stays
    not-allow.
    """
    assert recognize_reader("awk '{print $1}'", ctx) is None
    assert recognize_reader('awk \'BEGIN{print > "/etc/x"}\'', ctx) is None


# --- tee: unclaimed -> abstain, asserted via a DIRECT call (D-09) ----------


def test_reader_abstains_on_tee(ctx: Context) -> None:
    """D-09: `tee FILE` writes files; tee is unclaimed -> abstain.

    Asserted by calling `recognize_reader('tee f')` DIRECTLY — NOT the compound
    `grep … | tee …`, which abstains via the multi-segment `len(tokens) != 1`
    guard and never observes tee's OWN abstain (RESEARCH §484).
    """
    assert recognize_reader("tee f", ctx) is None
    assert recognize_reader("tee out.txt", ctx) is None


# --- W3 over-fence guard: inputs-only multi-operand reads stay allow -------


@pytest.mark.parametrize(
    "segment",
    [
        "cat a b",
        "diff a b",
        "comm a b",
        "paste a b",
        "grep x f1 f2",
    ],
)
def test_reader_multi_input_stays_allow(segment: str, ctx: Context) -> None:
    """Pitfall 3: the W3 fence is scoped to {uniq,xxd} — inputs-only reads allow.

    `cat`/`diff`/`comm`/`paste`/`grep` take multiple INPUT operands; the fence
    must NOT be a blanket operand-count rule or it breaks these legitimate
    multi-input reads.
    """
    verdict = recognize_reader(segment, ctx)
    assert verdict is not None
    assert verdict.decision == "allow"
    assert verdict.tag == "reader"

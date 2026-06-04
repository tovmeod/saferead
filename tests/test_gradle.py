"""Boundary tests for the opt-in ``gradle``/``gradlew`` recognizer (REC-07 / TEST-02).

The cardinal axis is the allow/abstain BOUNDARY for a gradle launcher. Unlike
``find``/``adb``, ``allow`` here is NOT a read-only proof (D8-01): gradle
evaluates ``build.gradle`` (arbitrary Groovy/Kotlin) at the configuration phase
even for ``tasks``/``help``/``dependencies``, so there is no execution-free form.
The recognizer is a deliberate OPT-IN TRUST grant on the user's OWN project; its
job is to guard the project BOUNDARY (which build/settings/init-script/project
dir runs), not the side-effect boundary. Arbitrary TASK NAMES are allowed.

The guard is a redirection DENYLIST (D8-04) that PORTS the seed blocks
(``--init-script``/``-I``, ``--build-file``/``-b``, ``--settings-file``/``-c``)
AND CLOSES the seed misses (``--project-dir``/``-p``, ``--include-build``,
``--project-cache-dir``, ``--gradle-user-home``/``-g``), each matched in all
THREE token shapes (split / glued-short / long ``=value``).

CRITICAL discrimination (T-08-13): the short blocked flags are CASE-SENSITIVE.
``-p`` (lowercase, project-dir) BLOCKS but ``-P``/``-Pkey=val`` (uppercase,
project property) ALLOWS.

Test-name contract (load-bearing, MEMORY.md silent-skip lesson): the ``-k``
filter selects on the substrings ``gradle``, ``allow``/``abstain``,
``task``/``redirection``. A test whose name misses every substring is silently
NOT run.
"""

from __future__ import annotations

import pytest

from safe_read_hook.context import Context
from safe_read_hook.engine import fold
from safe_read_hook.recognizers.gradle import recognize_gradle


@pytest.fixture
def ctx() -> Context:
    return Context(cwd="/x")


# --- task / launcher allow ------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "gradle build",
        "gradle tasks",
        "gradle help",
        "gradle dependencies",
        "gradle :app:testDebugUnitTest",
        "./gradlew build",
        "./gradlew :app:assembleRelease",
        "/path/to/gradlew test",
        "gradle --info build",
        "gradle clean build",
        "VAR=val gradle build",
        "gradle -Pkey=val build",
        "gradle --stacktrace tasks",
    ],
)
def test_gradle_task_allow(segment: str, ctx: Context) -> None:
    v = recognize_gradle(segment, ctx)
    assert v is not None
    assert v.decision == "allow"
    assert v.tag == "gradle"


@pytest.mark.parametrize(
    "segment",
    [
        "gradle build >/dev/null",
        "gradle tasks 2>&1",
        "gradle build >/tmp/out",
    ],
)
def test_gradle_task_allow_safe_redirection(segment: str, ctx: Context) -> None:
    v = recognize_gradle(segment, ctx)
    assert v is not None
    assert v.decision == "allow"
    assert v.tag == "gradle"


# --- DISCRIMINATION pin: -P (property, ALLOW) vs -p (project-dir, BLOCK) ---


def test_gradle_property_uppercase_allow_not_overblocked(ctx: Context) -> None:
    # ``-Pkey=val`` (uppercase project PROPERTY) must NOT collide with the
    # blocked lowercase ``-p`` (project-dir). Case-sensitive (T-08-13).
    v = recognize_gradle("gradle -Pkey=val build", ctx)
    assert v is not None
    assert v.decision == "allow"


@pytest.mark.parametrize(
    "segment",
    [
        "gradle -Pp build",  # blocked letter ``p`` INSIDE a -P value -> allow
        "gradle -Pgpr.key=val build",  # ``g``/``p`` inside a -P value -> allow
        "gradle -Dorg.gradle.parallel=true build",  # ``g`` inside a -D value -> allow
        "gradle -si tasks",  # benign no-arg cluster (not all clusters over-blocked)
    ],
)
def test_gradle_glued_value_and_benign_cluster_task_allow(
    segment: str, ctx: Context
) -> None:
    # The bundled-cluster scan must NOT trip on a blocked LETTER that lives
    # inside a -P/-D glued VALUE, nor over-block a benign no-arg cluster.
    v = recognize_gradle(segment, ctx)
    assert v is not None
    assert v.decision == "allow"


@pytest.mark.parametrize(
    "segment",
    [
        "gradle -ip /other",  # bundled cluster -i -p (project-dir) -> abstain
        "gradle -ip/other",  # self-contained glued cluster -> abstain
    ],
)
def test_gradle_bundled_cluster_redirection_abstain(
    segment: str, ctx: Context
) -> None:
    # A blocked value-bearing flag NOT at the head of a getopt cluster
    # (``-ip`` = ``-i -p``) would redirect the project; gradle's parser cannot be
    # verified here, so per D8-04 (when unsure, abstain) it blocks.
    assert recognize_gradle(segment, ctx) is None


# --- redirection DENYLIST abstain (ported seed blocks) --------------------


@pytest.mark.parametrize(
    "segment",
    [
        # --init-script / -I  (split / =value / glued)
        "gradle --init-script x",
        "gradle --init-script=x",
        "gradle -I x",
        "gradle -Ix",
        # --build-file / -b
        "gradle --build-file x",
        "gradle --build-file=x",
        "gradle -b x",
        "gradle -bbuild.gradle",
        # --settings-file / -c
        "gradle --settings-file x",
        "gradle --settings-file=x",
        "gradle -c x",
        "gradle -csettings.gradle",
    ],
)
def test_gradle_ported_redirection_flag_abstain(segment: str, ctx: Context) -> None:
    assert recognize_gradle(segment, ctx) is None


# --- redirection DENYLIST abstain (EXTENDED — seed misses, D8-04) ---------


@pytest.mark.parametrize(
    "segment",
    [
        # --project-dir / -p
        "gradle --project-dir x",
        "gradle --project-dir=x",
        "gradle -p x",
        "gradle -p/other",
        # --include-build
        "gradle --include-build x",
        "gradle --include-build=x",
        # --project-cache-dir
        "gradle --project-cache-dir x",
        "gradle --project-cache-dir=x",
        # --gradle-user-home / -g
        "gradle --gradle-user-home x",
        "gradle --gradle-user-home=x",
        "gradle -g x",
        "gradle -g/home",
    ],
)
def test_gradle_extended_redirection_flag_abstain(segment: str, ctx: Context) -> None:
    assert recognize_gradle(segment, ctx) is None


# --- non-launcher / tokenizer abstain -------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        'gradle "$(id)"',  # tokenizer abstain (D8-08)
        "mvn build",  # non-gradle leading word
    ],
)
def test_gradle_non_launcher_task_abstain(segment: str, ctx: Context) -> None:
    assert recognize_gradle(segment, ctx) is None


# --- long-flag prefix-abbreviation redirection abstain (WR-01, D8-04) ------
#
# gradle's CommandLineParser accepts unambiguous PREFIX ABBREVIATIONS of long
# options, so ``--build-f`` resolves to ``--build-file``, ``--init-scr`` to
# ``--init-script``, etc. An exact-membership denylist misses these, leaving a
# build-file/init-script redirect (foreign-project injection) un-blocked. gradle
# is not installed here, so per D8-04 (can't verify -> abstain conservatively)
# ANY ``--xxx`` token that is an unambiguous prefix of a blocked long flag must
# abstain.


@pytest.mark.parametrize(
    "segment",
    [
        "gradle --build-f other.gradle build",  # abbrev of --build-file
        "gradle --init-scr evil.gradle build",  # abbrev of --init-script
        "gradle --settings-f other.gradle",  # abbrev of --settings-file
        "gradle --project-d /other build",  # abbrev of --project-dir
    ],
)
def test_gradle_long_flag_abbreviation_redirection_abstain(
    segment: str, ctx: Context
) -> None:
    assert recognize_gradle(segment, ctx) is None


# --- live fold-path wiring ------------------------------------------------


def test_gradle_allow_through_fold_task(ctx: Context) -> None:
    verdict = fold(["gradle build"], ctx)
    assert verdict is not None
    assert verdict.decision == "allow"


def test_gradle_redirection_through_fold_abstain(ctx: Context) -> None:
    assert fold(["gradle -b other.gradle"], ctx) is None

"""End-to-end tests for the exec-form entrypoint (PKG-05, CORE-06).

Runs ``hooks/safe_read_hook.py`` as a real subprocess feeding a JSON payload on
stdin and asserting the stdout envelope (or empty stdout). This exercises the
whole vertical slice: stdin -> split -> fold -> envelope.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_HOOK = Path(__file__).resolve().parent.parent / "hooks" / "safe_read_hook.py"


def _run(payload: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_HOOK)],
        input=payload,
        capture_output=True,
        text=True,
    )


def test_real_cat_payload_yields_allow_envelope() -> None:
    """The phase's E2E proof: a real cat foo.txt Bash payload -> allow envelope.

    Selectable via ``-k allow`` by name (VALIDATION map).
    """
    payload = json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "cat foo.txt"}, "cwd": "/x"}
    )
    result = _run(payload)
    assert result.returncode == 0
    parsed = json.loads(result.stdout)
    hso = parsed["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "allow"


def test_compound_with_unsafe_segment_emits_nothing() -> None:
    """cat foo.txt && rm -rf x -> abstain -> empty stdout (the slice's veto, E2E)."""
    payload = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "cat foo.txt && rm -rf x"},
            "cwd": "/x",
        }
    )
    result = _run(payload)
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_non_bash_tool_emits_nothing() -> None:
    payload = json.dumps(
        {"tool_name": "Read", "tool_input": {"file_path": "foo.txt"}, "cwd": "/x"}
    )
    result = _run(payload)
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_empty_command_emits_nothing() -> None:
    payload = json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": ""}, "cwd": "/x"}
    )
    result = _run(payload)
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_malformed_json_emits_nothing_and_does_not_crash() -> None:
    result = _run("{not valid json")
    assert result.returncode == 0
    assert result.stdout.strip() == ""

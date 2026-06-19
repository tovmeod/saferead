"""Shared fixtures for the safe-read-hook test suite.

Provides sample PreToolUse payloads and a stub ``ask``-returning recognizer
used by the engine tests (Plan 02) to exercise the ask tier and precedence.
"""

from __future__ import annotations

import json

import pytest

from sash.context import Context
from sash.recognizers import Recognizer
from sash.verdict import Verdict


@pytest.fixture
def ctx() -> Context:
    """A plain Context with the no-op branch resolver (no git logic)."""
    return Context(cwd="/x")


@pytest.fixture
def bash_payload() -> dict:
    """A well-formed Bash PreToolUse payload running a safe read."""
    return {
        "tool_name": "Bash",
        "tool_input": {"command": "cat foo.txt"},
        "cwd": "/x",
    }


@pytest.fixture
def non_bash_payload() -> dict:
    """A PreToolUse payload for a non-Bash tool (entrypoint must ignore it)."""
    return {
        "tool_name": "Read",
        "tool_input": {"file_path": "foo.txt"},
        "cwd": "/x",
    }


@pytest.fixture
def empty_command_payload() -> dict:
    """A Bash payload whose command is empty."""
    return {"tool_name": "Bash", "tool_input": {"command": ""}, "cwd": "/x"}


@pytest.fixture
def malformed_payload() -> str:
    """A raw stdin string that is not valid JSON."""
    return "{not valid json"


@pytest.fixture
def stub_ask() -> Recognizer:
    """Return a recognizer that asks on a sentinel segment, else abstains.

    Returned (not consumed) so engine tests can place it into the registry to
    exercise the ask tier and abstain > ask > allow precedence.
    """

    def _stub_ask(segment: str, ctx: Context) -> Verdict | None:
        if segment.startswith("gitstub"):
            return Verdict("ask", "stub gated op", "test.ask")
        return None

    return _stub_ask


# Silence "imported but unused" for the json convenience re-export some tests use.
_ = json

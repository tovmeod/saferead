<!-- GSD:project-start source:PROJECT.md -->
## Project

**Claude Safe-Read Hook**

A Claude Code `PreToolUse` hook that recognizes known-safe, read-only shell
commands and auto-approves them, so routine reads don't interrupt the user with
permission prompts. It decomposes compound Bash commands (`&&`, `||`, `;`, `|`,
newlines — quote/backtick/`$()`-aware) and allows a segment set only when *every*
segment is a recognized safe read. It also ASKs for confirmation on gated git
writes (`add`/`commit`/`stash`) when the working branch is protected
(`master`/`main`). It is for a single power-user (the author) today, with a
later goal of being installable and configurable by others.

It is **complementary to `dcg`** (`~/.local/bin/dcg`), which remains the
authority for *blocking* dangerous commands. This hook never denies — it only
ALLOWs or ASKs, and otherwise abstains (stays silent, letting the normal
permission flow proceed).

**Core Value:** Auto-approve known-safe read-only commands with zero false-allows — a command
that mutates state must never be silently approved. Coverage is secondary to
that guarantee; when in doubt, abstain.

### Constraints

- **Tech stack**: Python, standard library only — no runtime dependencies. TOML via stdlib `tomllib` (Python 3.11+). Keeps the hook trivially deployable.
- **Safety**: Conservative-by-default. Any ambiguity → abstain. A false-allow (approving a state-mutating command) is the cardinal failure; favor zero false-allows over broader coverage.
- **Reliability**: The hook must never crash or block Claude's flow; all errors are caught and logged (currently to `/tmp/claude-hook.log`), and the hook abstains on failure.
- **Performance**: Decision path must remain low-latency since it runs on every Bash invocation.
- **Compatibility**: Must keep emitting the Claude Code PreToolUse hook output contract.
<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->
## Technology Stack

## The Cardinal Constraint: Runtime vs Dev
| Layer | Contents | Lives in pyproject as |
|-------|----------|------------------------|
| **Runtime** | Python stdlib only (`json`, `re`, `subprocess`, `sys`, `tomllib`, `pathlib`, …) | `dependencies = []` |
| **Dev / CI** | pytest, ruff, a type checker, build backend | `[dependency-groups]` / `[project.optional-dependencies]` |
## Recommended Stack
### Runtime (shipped artifact)
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| CPython | `>=3.11` (floor) | Execution | `tomllib` enters stdlib at 3.11. Setting the floor here means TOML config needs zero runtime deps. Local dev/runtime is currently 3.14.4. |
| `tomllib` | stdlib | Parse TOML config (global + per-project) | In-stdlib since 3.11. **Read-only** parser — fine, since config is human-edited, never machine-written by the hook. |
| `re`, `subprocess`, `json`, `sys`, `pathlib`, `traceback`, `datetime` | stdlib | Existing hook machinery | Already used by the 447-line seed; no change. |
### Dev / CI tooling
| Technology | Version (2026-05-30) | Purpose | Why |
|------------|----------------------|---------|-----|
| **pytest** | `9.0.3` | Test framework (splitter, each recognizer, allow/ask/abstain matrix, adversarial false-allow cases) | De-facto standard. Fixtures + `parametrize` are ideal for a recognizer table and a corpus of malicious compound commands. v9 reads native `[tool.pytest]` in pyproject; requires Python `>=3.10` (compatible with our 3.11 floor). |
| **ruff** | `0.15.15` | Linter **and** formatter (one tool) | Replaces black + isort + flake8 + pyupgrade + pydocstyle. Rust-fast, single binary, configured entirely in pyproject `[tool.ruff]`. Industry default in 2026. |
| **pyright** | `1.1.409` | Static type checker | Fast, ~98% typing-spec conformance, already installed on this machine. Good editor integration. Small codebase → cheap to keep green. mypy `2.1.0` is an equally defensible alternative; pick pyright for speed + zero extra install here. |
| **hatchling** | `1.29.0` | PEP 517 build backend | Pure-Python project, no compiled step, no VCS-versioning need, deployment deferred → low-stakes choice. Hatchling is backend-neutral: works with plain `pip install -e .` and `python -m build`, so contributors are **not** forced onto uv. |
| **uv** | `0.11.16` | Dev environment + lockfile + CI installer | Already installed locally. Fast resolver/installer; `uv run pytest`, `uv run ruff`, `uv lock`. Used as the *workflow tool*, distinct from the *build backend*. |
| **GitHub Actions** | — | CI: lint + typecheck + test matrix | Standard for a single-maintainer OSS repo; free for public repos. |
### Project layout (src layout)
## How Claude Code hooks are packaged / deployed
- **Exec form (recommended):** `"command": "python3", "args": ["${CLAUDE_PROJECT_DIR}/hooks/safe_read_hook.py"]`
- **Shell form:** single `command` string with pipes/`&&`; requires manual quoting.
## Rationale Summary (why these, briefly)
- **stdlib-only runtime** — non-negotiable per PROJECT.md; preserves zero-install deployability and keeps the
- **3.11 floor + tomllib** — the single decision that makes TOML config free of runtime deps.
- **ruff** — collapses 4–5 legacy tools into one fast binary; one `[tool.ruff]` block.
- **pytest** — the table/parametrize model fits a recognizer registry and an adversarial corpus perfectly.
- **pyright** — fast, installed, high conformance; mypy is a fine swap.
- **hatchling + uv** — neutral backend (doesn't lock contributors into uv) plus uv as the fast workflow tool.
- **src layout** — tests hit the installed package, catching packaging bugs the standalone deploy would hit.
## What NOT to Use (and why)
| Avoid | Why not | Use instead |
|-------|---------|-------------|
| **`tomli` (PyPI backport) + fallback shim** | Adds a *runtime* dependency, violating the cardinal "stdlib only" rule. The whole point of the 3.11 floor is to avoid this. | `requires-python = ">=3.11"` + stdlib `tomllib`. |
| **Supporting Python < 3.11** | Forces `tomli` or a hand-rolled parser; reintroduces a runtime dep and parser-divergence risk. | Floor at 3.11. |
| **black + isort + flake8 (separate tools)** | Three configs, three installs, slower; superseded. | ruff (lint + format). |
| **Poetry / `poetry-core` backend** | Heavier workflow, non-PEP-621 history, no benefit for a zero-dep pure-Python lib. | hatchling (or uv_build). |
| **`ty` / `pyrefly` as the primary type checker** | Astral `ty` is beta (~53% spec conformance); pyrefly is new. Promising and very fast, but not the safe primary for a *safety-critical* tool in 2026. | pyright (or mypy 2.x); revisit `ty` later. |
| **Runtime deps for shell parsing (`bashlex`, `shlex`-heavy rewrites, `pyparsing`)** | New runtime dep + the seed's quote/`$()`/backtick-aware splitter already works and is fast. Replacing it risks behavior drift on the exact security-sensitive path. | Keep the existing hand-written `split_compound`; just extract + test it. |
| **`argparse` / CLI frameworks (click/typer) on the hook path** | The hook's only input is a JSON stdin payload; no CLI surface. Adds deps and startup cost. | Plain `sys.stdin.read()` + `json.loads`. |
| **Async anything** | Single short-lived process per Bash call; async adds overhead and complexity with zero benefit. | Synchronous stdlib. |
| **`setuptools` with `setup.py`** | Legacy boilerplate; no compiled extensions to justify it. | hatchling + declarative pyproject. |
## CI Recommendation
## Installation (dev)
# All dev tooling via uv (no global installs needed)
## Open Questions
## Confidence Assessment
| Area | Confidence | Notes |
|------|------------|-------|
| Versions (ruff 0.15.15, pytest 9.0.3, mypy 2.1.0, hatchling 1.29.0, pyright 1.1.409, uv 0.11.16) | HIGH | Fetched live from PyPI / `uv --version` on 2026-05-30. |
| tomllib floor / no-tomli decision | HIGH | stdlib `tomllib` since 3.11 verified locally; constraint logic is deductive from PROJECT.md. |
| ruff / pytest / src-layout as standard | HIGH | Consistent across official docs and 2026 ecosystem sources. |
| Type-checker choice | MEDIUM-HIGH | pyright recommended; mypy equally valid. ty/pyrefly intentionally excluded as primary. |
| Build backend choice | MEDIUM | hatchling vs uv_build both fine; recommendation is preference, not necessity. |
| Hook deploy / output contract | HIGH for established parts | settings.json `command`+`args`, `$CLAUDE_PROJECT_DIR`, allow/ask/abstain verified. `"defer"` / new hook types flagged needs-verification. |
## Sources
- [ruff (PyPI)](https://pypi.org/project/ruff/) — 0.15.15
- [pytest (PyPI)](https://pypi.org/project/pytest/) — 9.0.3, requires-python >=3.10
- [mypy (PyPI)](https://pypi.org/project/mypy/) — 2.1.0
- [hatchling (PyPI)](https://pypi.org/project/hatchling/) — 1.29.0
- [pyright (PyPI)](https://pypi.org/project/pyright/) — 1.1.409
- [Ruff docs](https://docs.astral.sh/ruff/)
- [uv build backend](https://docs.astral.sh/uv/concepts/build-backend/)
- [Scientific-Python: simple packaging (src layout)](https://learn.scientific-python.org/development/guides/packaging-simple/)
- [Python type checker comparison 2026](https://pydevtools.com/handbook/explanation/how-do-mypy-pyright-and-ty-compare/)
- [Claude Code Hooks reference](https://code.claude.com/docs/en/hooks)
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->

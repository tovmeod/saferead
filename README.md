# saferead

A [Claude Code](https://claude.com/claude-code) `PreToolUse` hook that
auto-approves known-safe, read-only shell commands — so routine reads
(`ls`, `cat`, `git status`, `grep`, …) don't interrupt you with permission
prompts.

[![PyPI](https://img.shields.io/pypi/v/saferead)](https://pypi.org/project/saferead/)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](LICENSE)

## What it does

`saferead` inspects each `Bash` command Claude Code is about to run and returns
one of three verdicts:

- **allow** — every part of the command is a recognized read-only operation.
- **ask** — a gated git write (`add` / `commit` / `stash`) on a protected
  branch (`master` / `main`); you get a confirmation prompt.
- **abstain** — anything it doesn't recognize: it stays silent and lets Claude
  Code's normal permission flow proceed.

It **never denies** a command. It only ever *removes* friction (allow) or
*adds* a confirmation (ask), so it composes safely alongside any separate
command-blocking layer you run.

Compound commands are decomposed at top-level `&&`, `||`, `;`, `|`, and
newlines (quote / backtick / `$(…)`-aware). A command is allowed **only when
every segment** is a recognized safe read.

### Design guarantee

The cardinal rule is **zero false-allows**: a command that mutates state must
never be silently approved. Coverage is secondary — when in doubt, it abstains.
The hook is also built to **never crash or block** Claude Code: any internal
error is caught and the hook abstains.

## Examples

| Command | Verdict | Why |
|---------|---------|-----|
| `ls -la`, `cat README.md`, `grep -rn foo src` | **allow** | read-only |
| `git status`, `git log --oneline`, `git diff` | **allow** | read-only git |
| `cat a.txt && wc -l a.txt` | **allow** | every segment is a safe read |
| `git commit -m "wip"` on `main` | **ask** | gated write on a protected branch |
| `git add .` on a feature branch | **allow** | gated write off a protected branch |
| `rm -rf build` | **abstain** | not recognized → normal prompt |
| `npm install` | **abstain** | not a read |
| `cat a.txt && rm b.txt` | **abstain** | one segment mutates state |

Only the `Bash` tool is inspected; every other tool is left untouched.

## Install

Install the `saferead` command with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install saferead
```

## Enable the hook

Register the hook in your Claude Code settings:

```bash
saferead install            # prompts for global or project settings.json
saferead install --project  # writes to ./.claude/settings.json
```

This writes a `PreToolUse` entry (matcher `Bash`) whose command is the **full
path** to the installed `saferead` binary — a direct exec on the hot path, with
no launcher overhead. The target `settings.json` is backed up first and any
existing hook entries are left untouched; re-running is idempotent. The entry
looks like:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "/home/you/.local/bin/saferead" } ] }
    ]
  }
}
```

## Configuration

Configuration is optional — `saferead` ships with safe built-in defaults.
Two TOML files are read, both optional:

| File | Trust | Purpose |
|------|-------|---------|
| `~/.config/saferead/config.toml` | trusted | your global settings |
| `$CLAUDE_PROJECT_DIR/.claude/saferead.toml` | untrusted | per-project overrides |

The project file can only **narrow** trust (add protected branches, disable
recognizers) — it can never broaden the allow-set for git writes, by design.

Every key is optional; the values below are the **built-in defaults**:

```toml
[git]
protected_branches = ["master", "main"]           # ask on a gated git write on these branches
gated_subcommands  = ["add", "commit", "stash"]    # which git writes are gated

[recognizers]
disabled = []   # recognizer tags to turn off (those commands then abstain)

[python]
allowed_modules = ["math", "datetime", "json"]  # modules the `python -c` analyzer admits
allowed_methods = []                            # extra read-only methods to admit

[read]
local_allowed_roots = []   # empty = allow any path; non-empty restricts file reads to these roots
ssh_allowed_roots   = []

[logging]
enabled = true                       # audit log of every allow/ask decision (ON by default)
path = "/tmp/claude-hook-audit.log"  # where that audit log is written
```

### Logs

`saferead` writes two files under `/tmp`:

- **Audit log** (`/tmp/claude-hook-audit.log`) — one JSON line per allow/ask
  decision. **On by default**; configure or disable it via the `[logging]`
  table above.
- **Error log** (`/tmp/claude-hook.log`) — internal diagnostics if the hook
  ever hits an error (it always abstains rather than crashing). Fixed path,
  not configurable.

## Updating

```bash
uv tool upgrade saferead
```

## License

[GPL-3.0-or-later](LICENSE)

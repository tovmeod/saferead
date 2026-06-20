# Changelog

All notable changes to **saferead** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses **calendar versioning**: `YYYY.M` for the first release in a
month, and `YYYY.M.N` for subsequent releases within the same month (Python
packaging drops the leading zero from the month, e.g. June is `2026.6`).

## [2026.6] - 2026-06-21

First calendar-versioned release. Fixes the installer that the earlier 0.1.x
releases shipped broken.

### Fixed
- `uvx saferead install` is now a true one-command setup. It bootstraps a
  permanent install (`uv tool install saferead --upgrade`) and writes the
  PreToolUse hook entry pointing at the **permanent** binary path (resolved via
  `uv tool dir --bin`) instead of the ephemeral `uvx` cache path that vanished
  when the process exited — the bug that made the shipped 0.1.x installer
  register a dead hook. (INST-01)
- The interactive global-vs-project target prompt no longer crashes with
  `EOFError` on non-interactive or closed stdin; it falls back to the global
  default. `--project` and an explicit settings-path argument still bypass the
  prompt.

### Added
- Refuse-to-write guard: if no permanent binary path can be resolved (e.g. `uv`
  is absent or the bootstrap fails), the installer prints actionable guidance and
  exits non-zero **without** touching `settings.json`, rather than registering a
  doomed hook.

### Removed
- The `saferead update` subcommand. Updating is now just re-running
  `uvx saferead install`, which upgrades to the latest version and refreshes the
  hook entry in place.

## [0.1.0] – [0.1.4] - 2026-06-20

Initial PyPI packaging and documentation iterations (the package builds, the
console script and hook contract work). The `saferead install` step in these
releases registered an ephemeral path under `uvx` and could crash at the target
prompt — both fixed in `2026.6`. See the
[GitHub Releases](https://github.com/tovmeod/saferead/releases) page for the
per-version notes.

[2026.6]: https://github.com/tovmeod/saferead/releases/tag/2026.6

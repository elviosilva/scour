# scour

A cross-platform disk cleaner (Linux / macOS / Windows) written in Rust.

`scour` scans for reclaimable files, groups them into categories, and removes
the ones you select. It is an original tool — not a port or clone of any
commercial product — and the cleanup targets (caches, logs, temp, trash, large
and old files, duplicates) are standard OS locations, not proprietary rules.

## Workspace layout

| Crate | What it is |
|-------|------------|
| `scour-core` | Engine: scanners, data model, safety-checked operation layer, IPC protocol. No UI, no elevation. |
| `scour-cli`  | `scour` binary: `scan`, `clean`, `tui` subcommands. |
| `scour-tui`  | `scour-tui` interactive terminal UI (also launchable via `scour tui`). |
| `scour-helperd` | Minimal privileged helper that performs deletions in system locations. |

## Categories

- **System junk** — application caches, logs, temporary files (`Safe`).
- **Trash** — contents of the OS trash / recycle bin (`Safe`). Linux XDG trash
  (`files` + `info`), macOS `~/.Trash`, and the Windows per-volume
  `$Recycle.Bin` (both `$R` payload and `$I` metadata; `$I` records are parsed
  to recover each item's original path for display).
- **Large & old files** — your own files over a size/age threshold (`Manual`, never auto-selected).
- **Duplicates** — byte-identical copies found by size → head-sample → BLAKE3 (`Review`).

## Safety model

1. Scanners may only surface paths inside an **allowlisted root** for their
   category (`scour-core::platform`).
2. The operation layer re-validates every path before deleting: it must be
   absolute, contained in an allowlisted root, contain no `..`, and must not be
   a symlink.
3. The **privileged helper independently re-runs the same checks** before
   deleting as root — it trusts nothing from the caller and can only perform
   deletions the policy already permits. It never executes arbitrary commands.
4. `clean` is **dry-run by default**; `--apply` plus a confirmation is required
   to delete.

## Usage

```bash
# Scan everything and print a report (never deletes)
scour scan

# Scan only junk and trash, as JSON
scour scan junk trash --json

# Dry-run clean of safe items
scour clean

# Actually delete safe items (prompts for confirmation)
scour clean --apply

# Include duplicates/old files too
scour clean --apply --include-review

# Interactive terminal UI
scour tui

# Use an explicit config file
scour --config ./scour.toml scan

# Silence the live scan progress line
scour scan --no-progress
```

## Progress reporting

Scanning a full home directory (large/old files, duplicates) can take a while,
so scanners emit `ProgressEvent`s consumed by the front-end. On a terminal, the
CLI shows a single self-overwriting status line on stderr (category, entries,
bytes, current path); when stderr is not a TTY it prints one concise line per
category instead, and `--json` disables progress so stdout stays machine-clean.
`--no-progress` turns it off entirely. The engine API is `scan_all_with_progress`
with any `Progress` sink; `scan_all` uses a no-op sink.

## Configuration

scour reads `scour.toml` from `<config-dir>/scour/scour.toml` (or `--config
<path>`). See [`packaging/scour.example.toml`](packaging/scour.example.toml).
It can:

- tune scan thresholds (`large_min_size`, `old_after_days`, `dupe_min_size`,
  `follow_symlinks`);
- add managed `allow_roots` (same effect as the `SCOUR_ALLOW_ROOT` env var);
- add `exclude` globs that must never be deleted.

Exclusions only ever *prevent* deletions, so they are safe to forward to the
privileged helper. A **built-in protected set** (SSH/GPG keys, password stores,
keychains, crypto wallets, cloud credentials) is always enforced on top and
cannot be disabled — even a file sitting inside a cache directory is refused if
it matches.

## Privilege separation

Deletions in user-owned locations run in-process, unprivileged. Deletions in
system locations (e.g. `/Library/Caches` on macOS) are routed to
`scour-helperd`, launched elevated:

- **Linux** — via `pkexec` (polkit); falls back to `sudo`. Install
  `packaging/linux/com.scour.helper.policy` into `/usr/share/polkit-1/actions/`
  for a GUI auth prompt.
- **macOS** — via `sudo` in v1; a production build would register a launchd
  helper with `SMAppService`.
- **Windows** — assumes an already-elevated process in v1; a production build
  would relaunch with `ShellExecute "runas"`.

## Building

```bash
cargo build --release
# binaries in target/release/: scour, scour-tui, scour-helperd
```

## Packaging (Arch / Omarchy)

A PKGBUILD is provided in [`packaging/arch`](packaging/arch/PKGBUILD). From a
checkout:

```bash
cd packaging/arch
makepkg -si
```

It builds the workspace and installs:

| File | Destination |
|------|-------------|
| `scour`, `scour-tui` | `/usr/bin/` |
| `scour-helperd` | `/usr/lib/scour/` (not in `$PATH`; where the policy authorizes it) |
| polkit action | `/usr/share/polkit-1/actions/com.scour.helper.policy` |
| example config, README, LICENSE | `/usr/share/{doc,licenses}/scour/` |

With the policy installed, cleaning a system location raises polkit's GUI
authentication dialog (`pkexec`) with a scour-specific prompt, instead of the
generic one. `scour` locates the helper next to its own binary first, then at
`/usr/lib/scour/scour-helperd`, so both dev and packaged layouts work.

## Status

v1 scope: CLI + TUI; junk, trash (incl. Windows recycle bin), large/old files,
duplicates; privilege separation with native elevation on Linux (pkexec/sudo),
macOS (osascript) and Windows (UAC). The tree type-checks for Linux,
`x86_64-apple-darwin` and `x86_64-pc-windows-gnu`. Not yet implemented: mail /
cloud / malware modules.

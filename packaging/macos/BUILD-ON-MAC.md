# Build scour on a Mac (Plan B)

Produces a universal (Apple Silicon + Intel) `scour.app` and `scour.dmg` directly
on a Mac — no GitHub Actions, no CI, no account billing. Works on a completely
fresh Mac: the script installs the two prerequisites if they are missing.

## What you need

- A Mac (Apple Silicon *or* Intel) running macOS 11 or newer.
- ~2 GB free disk and a few minutes.
- Internet access (first run downloads the Rust toolchain and crates).

Nothing is installed system-wide except, only if absent:
- **Xcode Command Line Tools** (Apple's linker, `lipo`, `hdiutil`) — via Apple's
  own GUI installer.
- **rustup + Rust** — user-local, into `~/.rustup` and `~/.cargo`.

## Steps

Open **Terminal** on the Mac and run:

```bash
# 1. Get the code (either clone, or copy the folder over by AirDrop/USB)
git clone https://github.com/elviosilva/scour.git
cd scour

# 2. One command — checks prerequisites, then builds everything
./packaging/macos/build-on-mac.sh
```

If it stops saying **"Xcode Command Line Tools are missing"**, accept the Apple
dialog that popped up, wait for it to finish installing, then run the same
command again. (That install is one-time.)

No git? Copy the `scour` folder to the Mac (AirDrop, USB key, `scp`) and run the
same `./packaging/macos/build-on-mac.sh` from inside it.

## Output

When it finishes you get, under `target/macos/`:

| File | What it is |
|------|------------|
| `scour.app` | Double-click to launch the GUI. Universal binary. |
| `scour.dmg` | Distributable disk image (drag-to-Applications). |
| `bin/` | `scour`, `scour-tui`, `scour-helperd` command-line tools. |

## First launch (unsigned app)

The build is **not code-signed**, so Gatekeeper will complain the first time.
Either:

- Right-click `scour.app` → **Open** → **Open** (only needed once), or
- Strip the quarantine flag:

  ```bash
  xattr -dr com.apple.quarantine target/macos/scour.app
  ```

## Troubleshooting

- **`cargo: command not found` after the toolchain install** — open a *new*
  Terminal window (or run `source "$HOME/.cargo/env"`) and re-run the script.
- **`this script must run on macOS`** — you ran it on Linux/Windows; the Mach-O
  linker only exists on macOS. That is the whole reason for Plan B.
- To rebuild after a code change, just run `./packaging/macos/build-app.sh`
  again (skips the prerequisite checks).

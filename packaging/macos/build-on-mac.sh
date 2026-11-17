#!/usr/bin/env bash
#
# One-command macOS build for scour (Plan B — no CI needed).
#
# Run this on any Mac (Apple Silicon or Intel) from the repository root:
#
#     ./packaging/macos/build-on-mac.sh
#
# It makes sure the two prerequisites are present, then builds a universal
# scour.app and scour.dmg. Nothing is installed system-wide except, if missing:
#   - Xcode Command Line Tools (Apple's linker + hdiutil), via a GUI prompt.
#   - rustup + the Rust toolchain, into ~/.rustup and ~/.cargo (user-local).
#
# Outputs land in target/macos/:  scour.app, scour.dmg, bin/.
set -euo pipefail

cd "$(dirname "$0")/../.."

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname)" == "Darwin" ]] || die "this script must run on macOS."

# 1) Xcode Command Line Tools — provides clang/ld (the Mach-O linker), lipo,
#    hdiutil. 'xcode-select -p' succeeds only once they are installed.
if ! xcode-select -p >/dev/null 2>&1; then
    say "Xcode Command Line Tools are missing — launching Apple's installer."
    say "Accept the dialog, let it finish, then re-run this script."
    xcode-select --install || true
    die "waiting on Xcode Command Line Tools install."
fi
say "Xcode Command Line Tools: OK ($(xcode-select -p))"

# 2) Rust toolchain. Prefer an existing cargo; otherwise install rustup locally.
if ! command -v cargo >/dev/null 2>&1; then
    # rustup may already be installed but not on PATH in this shell.
    if [[ -f "$HOME/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi
fi
if ! command -v cargo >/dev/null 2>&1; then
    say "Rust not found — installing rustup (user-local, into ~/.rustup and ~/.cargo)."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi
command -v cargo >/dev/null 2>&1 || die "cargo still not on PATH; open a new terminal and re-run, or 'source \$HOME/.cargo/env'."
say "Rust: OK ($(cargo --version))"

# 3) Hand off to the real build (adds both apple targets, lipo, bundles, dmg).
say "Building universal scour.app + scour.dmg (this takes a few minutes)…"
exec ./packaging/macos/build-app.sh

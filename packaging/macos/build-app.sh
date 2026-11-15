#!/usr/bin/env bash
#
# Build universal (Apple Silicon + Intel) macOS binaries, bundle the GUI into
# scour.app, and produce a scour.dmg. Run on macOS from the repository root:
#
#     ./packaging/macos/build-app.sh
#
# Outputs land in target/macos/.
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ "$(uname)" != "Darwin" ]]; then
    echo "error: this script must run on macOS (needs lipo, hdiutil and the Apple linker)." >&2
    exit 1
fi

TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
BINS=(scour scour-tui scour-gui scour-helperd)

for t in "${TARGETS[@]}"; do
    rustup target add "$t"
    cargo build --release --target "$t"
done

OUT="target/macos"
APP="$OUT/scour.app"
rm -rf "$OUT"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Universal binaries via lipo; all four live in Contents/MacOS so the GUI finds
# scour-helperd next to itself and the CLI tools ship with the app.
for bin in "${BINS[@]}"; do
    lipo -create -output "$APP/Contents/MacOS/$bin" \
        "target/aarch64-apple-darwin/release/$bin" \
        "target/x86_64-apple-darwin/release/$bin"
done

cp packaging/macos/Info.plist "$APP/Contents/Info.plist"
if [[ -f packaging/macos/scour.icns ]]; then
    cp packaging/macos/scour.icns "$APP/Contents/Resources/scour.icns"
fi

# A loose copy of the CLI tools for a "move to /usr/local/bin" workflow.
mkdir -p "$OUT/bin"
for bin in scour scour-tui scour-helperd; do
    cp "$APP/Contents/MacOS/$bin" "$OUT/bin/$bin"
done

# Disk image containing the app plus an /Applications shortcut.
STAGE="$OUT/dmg"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "scour" -srcfolder "$STAGE" -ov -format UDZO "$OUT/scour.dmg"
rm -rf "$STAGE"

echo
echo "Built:"
echo "  $APP            (double-click to run the GUI)"
echo "  $OUT/scour.dmg  (distributable disk image)"
echo "  $OUT/bin/       (scour, scour-tui, scour-helperd CLI tools)"
echo
echo "Note: the binaries are unsigned. On first launch, right-click the app and"
echo "choose Open, or run: xattr -dr com.apple.quarantine \"$APP\""

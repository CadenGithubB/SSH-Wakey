#!/bin/sh
#
# Builds a disk image for moving SSH-Wakey to another Mac.
#
# Read this before using it on someone else's machine: the app is signed
# ad-hoc, not with a Developer ID, and it is not notarised. On the Mac that
# built it that is fine. Anywhere else, macOS attaches a quarantine flag to
# anything that arrives by download or AirDrop, and Gatekeeper refuses an
# ad-hoc signed app outright. The person receiving it has to either
# right-click the app and choose Open, or run:
#
#     xattr -d com.apple.quarantine /Applications/SSH-Wakey.app
#
# Telling people to bypass Gatekeeper is a bad habit to teach. If you want to
# hand this to anyone else, sign it with a Developer ID and notarise it instead.

set -eu

cd "$(dirname "$0")/.."

echo "Building Release…"
xcodebuild \
    -project SSH-Wakey.xcodeproj \
    -scheme SSH-Wakey \
    -configuration Release \
    -derivedDataPath build \
    build >/dev/null

BUILT="build/Build/Products/Release/SSH-Wakey.app"
[ -d "$BUILT" ] || { echo "Build produced no app at $BUILT" >&2; exit 1; }

STAGING="build/dmg"
rm -rf "$STAGING" "build/SSH-Wakey.dmg"
mkdir -p "$STAGING"
/usr/bin/ditto "$BUILT" "$STAGING/SSH-Wakey.app"
ln -s /Applications "$STAGING/Applications"

hdiutil create \
    -volname "SSH-Wakey" \
    -srcfolder "$STAGING" \
    -ov -format UDZO \
    "build/SSH-Wakey.dmg" >/dev/null

rm -rf "$STAGING"
echo
echo "Wrote build/SSH-Wakey.dmg"
echo "Drag the app onto Applications after opening it."

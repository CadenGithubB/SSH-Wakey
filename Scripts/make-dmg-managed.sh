#!/bin/sh
#
# Builds a disk image for the IT Managed app.
#
# Writes build/SSH-Wakey-Managed.dmg
#
# Same repo and Xcode project as Standard. This script uses the
# "SSH-Wakey Managed" scheme (bundle id com.CadenGithubB.sshwakey.managed).
# The public app is:
#   ./Scripts/make-dmg.sh
#
# Ad-hoc signed, not notarised. A Jamf policy that installs the .app as root
# usually avoids Gatekeeper; a Self Service download of this image still gets
# a quarantine flag. Developer ID and notarisation are a later step.

set -eu

cd "$(dirname "$0")/.."

echo "Building ManagedRelease…"
xcodebuild \
    -project SSH-Wakey.xcodeproj \
    -scheme "SSH-Wakey Managed" \
    -configuration ManagedRelease \
    -derivedDataPath build \
    build >/dev/null

BUILT="build/Build/Products/ManagedRelease/SSH-Wakey Managed.app"
[ -d "$BUILT" ] || { echo "Build produced no app at $BUILT" >&2; exit 1; }

STAGING="build/dmg-managed"
rm -rf "$STAGING" "build/SSH-Wakey-Managed.dmg"
mkdir -p "$STAGING"
/usr/bin/ditto "$BUILT" "$STAGING/SSH-Wakey Managed.app"
ln -s /Applications "$STAGING/Applications"

hdiutil create \
    -volname "SSH-Wakey Managed" \
    -srcfolder "$STAGING" \
    -ov -format UDZO \
    "build/SSH-Wakey-Managed.dmg" >/dev/null

rm -rf "$STAGING"
echo
echo "Wrote build/SSH-Wakey-Managed.dmg"
echo "Drag the app onto Applications after opening it."

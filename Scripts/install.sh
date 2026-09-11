#!/bin/sh
#
# Builds SSH-Wakey for release and installs it into /Applications.
#
# The Release configuration is the one to install: it has the Hardened Runtime
# on and no get-task-allow entitlement, so another process running as you cannot
# attach a debugger and read the password out of memory. The Debug build
# deliberately keeps both so Xcode can attach.

set -eu

cd "$(dirname "$0")/.."

DESTINATION="/Applications/SSH-Wakey.app"
BUNDLE_ID="com.CadenGithubB.sshwakey"

echo "Building Release…"
xcodebuild \
    -project SSH-Wakey.xcodeproj \
    -scheme SSH-Wakey \
    -configuration Release \
    -derivedDataPath build \
    build >/dev/null

BUILT="build/Build/Products/Release/SSH-Wakey.app"
[ -d "$BUILT" ] || { echo "Build produced no app at $BUILT" >&2; exit 1; }

# Replace rather than merge, so a rename or a deleted file cannot leave
# something stale behind inside the bundle.
if [ -d "$DESTINATION" ]; then
    EXISTING=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" \
        "$DESTINATION/Contents/Info.plist" 2>/dev/null || echo "")
    if [ "$EXISTING" != "$BUNDLE_ID" ]; then
        echo "$DESTINATION exists and is not SSH-Wakey ($EXISTING). Refusing." >&2
        exit 1
    fi
    echo "Replacing the existing copy…"
    rm -rf "$DESTINATION"
fi

/usr/bin/ditto "$BUILT" "$DESTINATION"

echo
codesign --verify --strict "$DESTINATION" && echo "Signature verifies."
codesign -dv "$DESTINATION" 2>&1 | grep -E "flags=" | sed 's/^/  /'
echo
echo "Installed to $DESTINATION"
echo
echo "macOS will ask once for Keychain access if you use encryption, because this"
echo "build has a different ad-hoc signature from the one you were running before."

#!/bin/sh
# Build a verified local Standard app image. Distribution still needs Developer ID
# signing and notarization; do not ask recipients to bypass Gatekeeper.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
cd -P "$(dirname "$0")/.."
. ./Scripts/release-common.sh
check_build_paths Release SSH-Wakey.app
[ ! -L build/SSH-Wakey.dmg ] || fail 'Refusing linked disk image destination.'
[ ! -d build/SSH-Wakey.dmg ] || fail 'Disk image destination is a directory.'

echo 'Building Release…'
/usr/bin/xcodebuild -project SSH-Wakey.xcodeproj -scheme SSH-Wakey \
    -configuration Release -derivedDataPath build build >/dev/null
BUILT=build/Build/Products/Release/SSH-Wakey.app
verify_release_bundle "$BUILT" com.CadenGithubB.sshwakey SSH-Wakey
WORK=$(/usr/bin/mktemp -d build/.SSH-Wakey-dmg.XXXXXX)
trap '/bin/rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
/bin/mkdir "$WORK/staging"
/usr/bin/ditto "$BUILT" "$WORK/staging/SSH-Wakey.app"
verify_release_bundle "$WORK/staging/SSH-Wakey.app" com.CadenGithubB.sshwakey SSH-Wakey
/bin/ln -s /Applications "$WORK/staging/Applications"
/usr/bin/hdiutil create -volname SSH-Wakey -srcfolder "$WORK/staging" \
    -format UDZO "$WORK/image.dmg" >/dev/null
[ ! -L build/SSH-Wakey.dmg ] || fail 'Refusing linked disk image destination.'
/bin/mv -f "$WORK/image.dmg" build/SSH-Wakey.dmg
echo 'Wrote build/SSH-Wakey.dmg (ad-hoc signed, not notarized).'

#!/bin/sh
# Build a verified local Managed app image. IT distribution still needs Developer
# ID signing and notarization.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
cd -P "$(dirname "$0")/.."
. ./Scripts/release-common.sh
check_build_paths ManagedRelease 'SSH-Wakey Managed.app'
[ ! -L build/SSH-Wakey-Managed.dmg ] || fail 'Refusing linked disk image destination.'
[ ! -d build/SSH-Wakey-Managed.dmg ] || fail 'Disk image destination is a directory.'

echo 'Building ManagedRelease…'
/usr/bin/xcodebuild -project SSH-Wakey.xcodeproj -scheme 'SSH-Wakey Managed' \
    -configuration ManagedRelease -derivedDataPath build build >/dev/null
BUILT='build/Build/Products/ManagedRelease/SSH-Wakey Managed.app'
verify_release_bundle "$BUILT" com.CadenGithubB.sshwakey.managed 'SSH-Wakey Managed'
WORK=$(/usr/bin/mktemp -d build/.SSH-Wakey-managed-dmg.XXXXXX)
trap '/bin/rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
/bin/mkdir "$WORK/staging"
/usr/bin/ditto --noextattr --noacl --norsrc "$BUILT" "$WORK/staging/SSH-Wakey Managed.app"
prepare_release_bundle "$WORK/staging/SSH-Wakey Managed.app" com.CadenGithubB.sshwakey.managed 'SSH-Wakey Managed'
/bin/ln -s /Applications "$WORK/staging/Applications"
/usr/bin/hdiutil create -volname 'SSH-Wakey Managed' -srcfolder "$WORK/staging" \
    -format UDZO -fs HFS+ -nospotlight "$WORK/image.dmg" >/dev/null
[ ! -L build/SSH-Wakey-Managed.dmg ] || fail 'Refusing linked disk image destination.'
/bin/mv -f "$WORK/image.dmg" build/SSH-Wakey-Managed.dmg
echo 'Wrote build/SSH-Wakey-Managed.dmg (ad-hoc signed, not notarized).'

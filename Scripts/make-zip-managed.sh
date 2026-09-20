#!/bin/sh
# Package an ad-hoc app without filesystem xattrs, ACLs, or local build metadata.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
cd -P "$(dirname "$0")/.."
. ./Scripts/release-common.sh
check_build_paths ManagedRelease 'SSH-Wakey Managed.app'
[ ! -L build/SSH-Wakey-Managed.zip ] || fail 'Refusing linked archive destination.'
[ ! -d build/SSH-Wakey-Managed.zip ] || fail 'Archive destination is a directory.'
/usr/bin/xcodebuild -project SSH-Wakey.xcodeproj -scheme 'SSH-Wakey Managed' \
    -configuration ManagedRelease -derivedDataPath build build >/dev/null
BUILT='build/Build/Products/ManagedRelease/SSH-Wakey Managed.app'
verify_release_bundle "$BUILT" com.CadenGithubB.sshwakey.managed 'SSH-Wakey Managed'
WORK=$(/usr/bin/mktemp -d build/.SSH-Wakey-zip.XXXXXX)
trap '/bin/rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
/usr/bin/ditto --noextattr --noacl --norsrc "$BUILT" "$WORK/SSH-Wakey Managed.app"
prepare_release_bundle "$WORK/SSH-Wakey Managed.app" com.CadenGithubB.sshwakey.managed 'SSH-Wakey Managed'
/usr/bin/python3 Scripts/release-privacy.py --archive "$WORK/archive.zip" "$WORK/SSH-Wakey Managed.app"
[ ! -L build/SSH-Wakey-Managed.zip ] || fail 'Refusing linked archive destination.'
/bin/mv -f "$WORK/archive.zip" build/SSH-Wakey-Managed.zip
echo 'Wrote build/SSH-Wakey-Managed.zip (ad-hoc signed, not notarized).'

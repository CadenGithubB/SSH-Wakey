#!/bin/sh
# Package an ad-hoc app without filesystem xattrs, ACLs, or local build metadata.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
cd -P "$(dirname "$0")/.."
. ./Scripts/release-common.sh
check_build_paths Release 'SSH-Wakey.app'
[ ! -L build/SSH-Wakey.zip ] || fail 'Refusing linked archive destination.'
[ ! -d build/SSH-Wakey.zip ] || fail 'Archive destination is a directory.'
/usr/bin/xcodebuild -project SSH-Wakey.xcodeproj -scheme 'SSH-Wakey' \
    -configuration Release -derivedDataPath build build >/dev/null
BUILT='build/Build/Products/Release/SSH-Wakey.app'
verify_release_bundle "$BUILT" com.CadenGithubB.sshwakey 'SSH-Wakey'
WORK=$(/usr/bin/mktemp -d build/.SSH-Wakey-zip.XXXXXX)
trap '/bin/rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
/usr/bin/ditto --noextattr --noacl --norsrc "$BUILT" "$WORK/SSH-Wakey.app"
prepare_release_bundle "$WORK/SSH-Wakey.app" com.CadenGithubB.sshwakey 'SSH-Wakey'
/usr/bin/python3 Scripts/release-privacy.py --archive "$WORK/archive.zip" "$WORK/SSH-Wakey.app"
[ ! -L build/SSH-Wakey.zip ] || fail 'Refusing linked archive destination.'
/bin/mv -f "$WORK/archive.zip" build/SSH-Wakey.zip
echo 'Wrote build/SSH-Wakey.zip (ad-hoc signed, not notarized).'

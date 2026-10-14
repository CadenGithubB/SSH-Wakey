#!/bin/sh
# Package an ad-hoc app without filesystem xattrs, ACLs, or local build metadata.
# Usage: Scripts/make-zip.sh [--managed]
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
cd -P "$(dirname "$0")/.."
. ./Scripts/release-common.sh

[ $# -le 1 ] || fail 'Usage: Scripts/make-zip.sh [--managed]'
case "${1-}" in
    '')
        SCHEME=SSH-Wakey
        CONFIGURATION=Release
        BUNDLE_ID=com.CadenGithubB.sshwakey
        ARCHIVE=build/SSH-Wakey.zip ;;
    --managed)
        SCHEME='SSH-Wakey Managed'
        CONFIGURATION=ManagedRelease
        BUNDLE_ID=com.CadenGithubB.sshwakey.managed
        ARCHIVE=build/SSH-Wakey-Managed.zip ;;
    *) fail 'Usage: Scripts/make-zip.sh [--managed]' ;;
esac
APP="$SCHEME.app"

check_build_paths "$CONFIGURATION" "$APP"
[ ! -L "$ARCHIVE" ] || fail 'Refusing linked archive destination.'
[ ! -d "$ARCHIVE" ] || fail 'Archive destination is a directory.'

echo "Building ${CONFIGURATION}..."
/usr/bin/xcodebuild -quiet -project SSH-Wakey.xcodeproj -scheme "$SCHEME" \
    -configuration "$CONFIGURATION" -derivedDataPath build build
BUILT="build/Build/Products/$CONFIGURATION/$APP"
verify_release_bundle "$BUILT" "$BUNDLE_ID" "$SCHEME"
WORK=$(/usr/bin/mktemp -d build/.SSH-Wakey-zip.XXXXXX)
trap '/bin/rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
/usr/bin/ditto --noextattr --noacl --norsrc "$BUILT" "$WORK/$APP"
prepare_release_bundle "$WORK/$APP" "$BUNDLE_ID" "$SCHEME"
/usr/bin/python3 Scripts/release-privacy.py --archive "$WORK/archive.zip" "$WORK/$APP"
[ ! -L "$ARCHIVE" ] || fail 'Refusing linked archive destination.'
/bin/mv -f "$WORK/archive.zip" "$ARCHIVE"
echo "Wrote $ARCHIVE (ad-hoc signed, not notarized)."

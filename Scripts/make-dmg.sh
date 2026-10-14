#!/bin/sh
# Package and verify a disk image from a privacy-checked ad-hoc app.
# Usage: Scripts/make-dmg.sh [--managed]
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
cd -P "$(dirname "$0")/.."
. ./Scripts/release-common.sh

[ $# -le 1 ] || fail 'Usage: Scripts/make-dmg.sh [--managed]'
case "${1-}" in
    '')
        SCHEME=SSH-Wakey
        CONFIGURATION=Release
        BUNDLE_ID=com.CadenGithubB.sshwakey
        ARCHIVE=build/SSH-Wakey.dmg ;;
    --managed)
        SCHEME='SSH-Wakey Managed'
        CONFIGURATION=ManagedRelease
        BUNDLE_ID=com.CadenGithubB.sshwakey.managed
        ARCHIVE=build/SSH-Wakey-Managed.dmg ;;
    *) fail 'Usage: Scripts/make-dmg.sh [--managed]' ;;
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
WORK=$(/usr/bin/mktemp -d build/.SSH-Wakey-dmg.XXXXXX)
MOUNTED=0
cleanup() {
    if [ "$MOUNTED" -eq 1 ]; then
        /usr/bin/hdiutil detach "$WORK/mount" >/dev/null || return
    fi
    /bin/rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
/bin/mkdir "$WORK/mount"
/usr/bin/ditto --noextattr --noacl --norsrc "$BUILT" "$WORK/$APP"
prepare_release_bundle "$WORK/$APP" "$BUNDLE_ID" "$SCHEME"
/usr/bin/python3 Scripts/release-privacy.py --archive "$WORK/clean.zip" "$WORK/$APP"
# Reconstruct the file tree from bytes with fixed permissions.
/bin/mkdir "$WORK/stage"
/usr/bin/python3 - "$WORK/clean.zip" "$WORK/stage" <<'PYTHON'
import os
import sys
import zipfile
from pathlib import Path

root = Path(sys.argv[2])
with zipfile.ZipFile(sys.argv[1]) as archive:
    for entry in archive.infolist():
        path = root / entry.filename
        if entry.is_dir():
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.write_bytes(archive.read(entry))
        os.chmod(path, (entry.external_attr >> 16) & 0o777)
PYTHON
/bin/ln -s /Applications "$WORK/stage/Applications"
/usr/bin/hdiutil makehybrid -quiet -hfs -hfs-volume-name "$SCHEME" \
    -o "$WORK/filesystem.dmg" "$WORK/stage"
# HFS+ image generation adds FinderInfo. Clear it on a disposable writable
# image before compression, then verify the final image independently.
/usr/bin/hdiutil convert -quiet "$WORK/filesystem.dmg" -format UDRW -o "$WORK/writable.dmg"
/usr/bin/hdiutil attach -quiet -nobrowse -noautoopen -mountpoint "$WORK/mount" "$WORK/writable.dmg"
MOUNTED=1
/usr/bin/xattr -cr "$WORK/mount/$APP"
/usr/bin/hdiutil detach "$WORK/mount" >/dev/null
MOUNTED=0
/usr/bin/hdiutil convert -quiet "$WORK/writable.dmg" -format UDZO -o "$WORK/archive.dmg"
/usr/bin/hdiutil verify "$WORK/archive.dmg"
/usr/bin/hdiutil attach -quiet -readonly -nobrowse -noautoopen \
    -mountpoint "$WORK/mount" "$WORK/archive.dmg"
MOUNTED=1
verify_release_bundle "$WORK/mount/$APP" "$BUNDLE_ID" "$SCHEME"
/usr/bin/python3 Scripts/release-privacy.py "$WORK/mount/$APP"
/usr/bin/python3 - "$WORK/mount" "$APP" <<'PY'
import os
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
expected = {sys.argv[2], "Applications"}
if set(item.name for item in root.iterdir()) != expected:
    raise SystemExit("Unexpected file in disk image.")
link = root / "Applications"
if not link.is_symlink() or os.readlink(link) != "/Applications":
    raise SystemExit("Incorrect Applications link in disk image.")
attributes = subprocess.run(["/usr/bin/xattr", "-r", str(root / sys.argv[2])],
                            check=True, capture_output=True)
if attributes.stdout:
    raise SystemExit("Unexpected extended attributes in disk image.")
PY
/usr/bin/hdiutil detach "$WORK/mount" >/dev/null
MOUNTED=0
[ ! -L "$ARCHIVE" ] || fail 'Refusing linked archive destination.'
/bin/mv -f "$WORK/archive.dmg" "$ARCHIVE"
echo "Wrote $ARCHIVE (ad-hoc signed, not notarized)."

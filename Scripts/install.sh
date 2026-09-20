#!/bin/sh
# Build, stage and verify a hardened Release before replacing an installed app.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
cd -P "$(dirname "$0")/.."
. ./Scripts/release-common.sh

DESTINATION=/Applications/SSH-Wakey.app
BUNDLE_ID=com.CadenGithubB.sshwakey
require_real_directory /Applications
check_build_paths Release SSH-Wakey.app
check_installed_identity() {
    require_real_directory "$DESTINATION"
    if [ -d "$DESTINATION" ]; then
        require_real_directory "$DESTINATION/Contents"
        [ ! -L "$DESTINATION/Contents/Info.plist" ] || fail 'Refusing linked installed Info.plist.'
        EXISTING=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$DESTINATION/Contents/Info.plist")
        [ "$EXISTING" = "$BUNDLE_ID" ] || fail "$DESTINATION is not SSH-Wakey. Refusing to replace it."
    fi
}
check_installed_identity

echo 'Building Release…'
/usr/bin/xcodebuild -project SSH-Wakey.xcodeproj -scheme SSH-Wakey \
    -configuration Release -derivedDataPath build build >/dev/null
BUILT=build/Build/Products/Release/SSH-Wakey.app
verify_release_bundle "$BUILT" "$BUNDLE_ID" SSH-Wakey

STAGE=$(/usr/bin/mktemp -d /Applications/.SSH-Wakey-install.XXXXXX)
BACKUP="$STAGE/previous.app"
INSTALLED=0
cleanup() {
    if [ -d "$BACKUP" ] && [ "$INSTALLED" -ne 1 ]; then
        if [ -e "$DESTINATION" ] || [ -L "$DESTINATION" ] || ! /bin/mv "$BACKUP" "$DESTINATION"; then
            echo "Installation interrupted; the previous app remains at $BACKUP" >&2
            return
        fi
    fi
    /bin/rm -rf "$STAGE"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
/usr/bin/ditto --noextattr --noacl --norsrc "$BUILT" "$STAGE/SSH-Wakey.app"
prepare_release_bundle "$STAGE/SSH-Wakey.app" "$BUNDLE_ID" SSH-Wakey
check_installed_identity
if [ -d "$DESTINATION" ]; then
    /bin/mv "$DESTINATION" "$BACKUP"
fi
/bin/mv "$STAGE/SSH-Wakey.app" "$DESTINATION"
INSTALLED=1
echo "Installed verified Release to $DESTINATION"
echo 'Ad-hoc rebuilds can require fresh Keychain approval.'

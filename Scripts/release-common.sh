#!/bin/sh
# Shared checks for local release builds. Callers set -eu before sourcing this.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077

fail() { echo "$*" >&2; exit 1; }

require_real_directory() {
    [ ! -L "$1" ] || fail "Refusing symbolic-link directory: $1"
    if [ -e "$1" ]; then
        [ -d "$1" ] || fail "Not a directory: $1"
    fi
}

check_build_paths() {
    for component in build build/Build build/Build/Products build/Build/Intermediates.noindex \
        build/ModuleCache.noindex build/SDKStatCaches.noindex build/Logs build/SourcePackages \
        build/Index.noindex "build/Build/Products/$1"; do
        require_real_directory "$component"
    done
    require_real_directory "build/Build/Products/$1/$2"
}

verify_signed_component() {
    release_bundle=$1
    expected_identifier=$2
    expected_executable=$3
    require_real_directory "$release_bundle"
    require_real_directory "$release_bundle/Contents"
    require_real_directory "$release_bundle/Contents/MacOS"
    [ ! -L "$release_bundle/Contents/Info.plist" ] || fail "Refusing linked Info.plist"
    [ ! -L "$release_bundle/Contents/MacOS/$expected_executable" ] || fail "Refusing linked executable"
    actual_identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$release_bundle/Contents/Info.plist")
    [ "$actual_identifier" = "$expected_identifier" ] || fail "Unexpected app identifier: $actual_identifier"
    /usr/bin/codesign --verify --strict --all-architectures "$release_bundle" || fail "Code signature verification failed."
    release_architectures=$(/usr/bin/lipo -archs "$release_bundle/Contents/MacOS/$expected_executable")
    [ -n "$release_architectures" ] || fail "No executable architectures found."
    for release_architecture in $release_architectures; do
        release_signature=$(/usr/bin/codesign -dv --arch "$release_architecture" "$release_bundle" 2>&1) || fail "Cannot inspect signature."
        case "$release_signature" in
            *"flags="*"runtime"*) ;;
            *) fail "Hardened Runtime is missing for $release_architecture." ;;
        esac
        release_entitlements=$(/usr/bin/codesign -d --arch "$release_architecture" --entitlements :- "$release_bundle" 2>/dev/null) || fail "Cannot inspect entitlements."
        case "$release_entitlements" in
            *com.apple.security.get-task-allow*|*com.apple.security.cs.allow-*|*com.apple.security.cs.disable-*)
                fail "Unsafe development or runtime-exception entitlement found for $release_architecture." ;;
        esac
        if [ "$4" = sandbox ]; then
            sandbox_json=$(printf '%s' "$release_entitlements" | /usr/bin/plutil -convert json -o - -- -) \
                || fail "Cannot parse password helper entitlements."
            [ "$sandbox_json" = '{"com.apple.security.app-sandbox":true}' ] \
                || fail "Password helper must have only the App Sandbox entitlement."
        fi
    done
}

verify_release_bundle() {
    main_bundle=$1
    main_identifier=$2
    main_executable=$3
    adapter_bundle="$main_bundle/Contents/Helpers/SSH-Wakey Askpass.app"
    input_bundle="$adapter_bundle/Contents/XPCServices/PasswordInput.xpc"
    require_real_directory "$main_bundle/Contents/Helpers"
    require_real_directory "$adapter_bundle/Contents/XPCServices"
    verify_signed_component "$main_bundle" "$main_identifier" "$main_executable" app
    verify_signed_component "$adapter_bundle" "$main_identifier.askpass" "SSH-Wakey Askpass" adapter
    verify_signed_component "$input_bundle" "$main_identifier.askpass.password-input" PasswordInput sandbox
}

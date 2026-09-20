#!/usr/bin/python3
"""Remove local build metadata from staged ad-hoc apps, then check privacy."""
import argparse
import plistlib
import subprocess
import stat
import zipfile
from pathlib import Path


BUILD_KEYS = {
    "BuildMachineOSBuild", "DTCompiler", "DTPlatformBuild", "DTPlatformName",
    "DTPlatformVersion", "DTSDKBuild", "DTSDKName", "DTXcode", "DTXcodeBuild",
}
PRIVATE_PATHS = (b"/Users/", b"/home/", b"/Volumes/", b"/private/tmp/", b"/var/folders/")
ARTIFACT_SUFFIXES = {".log", ".xcactivitylog", ".xcresult", ".crash", ".ips", ".dSYM"}


def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def components(app):
    adapter = app / "Contents/Helpers/SSH-Wakey Askpass.app"
    service = adapter / "Contents/XPCServices/PasswordInput.xpc"
    return [service, adapter, app]


def verify_privacy(app):
    for item in app.rglob("*"):
        relative = item.relative_to(app)
        if item.is_symlink():
            raise ValueError("Unexpected symlink in staged app: " + str(relative))
        if item.suffix in ARTIFACT_SUFFIXES or item.name == ".DS_Store":
            raise ValueError("Local diagnostic artifact in staged app: " + str(relative))
        if not item.is_file():
            continue
        data = item.read_bytes()
        if any(marker in data for marker in PRIVATE_PATHS):
            raise ValueError("Local filesystem path in staged app: " + str(relative))
        if item.name == "Info.plist":
            info = plistlib.loads(data)
            if BUILD_KEYS.intersection(info):
                raise ValueError("Build-machine metadata in staged app: " + str(relative))


def prepare(app):
    bundles = components(app)
    # Refuse to replace a certificate signature with ad-hoc signing. The shell
    # caller verifies all original signatures and entitlements before this step.
    for bundle in bundles:
        info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
        if info.get("CFBundleExecutable") != bundle.stem:
            raise ValueError("Unexpected executable name in staged component.")
        executable = bundle / "Contents/MacOS" / info["CFBundleExecutable"]
        for arch in run("/usr/bin/lipo", "-archs", str(executable)).stdout.decode().split():
            signature = run("/usr/bin/codesign", "-dv", "--arch", arch, str(bundle)).stderr
            if b"Signature=adhoc" not in signature.splitlines():
                raise ValueError("Privacy preparation requires an ad-hoc input build.")
    for bundle in bundles:
        plist = bundle / "Contents/Info.plist"
        info = plistlib.loads(plist.read_bytes())
        executable = bundle / "Contents/MacOS" / info["CFBundleExecutable"]
        run("/usr/bin/strip", "-S", str(executable))
        for key in BUILD_KEYS:
            info.pop(key, None)
        plist.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        arguments = ["/usr/bin/codesign", "--force", "--sign", "-",
                     "--options", "runtime", "--timestamp=none"]
        if bundle == bundles[0]:
            entitlement_file = (Path(__file__).resolve().parent.parent /
                                "SSH-Wakey/Helpers/PasswordInput/PasswordInput.entitlements")
            arguments += ["--entitlements", str(entitlement_file)]
        # Sign the XPC service, its adapter, then the enclosing app. Each outer
        # seal must cover the already-finalized inner bundle.
        run(*arguments, str(bundle))
    verify_privacy(app)



def archive(app, destination):
    verify_privacy(app)
    # Write file contents explicitly. Filesystem copy APIs can reattach local
    # provenance even when asked to omit xattrs; ZIP entries have none here.
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as output:
        for item in [app] + sorted(app.rglob("*")):
            name = str(item.relative_to(app.parent))
            directory = item.is_dir()
            if directory:
                name += "/"
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            mode = (stat.S_IFDIR | 0o755) if directory else (
                stat.S_IFREG | (0o755 if item.stat().st_mode & 0o111 else 0o644))
            entry.external_attr = mode << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(entry, b"" if directory else item.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("app", type=Path)
    args = parser.parse_args()
    if not args.app.is_dir() or args.app.is_symlink():
        parser.error("Expected a real app directory.")
    if args.prepare:
        prepare(args.app)
    else:
        verify_privacy(args.app)
    if args.archive:
        archive(args.app, args.archive)


if __name__ == "__main__":
    main()

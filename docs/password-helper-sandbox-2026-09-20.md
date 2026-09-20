# Password helper sandbox — 2026-09-20

The SSH password field now runs in a small, separately signed App Sandbox XPC
service. The main application no longer contains the password dialog implementation.
A separate signed askpass adapter handles only authorization metadata and open
file descriptors. There is no unsandboxed password-entry fallback.

## Process and capability boundaries

1. The app validates the host and registers its exact Apple SSH child. A private
   UNIX socket carries authorization metadata, never the password.
2. SSH launches `Contents/Helpers/SSH-Wakey Askpass.app`. Both ends verify the
   socket peer's code identity and the registered parent/child relationship.
3. The adapter launches its embedded `PasswordInput.xpc`, pins the service's
   code hash and passes a read-only handle to its own executable for caller
   verification. The service requires that handle to name its enclosing adapter,
   extracts the expected code hash, and installs an XPC signing requirement.
4. A separate XPC message, now subject to that requirement, passes the connected
   authorization socket, SSH's writable output pipe, a read-only handle to the
   enclosing main executable, and bounded nonsecret metadata. The service checks
   the main app's kernel audit token against the expected code hash. Security
   validates the supplied Info.plist bytes against the running app's signature.
5. Only after those checks does the service show the native secure field. A
   scoped Swift String bridge still exists inside this short-lived process.
   Controlled UTF-8 storage is locked, written directly to SSH, and wiped.
6. Darwin updates socket peer credentials when the service becomes the writer.
   Before permitting output, the app verifies that new writer against the fixed
   service executable and its signed code hash, while also requiring the original
   adapter and registered SSH process to remain alive.
7. Replies contain status only. The service accepts one caller/attempt, monitors
   cancellation, and exits after completion. A process alarm also bounds stalls.

The password service receives only `com.apple.security.app-sandbox=true`.
There are no network, file, app-group, inheritance, or temporary-exception
entitlements. It checks this exact set at startup. Both helpers enforce Hardened
Runtime without debugging or code-loading exceptions, including test builds.
The release packaging check verifies all three signed components and the
service's exact entitlement set for every architecture.

### Xcode test signing

Xcode's entitlement-packaging task can add read access to `/` and Mach lookup
exceptions during test/profile builds, even when testability and base-entitlement
injection are disabled. Those exceptions would invalidate the
sandbox test. The helper target therefore passes its fixed entitlement file
directly to `codesign` through `OTHER_CODE_SIGN_FLAGS`, and also explicitly sets
`--options runtime`. `ENABLE_APP_SANDBOX=NO` disables Xcode's automatic entitlement
generation; it does **not** disable the actual sandbox, which is enabled by the
signed entitlement and checked at runtime. Do not replace this configuration
with the checkbox alone. Helper preview/debug dylibs are disabled.

## Tests and limitations

A synthetic real-SSH integration test checks denial of unrelated file reads,
file writes, executable writes, IPv4/IPv6 TCP connections, UDP connections and a
fresh UNIX-socket connection. It also rejects an incorrect peer code hash and
altered signed Info.plist data, while proving that the passed channel and output
pipe work. Diagnostic entry points are compiled out of release builds and never
create a password field. No test uses real SSH credentials or a remote host.

App Sandbox still grants access to the service's own container and necessary
system resources. This design provides no general user-filesystem or network
capability, but does not guarantee that a compromised service could never write
anything anywhere. No filesystem bookmarks or sandbox extensions are passed.
The main app and metadata-only adapter remain unsandboxed. AppKit, Swift bridge,
OpenSSH and kernel memory copies are not guaranteed to be physically erased.
Developer ID signing/notarization and testing on additional supported macOS
versions and hardware configurations remain distribution work; local signing is
ad-hoc.

Validation summary (workstation details and raw logs excluded):

- 388 tests passed in both standard and managed configurations.
- Native sandboxed dialog: synthetic submission succeeded; Cancel sent no bytes.
- Standard and managed universal release builds cover arm64 and x86_64.
- All three components passed strict signature checks across both architectures,
  Hardened Runtime checks and the password service's exact entitlement check.
- Re-signed disposable release copies with a network entitlement, broad read
  exception, or missing service Hardened Runtime were rejected by packaging for
  the intended reason.

The native tests used an isolated test store and disposable local SSH keys.
No real vault was migrated and no app was installed or distributed by this change.

Sources: Apple's [App Sandbox overview](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox),
[XPC code-signing requirement API](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:)),
and Swift Build's [test entitlement augmentation](https://github.com/swiftlang/swift-build/blob/main/Sources/SWBTaskExecution/TaskActions/ProcessProductEntitlementsTaskAction.swift).

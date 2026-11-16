# Security review of SSH-Wakey 1.3.0

Reviewed release: `v1.3.0`, commit `f3b6c960783f76a7f765142daa95a93f2bd4d949`.

The review found two medium-priority sensitive-data handling defects, one
lower-impact SSH policy defect, and a reproducible password-helper compatibility
failure in the test environment. This release does not receive an all-clear.
No SSH password disclosure, arbitrary command injection, or host-authentication
bypass was demonstrated in the reviewed paths.

Application sources remain at the published release. This report records
findings, not fixes. Pre-existing local changes were preserved separately in a
named Git stash before the checkout was fast-forwarded.

## Findings

### 1. Export can overwrite the active encrypted vault with plaintext

**Priority: P2 / medium.** Source:
[ConnectionStore.swift](../SSH-Wakey/Models/ConnectionStore.swift), lines 583–601;
[SecuritySettingsView.swift](../SSH-Wakey/Views/SecuritySettingsView.swift),
lines 222–240.

`export(to:passphrase:)` authenticates the recovery phrase, serializes a plaintext
document, and writes to the supplied URL without excluding the active store.
The save panel limits the file type to JSON but does not exclude that destination.
A user can select the application's own `connections.json` through Go to Folder
and confirm replacement while intending to export a readable copy.

A disposable protected vault using the actual store, cryptographic, and
filesystem code reproduced this sequence:

1. Open the synthetic App Lock vault with its recovery passphrase.
2. Call `store.export(to: store.fileURL, passphrase: phrase)`.
3. The disk file now contains plaintext connection metadata; the open store
   still reports encryption and App Lock enabled.
4. Reopen the store: it opens immediately as plaintext, with encryption and
   App Lock disabled.

The valid recovery passphrase is required. This is an unintended security
downgrade and misleading protection state, not a way for an unauthenticated
attacker to obtain the vault. SSH passwords are not part of the exported data.

**Recommended correction:** refuse an export destination identifying the active
store, including aliases of the same filesystem location. Enforce this in the
store rather than only in the save panel. Regression tests should verify that
self-export leaves bytes and protection state unchanged, while a separate
plaintext export still succeeds.

### 2. Normal quit leaves a copied recovery passphrase on the clipboard

**Priority: P2 / medium.** Source:
[PassphraseSheet.swift](../SSH-Wakey/Views/PassphraseSheet.swift), lines 281–298;
[SSHWakeyApp.swift](../SSH-Wakey/SSHWakeyApp.swift), lines 135–137.

The UI promises to clear an unchanged recovery-phrase clipboard entry after
90 seconds. Cleanup is an in-process delayed callback. Normal termination only
disconnects sessions; it does not clear the entry owned by `RecoveryClipboard`.
Quitting or closing the last app window before expiry therefore leaves the
recovery phrase available after the timer's process has exited.

A synthetic writer used the actual extracted termination handler and clipboard
ownership implementation with a uniquely named pasteboard, then exited. A
separate reader retrieved the same phrase 113 seconds later. The test pasteboard
was cleared afterward; the user's general clipboard was untouched.

**Recommended correction:** call `RecoveryClipboard.clearIfOwned()` during
normal termination. Test both owned-secret cleanup and preservation of clipboard
content another application has subsequently replaced. A crash or force quit
still cannot guarantee cleanup; clipboard-manager hints are not access controls.

### 3. Terminal's no-network fallback guard is ignored by SSH

**Priority: P2 / lower security impact.** Source:
[SSHCommandBuilder.swift](../SSH-Wakey/SSH/SSHCommandBuilder.swift), lines
100 and 225–231.

The shared options set `ProxyJump=none` before Terminal attachment adds
`ProxyCommand=/usr/bin/false`. System OpenSSH accepts the earlier transport
selection and ignores the intended failing proxy. If the master disappears
between the app's check and execution of the handoff script, the Terminal client
can initiate a fresh network connection.

A driver compiled from the release's actual command builder, connection model,
and argument parser was exercised against a disposable loopback listener:

| Attachment configuration | New TCP connection with absent master |
| --- | --- |
| Unmodified 1.3.0 arguments | Yes |
| Forced `ProxyCommand` placed first | No |

Both runs exited with failure. Strict checking against empty trust sources and
batch mode still prevented fresh authentication. No password disclosure or
authentication bypass was demonstrated. The existing regression checks whether
the argument is present, not how SSH interprets the combination.

**Recommended correction:** put the forced failing proxy before the shared
options for attachment, or remove the redundant jump setting from the isolated
configuration. Add an actual system-SSH configuration or loopback regression.

## Password-helper validation blocker

**Priority: P1 / functional blocker in the tested environment.**

Both Standard and Managed ran 388 tests. Each had one failing test,
`testSandboxDeniesUnrelatedFilesAndNewNetworkConnectionsButAllowsPassedChannels`,
with two failed assertions at `PasswordChannelTests.swift` lines 301–302.
The remaining 387 tests in each configuration passed.

Instrumentation in a disposable source copy localized the failure to
[HelperIdentity.swift](../SSH-Wakey/SSH/HelperIdentity.swift), line 56.
During `PasswordInputService.prepare`, descriptor mode, type, size, and expected
path checks succeeded, but `SecStaticCodeCreateWithPath` on `/dev/fd/<fd>` returned
status `100001` (`Operation not permitted`). The service could not finish the
adapter signature requirement preparation. It never reached the sandbox probe
or password-entry UI.

Direct `pread` on the passed descriptor succeeded, while reopening
`/dev/fd/<fd>` failed with `EPERM`. Security inspection through the canonical
executable pathname failed as well. Repeating the test from an ordinary
repository build directory produced the same result, ruling out temporary build
placement or a path-alias mismatch. The helper assumes a readable transferred
descriptor can be reopened by pathname under the sandbox; that assumption fails
here.

This is a **fail-closed availability/compatibility issue**, not evidence that the
helper can escape its sandbox or disclose a password. Ordinary password entry
uses the same preparation path, so its operation in this environment is not
validated. Do not resolve this by skipping identity verification or granting
broad filesystem access. Investigate descriptor-based signature inspection under
the actual supported OS sandbox rules, then rerun the integration test and a
synthetic native entry/cancellation check.

## Review and verification coverage

| Area | Work performed and result |
| --- | --- |
| Password entry and IPC | Reviewed native secure field, signed adapter, XPC preparation and caller requirements, socket audit tokens, registered SSH process lineage, one-shot authorization, cancellation, output descriptors, size/line restrictions, locked buffers and wiping. No further verified disclosure or caller bypass; runtime blocker above remains. |
| SSH trust and execution | Reviewed option parser/validator, strict private Ed25519 trust snapshots, independent fingerprint enrollment, authenticated callback, bounded process runner, cancellation and abandoned-session cleanup. Eighteen accepted option combinations preserved fixed policy in actual SSH parsing; sixteen adversarial combinations were rejected. |
| Storage and cryptography | Reviewed AES-GCM domains, independent recovery verification, PBKDF2 input bounds, key rotation, Keychain and Secure Enclave integration, file revisions, descriptor traversal, ownership/ACL checks, symlink/hard-link rejection, private staging and failure behavior. Export exception is recorded above. |
| App Lock and UI | Reviewed startup lock, expiry, sleep/screen/user-switch events, pending-operation generations, session revocation, stale UI callbacks, recovery fields, clipboard ownership, settings and diagnostics access gates. Clipboard termination exception is recorded above. |
| Diagnostics and privacy | Reviewed bounded transient classification, exclusion of raw server output/prompts from retained diagnostics, output sanitization, saved metadata/history, exports, managed catalog and MAC cache. |
| Builds and packaging | Standard Release and ManagedRelease built for both arm64 and x86_64. All three components passed strict signature and Hardened Runtime checks; password services had exactly the App Sandbox entitlement, without development/runtime exceptions. |
| Staged archives | Disposable copies passed privacy preparation, re-signing checks, ZIP CRC, fixed timestamp and absence-of-extra-metadata checks. A deliberately re-signed helper with a network entitlement was correctly rejected by the release guard. |
| Repository scan | Pattern scan covered 106 tracked files and 355 reachable historical blobs for private-key headers, recognizable access-token formats, credential-bearing URLs and workstation paths. No private keys or recognizable access tokens were detected. This is not proof against arbitrary secret formats. |
| Basic checks | Shell and Python script syntax checks and whitespace validation passed. No third-party application package dependencies were identified. |

The repository scan found a historical personal-path/username test fixture in
the initial commit `3a39ff9`, removed in `ab7f0d1`. It remains reachable in Git
history. The current release does not contain that fixture. This is a low-level
repository privacy observation, not an exposed SSH password or private key.
History rewriting was not performed.

## Remaining boundaries and limits

- SSH password bytes stay outside the main app and adapter. The sandboxed
  service writes to SSH's pipe, and owned buffers require memory locking and are
  wiped. AppKit/Swift framework storage, kernel pipes, and OpenSSH's memory do
  not have an application-enforceable complete-erasure guarantee.
- Vault encryption covers connection metadata and history. Enrolled hostnames
  and public host keys remain in the separate plaintext trust file. Exports are
  intentionally plaintext. Existing backups and filesystem snapshots cannot be
  retroactively erased by enabling encryption.
- Recovery phrases can unlock copied vaults. Explicit clipboard copying exposes
  them to clipboard readers; concealed/transient hints do not prevent a hostile
  application from reading them.
- Release signatures are ad hoc. These checks do not establish Developer ID
  provenance or notarization, and a compromised OS or modified application is
  outside the claimed boundary.
- Tests and proofs used synthetic data, disposable keys/directories and a named
  test pasteboard. No real remote password, production vault migration, app
  installation, or remote machine was needed. New hardware-authentication and
  physical FileVault-startup flows were not exercised. The existing suite does
  not type into the native password field during an ordinary run.
- Verification covered the fetched source and locally built/staged artifacts;
  GitHub-hosted downloadable binaries were not independently compared. Results
  do not establish compatibility across every supported OS/hardware combination.

Raw logs, result bundles, workstation details and test credentials are excluded
from this report and from the repository.

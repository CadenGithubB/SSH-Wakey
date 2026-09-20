# Security hardening review — 19 September 2026

This review covers the local working tree based on commit `fb2a65b`, including
the earlier uncommitted security changes. The earlier 283-test implementation
was a useful start, but passing those tests did not establish the intended
password and host-trust boundaries. This report records the initial hardening
stage; subsequent App Lock and sandbox work is linked below. Validation did not
install the app or use a production vault.

## Findings addressed

| Area | Resulting protection |
| --- | --- |
| SSH password entry | A native secure field now runs in a separately signed, short-lived sandboxed XPC service; a small signed adapter connects it to SSH. The main app never receives the password. SwiftUI password bindings and the password-bearing IPC reply are removed. |
| Helper impersonation/replay | Both ends check UID, kernel audit-token code identity, the exact live Apple SSH child, its parent and process start identity. Copying the socket path and nonce is insufficient. |
| Password lifetime | One prompt per attempt; bounded authorization; cancellation and quit close the channel; page-aligned controlled storage must lock successfully and is wiped after direct output. No appended password byte array is created. |
| Authentication result | A verified callback from the registered SSH child replaces diagnostic-text matching. A local test demonstrated that remote text could forge an apparent authentication log line. The callback has two fixed arguments, so one server-controlled askpass prompt cannot select it. |
| Host trust | Independent fingerprint entry, one validated Ed25519 key, a separate private trust file and a protected read-only snapshot for each attempt. Old settings cannot disable strict checking. |
| SSH arguments | Strict bounded allowlist; user/system configuration ignored; forwarding, alternate trust, jump hosts, arbitrary commands and authentication overrides refused. A fixed application-owned LocalCommand is used only for the authenticated callback. |
| Process and diagnostic handling | Minimal child environment, bounded input/output and timeouts, owned child reaping, cancellation, bounded DNS work. SSH diagnostics use a private FIFO; raw retention stops before password entry. Persisted/exported history contains curated statuses. |
| Terminal handoff | A private executable script attaches to the existing master. Its fixed failing proxy prevents fallback authentication. Arguments are quoted; the absolute system Terminal app is opened. |
| Private files | Descriptor-based parent traversal, owner/mode/ACL checks, no user-controlled symlinks, regular-file and hard-link checks, private staging before content writes, atomic replacement and revision checks. |
| Damaged connection files | Existing empty, corrupt, insecure, inaccessible and newer-format files remain unavailable. Add/edit/export/encryption paths cannot silently replace them. |
| Vault and Keychain | Bounded validated derivation metadata, independent recovery-slot decoding, protected derivation buffers, data-key rotation on recovery-passphrase change, and serialized file/Keychain transactions. Failed recovery does not replace a working Keychain key prematurely. |
| Managed profiles | Destinations and options are validated before use. Managed tests run against the managed app configuration. |
| Recovery UI | Native secure fields replace persistent SwiftUI secret strings. Submission uses scoped bridges; fields clear on completion/cancellation. Clipboard copying remains explicit and conditionally expires. |
| Release tooling | Install/package scripts require valid signatures, Hardened Runtime and absence of debug/code-loading exception entitlements before accepting either app variant. |

## Memory ownership and remaining copies

| Data | Where it exists and when it is released |
| --- | --- |
| SSH password during typing | AppKit's secure field and native text machinery in the helper. These backing stores cannot be proven locked or erased by the app. |
| SSH password on submission | A scoped AppKit-to-Swift String bridge, then an owned locked mapping. The mapping is fully wiped/unmapped; the helper exits. Swift/native temporary storage has no reliable explicit-erasure guarantee. |
| SSH password after output | The kernel pipe and system OpenSSH. These are outside the app's allocation ownership. The main app receives status only. |
| Authorization identifiers | A random nonce, socket path, process identities and destination metadata. These are not password material; process identity is required in addition to possession. |
| Recovery passphrase | Native fields in the main app, scoped String bridges, and protected derivation input. Framework-owned copies remain possible. Explicit Copy also places it on the pasteboard. |
| Vault keys | Security framework return storage and CryptoKit SymmetricKey internals, plus owned derivation/unwrapped buffers where needed. Owned buffers are cleared; platform-internal copies are not under explicit erase control. The open vault retains its data key for normal editing. |
| Decrypted connection metadata | The open connection model and edit history. Owned serialization/decryption Data is cleared when finished, but displayed metadata intentionally remains in application memory. |
| Logs | Bounded pre-password classification input and curated activity records. Raw server data is not an authentication signal or a persisted diagnostic record. |

The app and helper disable core dumps. Failure to lock an owned secret buffer
refuses the operation. These measures do **not** prove that every plaintext copy
is absent from swap, a privileged memory inspection or framework storage.
Replacing a Swift String with a native popup alone cannot provide that guarantee.

## Verification

Verification used isolated test data. All test credentials and keys were
synthetic; workstation details and raw execution logs are excluded from this
report.

- Initial hardening stage, standard app: **343 tests passed, zero failures**.
- Initial hardening stage, managed app: **343 tests passed, zero failures**.
- Release and ManagedRelease: built successfully; strict signatures, runtime
  flags and entitlement checks passed for both arm64 and x86_64.
- Real Apple SSH and a local pipe-connected sshd authenticated with disposable
  keys and successfully invoked the signed post-authentication callback. This
  required no listening port, remote machine or system SSH configuration change.
- Copied helper authorization was refused before UI. The actual-source native
  input harness accepted masked synthetic input and wiped the returned buffer;
  expiration/cancellation returned no password.
- The real signed helper, launched by registered Apple SSH after local synthetic
  authentication, displayed the native popup and completed the submission
  handshake. The test recorded only `served=true`, `cancelled=false` and
  `wrongProgramAttempts=0`; its stdout was discarded. This also verified native
  AppKit startup and the final secure-input submission guard.
- The recovery sheet masked input, refused mismatched confirmation, and reopened
  with empty fields after cancellation in an isolated app store.
- Forced memory-lock failure refused SecureBuffer allocation and vault derivation.
- Actual SSH configuration parsing verified quoted paths and policy values.
  Private-file and host-trust checks exercised unsafe modes, symlinks, malformed
  keys and protected snapshots.
- Shell syntax checks and `git diff --check` passed.

The repository's regression tests and this summary record the checks performed.
Raw build and test logs are not included. Tests did not use a real remote account
password or exercise a physical Mac's FileVault startup unlock.

## Operational consequences and limits

Existing `~/.ssh/known_hosts` entries are not imported automatically. Enroll each
destination using a fingerprint obtained independently from its actual target.
Ed25519 host keys are required. Jump hosts, permissive host checking and prompted
private-key passphrases are intentionally unsupported in this flow. SSH keys
available through an appropriate agent can authenticate without a password popup.

Vault encryption covers the connection payload. The private host-trust file
still contains enrolled hosts and public keys in plaintext. Old exports,
backups and filesystem snapshots cannot be retroactively erased. An old vault
and its old recovery phrase still open that old copy.

Use the hardened Release build for normal use. The main app and adapter remain unsandboxed, while password entry is sandboxed. All are locally ad-hoc signed; Developer ID signing and notarization remain distribution work.
The same-user control socket, unlocked Keychain and open app are not a complete
boundary against malware running as the user. Host authentication also cannot
protect a password from the correctly authenticated server receiving it.

For the ongoing security contract and full command inventory, see
[SECURITY.md](../SECURITY.md). This review improves concrete boundaries and
failure behavior; it is not a guarantee of complete RAM erasure or absence of
all vulnerabilities.

The subsequent [App Lock implementation](app-lock-2026-09-20.md) and
[helper sandbox implementation](password-helper-sandbox-2026-09-20.md) document
the added boundaries and the final 388-test suites in both configurations.

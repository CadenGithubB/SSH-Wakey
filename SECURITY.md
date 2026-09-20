# Security model

SSH-Wakey runs the system `/usr/bin/ssh` to authenticate to a saved Mac. SSH
passwords are entered in a separate, short-lived native helper. The main app
receives authorization and status messages, not the password. Neither the helper
nor the app intentionally saves SSH passwords to files, preferences, Keychain,
logs, command arguments or environment variables.

This is defense in depth for an uncompromised Mac running the hardened Release
build. It is not a guarantee that plaintext never exists in RAM. AppKit, OpenSSH,
the kernel and cryptographic frameworks own memory the app cannot erase. A
compromised operating system, a modified app, or a malicious authenticated SSH
server remains outside this protection.

## SSH password lifetime

1. The app validates the destination and options, creates a private temporary
   directory, and copies its validated host-key store into a read-only snapshot.
   SSH always checks this snapshot strictly before password authentication.
2. The app creates a mode `0600` UNIX authorization socket inside that mode
   `0700` directory. The SSH child receives a minimal environment with the helper
   executable path, socket path and a random 256-bit nonce. These are not passwords.
3. The app registers the exact SSH child: PID, process start time, parent, UID
   and executable. It also checks Apple's code-signing requirement for system SSH.
4. When SSH requests a password, it starts the embedded signed askpass adapter,
   without initializing the app model, vault or SwiftUI window. Both ends
   verify the socket peer's UID, kernel audit-token code identity, and the exact
   SSH parent relationship. Missing identity information is a refusal. Copying
   the environment and launching the genuine helper from another process is
   insufficient.
5. The app authorizes at most one password popup for the attempt. The adapter
   passes the authorized channel and SSH's stdout pipe to its separately signed
   App Sandbox XPC service. The adapter verifies the service signature; the
   service pins its caller through XPC and independently verifies the main-app
   socket peer's kernel audit token and signed Info.plist. Read-only handles to
   the fixed enclosing executables allow identity checks without granting folder
   access. A second XPC message is required after the caller requirement is set.
   Only the sandboxed service shows an `NSSecureTextField` with the destination supplied by the app. It uses
   secure event input while active and closes on cancellation, parent loss,
   main-app exit or expiration. A server prompt does not supply the displayed destination.
6. On submission, a scoped AppKit-to-Swift `String` bridge copies UTF-8 directly
   into a page-aligned `mmap` allocation. `mlock` must succeed. The helper refuses
   empty answers, NUL/newline characters and answers exceeding 1,022 UTF-8 bytes,
   avoiding askpass line injection and OpenSSH reader truncation.
7. Authorization is checked again. The helper writes directly from that buffer
   to SSH's stdout pipe, wipes its complete allocation with `memset_s`, unmaps
   it, writes the newline separately, and exits. No appended password `Data` or
   byte-array copy is constructed. Status messages contain no secret bytes.
8. Repeated password prompts and private-key passphrase prompts are refused.
   Attempts are bounded and cancellation closes the authorization channel.

The app, adapter and password service disable core dumps. SSH inherits that
restriction. The password service has only the `com.apple.security.app-sandbox`
entitlement, with no network, file, group, inheritance or temporary exceptions.
It refuses startup if its entitlement set differs. It cannot open new network
connections or arbitrary user files. Standard App Sandbox still permits its own
container and system/framework resources. This is containment, not a guarantee
that a compromised helper could never persist data anywhere. No user-data
bookmarks or filesystem sandbox extensions are passed to it.

The main app and adapter never receive password bytes through XPC or their
private authorization socket. XPC replies carry only success/failure. The service
accepts a single caller and attempt, checks that output is a writable pipe,
monitors cancellation/process identities and exits after submission or failure.
Missing helpers and failed checks abort; there is no unsandboxed password fallback.
A live session holds no application password buffer. Terminal attaches to the
existing master; its fixed failing fallback command prevents a new connection
if that master disappears.

### What a native popup does not solve

`NSSecureTextField` masks input and integrates with native text entry. It does not
promise a caller-controlled, zeroizable backing store. The helper's temporary
Swift string and AppKit's copies cannot be reliably overwritten. Process
isolation confines those input copies to a helper that exits after the attempt;
it does not prove physical erasure or prevent framework-managed pages from
being paged out. Only the explicitly locked buffer has that guarantee while
locked. OpenSSH must also hold the password to perform password authentication.

The recovery passphrase is a separate secret used by the main app's vault. Its
native fields avoid SwiftUI string bindings, but submission still crosses scoped
String and CryptoKit/CommonCrypto boundaries. Owned derivation buffers are
locked and wiped; framework copies and `SymmetricKey` internals are outside the
app's erase control. Decrypted connection metadata is intentionally retained
while the file is open so it can be displayed and edited.

For a design that avoids sending an account password, use SSH key authentication
with a suitable agent or hardware-backed signer. That requires support from the
target Mac; it may not serve the same FileVault startup-unlock workflow. A local
Touch ID/Keychain permission popup authorizes a local operation. It cannot replace
a remote account password that the remote SSH server requires.

## Host trust and command execution

Each app distribution has its own `known_hosts` file in its Application Support
folder. User/system SSH configuration and global trust files are disabled.
The trust file contains enrolled host addresses and public keys in plaintext, even
when the separate connection list is encrypted. Existing entries in
`~/.ssh/known_hosts` are not silently imported. Old settings
that disabled strict checking are normalized to strict checking.

Enrollment fetches exactly one Ed25519 key, validates its SSH wire format and
computes SHA-256 in process. The user must enter the fingerprint obtained through
an independent trusted route, such as a terminal on the target Mac:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

A network scan alone proves no identity. The app refuses changed keys, duplicate
host entries, wildcard entries, extra algorithms and malformed trust stores.
Every authentication uses a validated private snapshot; SSH never updates it or
automatically accepts a new key. Ed25519 is currently the only supported host-key
algorithm. Configuring a different algorithm requires a deliberate design change.

Extra options are parsed as argv, without shell expansion, and accepted only from
a small allowlist with bounded values. Allowed tuning includes IP version,
verbosity, identity-file selection, identities-only behavior, connection attempts,
keepalives and address family. `-F`, `-I`, `-J`, proxy commands, arbitrary local
commands, forwarding, alternate trust sources, code providers and authentication
policy overrides are refused. Jump hosts are deliberately unsupported: this
password path must authorize one destination, not another authentication endpoint.
Agent/X11/TCP forwarding, automatic agent key additions, GSSAPI delegation,
host-based authentication and automatic host-key updates are disabled.

| Operation | Executable and control |
| --- | --- |
| Wake or session | `/usr/bin/ssh`, isolated config, strict Ed25519 trust, validated argv, minimal environment |
| Authentication status | Fixed `LocalCommand` executes the same signed helper after SSH authentication; both helper arguments are constants, executable path is shell-quoted and SSH percent expansion escaped |
| Host-key enrollment | `/usr/bin/ssh-keyscan -t ed25519`, validated host/port, bounded time/output; SHA-256 is computed in process |
| Master check/cleanup | `/usr/bin/ssh -O check/exit`, private control socket, isolated config |
| Terminal handoff | `/usr/bin/open` opens a private mode `0700` `.command` file; the file removes itself, then execs quoted SSH arguments with network fallback disabled |
| Wake address lookup | `/usr/sbin/arp -n`, numeric IPv4 only, bounded runner |
| Wake packet | UDP magic packet and bounded name lookup; no credential involved |

The post-authentication helper callback is verified against the registered SSH
process. An SSH banner, disconnect reason, diagnostic line or successful process
exit alone cannot mark authentication successful. OpenSSH logs can contain
server-controlled newlines, including forged “Authenticated to” records, so they
are never authentication evidence. The callback mode takes two fixed arguments;
a single askpass prompt cannot select it.

Transient diagnostic input uses a private FIFO, not a regular logfile, and is
capped. Raw collection stops before password entry. Activity and exported
diagnostics retain only curated statuses and user-supplied destination metadata;
server output and prompts are not retained there. Auxiliary subprocesses have
nonblocking input, capped output, cancellation, timeout escalation and owned child reaping.
Session termination targets Foundation's live system-SSH process, without a
later raw-PID kill that could hit a reused PID.

## Files and encrypted storage

Standard stores connections at:

```
~/Library/Application Support/SSH-Wakey/connections.json
```

This contains connection metadata, MAC addresses and edit history, never SSH
passwords. History retains old metadata values. The eye control hides display
fields; it does not encrypt metadata or remove it from memory.

Private-file access walks parent directories using descriptors and refuses
user-controlled symlinks, unsafe owners, writable ancestors, unsafe ACL grants,
nonregular files, hard links and oversized content. New files are created in a
private staging directory, with inherited ACLs removed and mode applied before
content is written. Atomic replacement, directory locking and revision checks
prevent cooperating app instances from silently overwriting each other's edits.
Only verified absence permits a new empty store. Existing empty, corrupt,
inaccessible, insecure or newer-format files remain unavailable and cannot be
silently replaced by adding connections, exporting or enabling encryption.

Encryption uses AES-256-GCM with a random data key. Independent slots wrap that
key using a local key and a PBKDF2-HMAC-SHA256 recovery key. The local key uses
the login Keychain by default, or user-presence-protected Secure Enclave key
agreement when App Lock is enabled. New vaults use
600,000 rounds and a 16-byte salt. Readers validate formats, cipher/derivation
identifiers, salt/key sizes and bounded work factors before derivation. A damaged
slot does not prevent using an intact other slot. Owned plaintext serialization,
unwrapped-key and derivation buffers are cleared when finished.

Changing the recovery passphrase rotates the data key, re-encrypts the payload
and rebuilds both slots. A copied old vault plus its old passphrase does not
unlock subsequently saved data. It still unlocks that old copy: backups cannot
be remotely revoked. Without App Lock, recovery restores Keychain access without
replacing another instance's working Keychain key before a potentially failing
file save. With App Lock, recovery preserves the protected mode.

Standard stores learned MAC addresses within the same connection file and removes
its legacy plaintext sidecar when encryption is enabled/opened. Managed has a
separate private MAC cache for its IT-provided catalog; it has no encrypted user
vault. Managed entries are validated before they can be launched.

Exports are explicitly plaintext. Recovery passphrase Copy deliberately puts a
secret on the clipboard. Concealed/transient/local-only pasteboard hints and
conditional expiry are mitigations, not access controls against another app.
Manual exports, old files, backups, APFS snapshots and previously existing
plaintext copies cannot be securely erased retroactively by this app.

FileVault protects storage at rest. Locking the screen does not relock a mounted
FileVault volume or remove an application's keys from memory. Vault encryption
helps with raw file copies and backups. Without App Lock it opens automatically
in your account. Neither mode protects data already obtained by an attacker who
can read the unlocked app's live process or possess a valid recovery passphrase.

## Optional App Lock

The standard app can require local macOS authentication to open its encrypted
connection vault. This is separate from authenticating to a remote SSH server;
the app still never stores a remote account password.

App Lock uses a user-presence-protected Secure Enclave key, with Touch ID or the
Mac login password handled by macOS. The opaque hardware-bound private-key blob
can be stored outside the Data Protection Keychain. This avoids making an
unprotected Keychain read conditional only on a UI authentication result. The
protected operation itself must succeed to derive the wrapping key. No
unprotected fallback is used when hardware or authentication is unavailable.

Enabling or disabling App Lock requires the recovery passphrase and safely
migrates the vault. The protection metadata is authenticated; older readers must
refuse the protected format. Password text is processed in a synchronous scope
before asynchronous system authentication begins. Prepared changes hold owned
key objects and sealed material, not a recovery-password String.

An enabled vault starts locked. A successful unlock retains the open data key
and connection model until five minutes without input delivered to SSH-Wakey,
or until screen lock, sleep, user switching or manual locking. Activity in
Terminal or another app does not renew the lease. A monotonic clock that includes
sleep measures the deadline; a late input event cannot renew an expired lease.

Locking revokes session access before releasing the vault state, cancels pending
authentication and SSH attempts, disconnects masters, dismisses editors, removes
transient session files and clears retained diagnostics. A generation check
prevents a late authentication or network result from restoring access. Local
activity monitoring does not install a global keyboard monitor or require
Accessibility permission. System lifecycle notifications and wake checks provide
additional revocation; a stalled or compromised process/OS is not a trusted clock
enforcement boundary.

These lock actions run in the app process. A crash or force quit can leave an
SSH master alive until the next launch's abandoned-session cleanup; App Lock is
not an independent watchdog for a terminated app. Normal quitting and locking
explicitly disconnect sessions.

Disconnecting the SSH transport does not erase Terminal scrollback or stop
remote jobs that were explicitly detached from the session. Those remain outside
this app's access boundary.

Recovery passphrase access remains a deliberate second route into the vault.
It preserves App Lock rather than silently creating an unprotected replacement
slot. Copies of the recovery phrase or a previously unprotected vault remain
sensitive. Clipboard expiry and lock cleanup only clear a phrase copied by this
app when the clipboard has not subsequently changed.

Releasing the connection model, CryptoKit key objects and native fields does not
prove physical erasure of their backing memory. The hardware private key remains
nonexportable; derived symmetric material and the open vault data still have to
exist in ordinary process memory while in use.

## Release builds and operating boundaries

Release and ManagedRelease enable Hardened Runtime and exclude debug attachment
and code-loading exception entitlements. Both helpers use Hardened Runtime and
exclude debugger entitlements even in Debug. Main-app Debug builds permit debugging and must
not be treated as equivalent protection. The install/package scripts verify the
signature, runtime flag and entitlements of all three executables before accepting a build; a failed
verification stops them.

The main app and metadata-only adapter remain unsandboxed; the password-entry
service is sandboxed. Local builds are currently ad-hoc signed. Rebuilds change its designated
requirement and can require new Keychain permission. Developer ID signing and
notarization are needed for a normal distributed release. Code signing protects
process identity; it does not authenticate the remote host or make an untrusted
binary safe.

The same-user control socket and connection files are not a boundary against all
malware running as your account. Such software may use an existing SSH master,
change user-owned files, interfere with availability or misuse UI permissions.
Hardened Runtime reduces injection/debugging exposure; it cannot secure a fully
compromised account or OS. Secure event input also does not protect against every
accessibility tool, input method or privileged observer.

Closing a normal app session stops its masters. Startup cleanup only examines a
validated private temporary root and refuses symlink entries; process start
identity distinguishes live owners from reused PIDs. Tests use explicit isolated
roots and must never sweep the user's real sessions.

The regression suite exercises these controls with synthetic data. Passing
those tests and reviewing the source cannot prove the absence of every memory
copy, race, OS bug or future OpenSSH behavior change. Changes to helper identity,
SSH arguments, host trust and password lifetime should be reviewed together.

Implementation references: OpenSSH's [post-authentication LocalCommand call](https://github.com/openssh/openssh-portable/blob/master/ssh.c)
and [command parsing](https://github.com/openssh/openssh-portable/blob/master/readconf.c).
The installed Apple SSH behavior is also exercised by local synthetic integration tests.

# Security model

SSH-Wakey's job is to hold a password for a few seconds and hand it to
`/usr/bin/ssh` without it touching disk, an argument list, or anything that
outlives the connection attempt. This document says how, and where the limits
are.

## What is stored

Connection metadata, and nothing else:

```
~/Library/Application Support/SSH-Wakey/connections.json
```

Name, username, host, port, extra `ssh` arguments, the host key policy flag, the
dates the entry was added and last edited, and a capped list of what changed on
each edit. The folder is `0700`, the file is `0600`, and permissions are
reapplied after each atomic write. There is no password field, no key material,
no passphrase, and no token of any kind in that file or anywhere else on disk.

Two things about the change history are worth saying plainly. It keeps previous
values, so an old hostname or username stays in the file after you change it;
delete the connection to be rid of them. And the per-row eye only reveals one
connection's details on screen at a time. It is there for screen sharing and
shoulder surfing, it does not encrypt or obscure anything on disk, the file still
contains the real values, and the password sheet deliberately ignores it so you
can always see where a password is about to go. Error text quoted from ssh can
still name a host, so it is a convenience, not a redaction guarantee.

## How the password moves

1. You type it into a `SecureField`.
2. It is copied immediately into a `SecureBuffer`: raw heap memory the app
   allocated and can overwrite. The SwiftUI binding is cleared in the same turn.
3. The app opens a `AF_UNIX` stream socket inside a freshly created `0700`
   directory under `$TMPDIR`, and generates a 256-bit random nonce from
   `SecRandomCopyBytes`.
4. It launches `ssh` with a deliberately small environment containing
   `SSH_ASKPASS` (pointing at SSH-Wakey's own executable),
   `SSH_ASKPASS_REQUIRE=force`, the socket path, and the nonce.
5. When `ssh` needs the password it executes `SSH_ASKPASS` with the prompt as an
   argument. That is SSH-Wakey again. Its `main` sees the two environment values,
   takes the askpass path, and never initialises any UI.
6. The helper connects to the socket, sends `nonce\nprompt`, and reads the reply.
   The app checks the peer's uid with `getpeereid`, compares the nonce in
   constant time, and checks that the prompt is a password prompt. Only then does
   it write the password.
7. The helper writes it to standard output, which is the pipe `ssh` is reading,
   and exits.
8. The app wipes the buffer with `memset_s` immediately after serving. When the
   attempt ends, the socket is unlinked and its directory removed.

### When it is destroyed

The password is gone before a session even exists. Nothing holds it once the
login has happened: the open connection is kept alive by ssh itself, and the
Terminal window that attaches to it authenticates against the running master
rather than against the far end, so it never needs a password and never sees one.

In the app, the plaintext lives in one `SecureBuffer`: raw heap memory, pinned
with `mlock` so it can never be written to swap, and overwritten with `memset_s`
when it is done with. It is wiped on four separate paths, so no ordering of
success, failure, cancellation or crash-free teardown leaves it behind:

- the instant it has been handed over, inside the channel;
- when the channel is torn down at the end of the attempt;
- in the `defer` that ends the connection attempt, whatever the outcome;
- in `deinit`, as a backstop.

In the helper, which is a separate short-lived process, the answer is read
straight into a buffer of the same kind and wiped explicitly before `exit`.
Explicitly, because `exit` does not run deferred blocks.

Neither side lets the plaintext near a growing `Array`. That matters more than it
sounds: an array that outgrows its storage copies itself somewhere new and frees
the old block without overwriting it, leaving stale copies of the secret
scattered through the heap that nothing will ever clean up. Both buffers are
sized once, up front.

### Properties this gives

- **No password on disk, ever.** No temporary file is created for it, so there is
  nothing to delete, nothing to leak through a crash, and nothing to recover from
  free space. The spec this was built to allowed a restrictive temporary file as
  a fallback; it was not needed.
- **No password in `argv`.** `ps` shows the full `ssh` command line and none of
  it is secret. Nothing in the app logs an argument list.
- **No password in a persistent environment variable.** Two environment values
  are set, and they are a socket path and a random token, not a credential. They
  exist only in the environment of the one spawned `ssh` process and of the
  askpass child it execs. The app's own environment is untouched.
- **No generated helper script.** `SSH_ASKPASS` points at the app binary itself,
  so there is no script on disk that could be read, edited, or run later.
- **Single use.** The password is served at most once. A second ask is counted
  and refused. When the attempt ends the channel is destroyed, so the helper has
  nothing left to connect to.
- **Prompt filtering.** The channel answers only a prompt containing "password",
  and explicitly refuses anything mentioning a fingerprint, `yes/no`, or a
  passphrase. It cannot be induced to answer a host key confirmation with your
  password, or to spend it on decrypting a local private key.
- **Caller checks.** The directory is `0700`, the socket is `0600`, the peer must
  have the same uid, and it must present the nonce.

### One password, one attempt

`NumberOfPasswordPrompts=1` limits `ssh` to a single prompt *per authentication
method*, so a rejected password produces a second ask under the next method.
SSH-Wakey does not answer it. The failure message says that it happened, and you
decide whether to try again. Nothing is retried automatically.

## Encrypting the file, and what that is worth

Off by default, switched on in Settings. What it protects against is narrower
than it sounds, and saying so plainly is more useful than overselling it.

**Already true without it.** The file is `0600` in a `0700` folder, so no other
account can read it. FileVault encrypts it whenever the Mac is off or locked. It
contains no passwords, no keys and no passphrases: names, usernames, addresses,
ports, dates and an edit history.

**What encrypting it adds.** Three narrower gaps close: a program running as you
reading the file directly, a backup destination that is not itself encrypted,
and the file being copied somewhere by accident. That is a real improvement, and
it is not the same as making the data secret from a compromised machine.

**What it costs.** The file stops being readable and hand-editable, and there is
now a key that can be lost. Both are answered below.

### The design

A random 256-bit data key seals the connection list with AES-GCM. The data key is
then wrapped twice, producing two independent ways in:

- **The Keychain slot.** A random key in the login keychain, read silently every
  time the app opens the file.
- **The passphrase slot.** A key derived from your recovery passphrase with
  PBKDF2-HMAC-SHA256 at 600,000 rounds, over a random 16-byte salt.

Either slot yields the data key, so losing one does not lose the data. Because
the passphrase decrypts a key rather than the file, changing it rewraps a few
dozen bytes instead of re-encrypting everything, and the old passphrase stops
working immediately.

Recovering with the passphrase also stores a fresh Keychain key, so a recovery is
a one-time event rather than a permanent downgrade to typing a passphrase.

### The limits of it

- **Changing the passphrase, and turning encryption off, both ask for it.** The
  app already holds the data key and could do either without asking. It asks
  anyway. Changing the passphrase would otherwise let someone set one of their
  own and read the file at leisure later, turning a brief lapse into lasting
  access. Turning encryption off would let them quietly downgrade the file to
  plain text and leave it that way.
- **Export asks too.** Every route to a lasting plain-text copy now needs the
  same proof. It is worth being honest that this is a weaker gate than the other
  two: the same information is already on screen, so it raises the effort rather
  than closing a hole.
- **The passphrase cannot be written into the Passwords app for you.** That app
  is built on the data protection keychain, and adding anything to it, or
  marking any keychain item as synchronisable, returns `errSecMissingEntitlement`
  for a build signed ad-hoc. Writing it to the ordinary login keychain would
  work, and would be the wrong thing to do anyway: that is the same keychain
  holding the key the passphrase exists to back up, so it would put the spare
  key inside the locked room. The sheet generates one, shows it, copies it and
  opens the Passwords app instead, and you paste it in yourself.
- **There is a corner this creates.** If the passphrase is forgotten while the
  Keychain key still works, the file opens normally but cannot be exported,
  turned off, or re-keyed, because all three need the passphrase. The way out is
  to read the connections off the screen and enter them again. Export once, as
  soon as encryption is turned on, and the corner never comes up.
- **A passphrase you cannot produce is a file you cannot open.** There is no
  back door and no reset. Export before you need it, and keep the passphrase in a
  password manager.
- **It is only unlocked while the app has the key.** Anything running as you
  while the app is open can read the connection list out of the app, and on
  macOS 15 and earlier, so can anything that can read the Keychain item.
- **The Keychain item is tied to the app's signature.** An ad-hoc signed build
  gets a new signature every time it is rebuilt, so macOS asks you to allow
  access again after each rebuild, and "Always Allow" only holds until the next
  one. That is expected while you are changing the code, and stops once you
  settle on a build. A Developer ID signature would make it a single prompt.
- **An export is plain text.** It is written `0600`, and after that it is an
  ordinary file with ordinary risks.

## Hardening the app itself

Protecting the password in memory is pointless if anything on the machine can
read that memory, so the Release build is configured to prevent it.

- **Hardened Runtime is on**, which blocks `DYLD_INSERT_LIBRARIES` injection and
  unsigned code being loaded into the process, and restricts `task_for_pid`
  against it.
- **`com.apple.security.get-task-allow` is not present.** Xcode injects that
  entitlement by default when signing locally, and it lets any process running
  as you attach a debugger and read the app's memory, password included.
  `CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO` stops the injection for Release.
- **The Debug build keeps both**, because Xcode cannot attach a debugger
  otherwise. That is the right trade for development and the wrong one for daily
  use: run the Release build.

Verify a build with:

```bash
codesign -dv --entitlements - /path/to/SSH-Wakey.app
```

`flags=0x10002(adhoc,runtime)` means the Hardened Runtime is on, and
`get-task-allow` should not appear at all.

### While the password is on screen and in memory

- **The pages holding it are pinned** with `mlock`, so the plaintext is never
  written out to swap. macOS encrypts swap, but not putting it there is better
  than relying on that.
- **A peer that vanishes cannot kill the app.** Writing into a socket or pipe
  nobody is reading raises SIGPIPE, whose default disposition is to terminate the
  process. Both sides of the password channel set `SO_NOSIGPIPE`, and the askpass
  helper ignores the signal, so an ssh process that gives up early produces a
  clean "no password available" rather than a killed process.
- **The password sheet is no longer excluded from screen capture.** It was, via
  `sharingType = .none`, and that had to be removed: the sheet stopped drawing
  on screen entirely a moment after it appeared, leaving the window in its modal
  state with nothing on it. The protection was worth little anyway, because the
  field is masked and there is nothing in the sheet a recording could reveal
  beyond the destination.
- **Secure event input is held** for as long as the sheet is open, which stops
  other processes reading the keystrokes through an event tap. It is given up
  the moment the sheet closes or the app stops being frontmost, because it is a
  system-wide setting that interferes with text input everywhere else.

### Who is allowed to ask for the password

The socket path and the nonce travel in the environment of the `ssh` process,
and on macOS anything running as your account can read the environment of
another of your own processes. So the nonce alone is not proof of identity.

Before answering, the channel checks the peer's process id with `LOCAL_PEERPID`,
resolves its executable with `proc_pidpath`, and requires it to be the same
binary the app named in `SSH_ASKPASS`. Paths are compared with symlinks
resolved. A program that scraped the token out of `ssh`'s environment is refused
and the refusal is reported in the failure message.

This check fails open in one case: if the peer's process cannot be identified at
all, the uid check and the nonce still stand and the request is allowed. That is
deliberate, so an unexpected platform change degrades to the previous behaviour
rather than making the app unusable.

## Known limitations

Stated plainly, because a security document that only lists strengths is not
useful.

- **Swift `String` cannot be wiped.** The password exists briefly as a `String`
  between the text field and the `SecureBuffer`. Its storage is immutable,
  reference counted, and may have been copied by AppKit before the app ever sees
  it. Those copies are freed but not overwritten. The `SecureBuffer` shortens the
  window and guarantees the app's own copy is zeroed; it cannot undo what the
  framework already did.
- **Memory is not locked.** There is no `mlock`, so in principle the page could
  be written to swap. macOS encrypts swap by default, which mitigates but does
  not eliminate this.
- **Local root still sees everything.** The Hardened Runtime raises the bar for
  a process running as *you*, but root can still read memory, and root can read
  the socket. Nothing here defends against a fully compromised machine.
- **A crash could capture it.** If the app crashes while the password is in
  memory, a crash report may contain it. Keeping the plaintext alive for seconds
  rather than minutes is the mitigation; there is no way to rule it out.
- **Trust on first use is still trust on first use.** With strict checking on,
  an unknown host is refused and the app offers to show you the fingerprint it
  fetched with `ssh-keyscan`. Fetching a fingerprint over the network proves
  nothing by itself: whatever answers that address supplies it. Compare it with
  the value printed on the machine (`ssh-keygen -lf
  /etc/ssh/ssh_host_ed25519_key.pub`) before approving. The sheet says this.
- **A changed host key is never handled for you.** SSH-Wakey refuses it loudly
  and will not edit `known_hosts`. That is deliberate.
- **Reaching a locked Mac depends on the target's macOS.** On macOS 26 (Tahoe)
  and later, SSH password authentication works while the data volume is still
  locked, so this app can unlock a Mac at the FileVault screen given Remote Login
  and a wired network. On macOS 15 and earlier it cannot, because nothing is
  listening. The README has the requirements and the caveats.
- **Local network access is a macOS permission.** SSH-Wakey needs it to reach a
  private address, and a missing permission looks exactly like an unreachable
  machine. The app names that possibility rather than leaving you guessing.
- **The app is ad-hoc signed and unsandboxed.** It needs to execute
  `/usr/bin/ssh`, read `~/.ssh`, and write outside a sandbox container. Build it
  yourself, or sign and notarise it with your own identity before moving it to
  another Mac.
- **Sessions die with the app.** The master `ssh` process is a child of
  SSH-Wakey. Quitting closes every session, including attached Terminal windows.
  The app warns before doing so.

## Command execution

No shell is ever used to reach `ssh`. `Process.arguments` is an array, built by
`SSHCommandBuilder` with no string interpolation of user values into a command
line. The extra-arguments field is tokenised by the app itself, which handles
quotes and backslashes but expands nothing, so shell metacharacters are inert.

Options that would give `ssh` a way to execute another program locally, or to
read its trust data from somewhere else, are rejected before the command is
built: `ProxyCommand`, `LocalCommand`, `PermitLocalCommand`, `KnownHostsCommand`,
`PKCS11Provider`, `SecurityKeyProvider`, `Include`, `Match`,
`UserKnownHostsFile`, `GlobalKnownHostsFile`, `XAuthLocation`. Flags the app sets
itself are rejected too, so they cannot be overridden.

### The one exception

Handing a session to Terminal needs a file Terminal can open, and that file is a
shell script. It is written `0700` into the session's private directory, every
value in it is single-quoted, and it begins by deleting itself. It contains the
`ssh` command that attaches to the already-authenticated control socket, and no
credential of any kind. No keystrokes are simulated and no application is
scripted.

## Reporting

This is a personal utility with no release process. If you find a problem in the
password path, the relevant code is `SSH/AskpassChannel.swift`,
`SSH/AskpassHelper.swift` and `SSH/SecureBuffer.swift`, and the tests that pin
its behaviour are in `SSH-WakeyTests/PasswordChannelTests.swift`.

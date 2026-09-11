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
dates the entry was added and last edited, whether its row is hidden in the
list, and a capped list of what changed on each edit. The folder is `0700`, the file is `0600`, and permissions are
reapplied after each atomic write. There is no password field, no key material,
no passphrase, and no token of any kind in that file or anywhere else on disk.

Two things about the change history are worth saying plainly. It keeps previous
values, so an old hostname or username stays in the file after you change it;
delete the connection to be rid of them. And the per-row eye button only
hides that connection's details on screen. It is there for screen sharing and
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
- **Local root sees everything.** Anything running as root, or as you with a
  debugger, can read the app's memory or the socket. Nothing here defends against
  a compromised local account; that is not a threat this design can address.
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

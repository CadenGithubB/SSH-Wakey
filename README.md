# SSH-Wakey

A small native macOS app that keeps a list of SSH destinations and opens a shell
on one of them, so you do not have to remember usernames, addresses and ports
when you need to get back into a machine.

It is a launcher, not a terminal. It authenticates once, holds the connection
open, and hands the session to Terminal.

- Swift and SwiftUI, macOS 14 or later
- No third-party dependencies at all
- No password storage, no key storage, no sync, no telemetry, no discovery

---

## Build and run

Requirements: macOS 14+, Xcode 16 or later. Nothing to install, nothing to fetch.

In Xcode:

```bash
open SSH-Wakey.xcodeproj
```

Then press ⌘R to run, or ⌘U to run the tests.

From the command line:

```bash
xcodebuild -project SSH-Wakey.xcodeproj -scheme SSH-Wakey -configuration Release build
```

```bash
xcodebuild -project SSH-Wakey.xcodeproj -scheme SSH-Wakey -destination 'platform=macOS' test
```

**Run the Release build.** It has the Hardened Runtime on and no
`get-task-allow` entitlement, so another process running as you cannot attach a
debugger and read the password out of memory. The Debug build deliberately keeps
both, because Xcode cannot attach a debugger otherwise. SECURITY.md explains the
difference and how to check a build.

The build is ad-hoc signed (`CODE_SIGN_IDENTITY = "-"`), which is enough to run
it on the Mac that built it. The App Sandbox is deliberately off: the app runs
`/usr/bin/ssh`, reads `~/.ssh/known_hosts`, and writes to Application Support
outside a sandbox container. To distribute it to another Mac you would need your
own signing identity and notarisation.

---

## Using it

1. **Add** a connection: display name, username, host or IP, port, and any extra
   `ssh` options. Nothing is flagged as wrong until you press Save.
2. Select it and press **Connect**, or double-click the row.
3. Type the password in the sheet that appears.
4. When it says Connected, press **Open in Terminal** for a shell.

Double-clicking a row that is already connected opens another Terminal window on
the same session.

**Disconnect** closes the session. So does quitting the app, which is why it asks
first when sessions are open.

The list shows when each connection was added and last edited. Open **Edit** to
see the full change history for one: what changed, and when.

Each row has its own **eye** button, beside the status dot on the left. It hides
that connection's username, address, extra arguments and dates behind bullets,
for screen sharing or a busy office. It is per connection, it sticks, and it is a
display setting only: nothing about what is saved changes. Right-clicking a row
offers the same thing. The password sheet always shows the real destination,
because confirming where a password is about to go is the point of that sheet.

**Port** and **Extra arguments** are optional columns. Switch them off from the
sliders button in the top-left corner of the table header, above the status dot,
or by right-clicking the table header. Name, Username, Host, Added and Last edited always show, because a row
that cannot tell you which machine it is or who it logs in as is not worth
showing.

Which columns show, and in what order, is remembered between launches. Their
widths deliberately are not. SwiftUI writes the width it has just worked out back
into the saved layout, so storing that verbatim pins every column at whatever the
window happened to be that day; reopened in a smaller window, those widths no
longer fit and the table scrolls sideways instead of shrinking. Widths are
stripped before saving, and the window cannot be made narrower than every column
at its ideal width, so the default layout never scrolls sideways.

The **?** button opens **What SSH-Wakey does**: what it saves, how connecting and
the password work, what reaching a Mac at the FileVault screen needs, and what
the different failures mean.

The **i** button beside the extra arguments field lists the `ssh` options worth
knowing, with a line each on what they do, and says what SSH-Wakey refuses.

### How the connection actually works

Connect starts one `ssh -M -N` process. `-N` means it runs no remote command; it
exists only to hold an authenticated connection open, with a control socket in a
private folder under your temporary directory.

Open in Terminal then starts an ordinary `ssh` client that attaches to that
control socket. Because the master is already authenticated, the new client asks
for nothing. No keystrokes are simulated, no application is scripted, and the
password is never anywhere near Terminal.

The trade-off is that the session belongs to SSH-Wakey. Quit the app and the
master goes away, taking attached Terminal windows with it.

---

## Saved connections

Metadata only, in:

```
~/Library/Application Support/SSH-Wakey/connections.json
```

Pretty-printed JSON written through `Codable`:

```json
{
  "version" : 1,
  "connections" : [
    {
      "createdAt" : "2026-09-11T09:14:02Z",
      "extraArguments" : "-o ServerAliveInterval=30",
      "hidesDetails" : false,
      "host" : "192.168.1.24",
      "id" : "7C6C1E5E-...",
      "modifiedAt" : "2026-09-12T18:03:41Z",
      "name" : "Studio Mac",
      "port" : 22,
      "revisions" : [
        {
          "date" : "2026-09-12T18:03:41Z",
          "id" : "1F2A...",
          "summary" : "Host: 192.168.1.9 → 192.168.1.24, Port: 22 → 2222"
        }
      ],
      "strictHostKeyChecking" : true,
      "username" : "admin"
    }
  ]
}
```

Timestamps are ISO-8601 and kept to the second, so what is written is exactly
what is read back. `revisions` records what changed and when, capped at the 20
most recent so the file cannot grow without bound. A connection saved by an
earlier build has no dates, and the app shows a dash rather than inventing one.

The folder is created `0700` and the file is written `0600`, so only your account
can read it. Writes are atomic, and permissions are reapplied after every save
because an atomic write replaces the file.

There is no password field, and there never will be. You can edit the file by
hand while the app is closed; anything invalid is caught by the same validation
the editor uses. A file written by an older build still loads, and a file from a
newer format version is refused rather than misread.

### Validation

A connection must have a name, a username and a host, and a port from 1 to
65535. Usernames and hosts may not contain spaces, `@`, `/`, control characters
or a leading dash, since a leading dash would be read by `ssh` as an option.

Extra arguments are split by the app, honouring quotes and backslashes, and are
passed to `Process` as an array. No shell is involved, so `;`, `|`, `$(...)` and
friends are just characters. Options are then checked:

- Refused as dangerous: anything that can make `ssh` run another program or
  redirect its trust decisions, including `ProxyCommand`, `LocalCommand`,
  `PermitLocalCommand`, `KnownHostsCommand`, `PKCS11Provider`, `Match`,
  `Include` and `UserKnownHostsFile`.
- Refused as reserved: options the app sets itself, such as `-p`, `-l`, `-M`,
  `-S`, `StrictHostKeyChecking` and `ControlPath`.
- Refused as unrecognised: any flag that is not a real `ssh` option, and any
  bare operand, since the destination comes from the fields.

---

## How passwords are handled

Short version: typed once, held in memory for seconds, never written anywhere,
never passed as an argument, never reused.

The app sets `SSH_ASKPASS` to **its own executable** and `SSH_ASKPASS_REQUIRE` to
`force`. When `ssh` needs the password it runs that program, which is SSH-Wakey
again, in a mode selected purely by two environment variables that exist only in
the environment of that one `ssh` process. The helper connects back to the app
over a UNIX socket in a `0700` folder, presents a 256-bit one-time token, and
receives the password on standard output. Then it exits.

What that avoids:

- **No temporary password file.** None is created, so there is nothing to delete
  and nothing to recover.
- **No password in any command line.** `ps` shows the `ssh` arguments and none of
  them is a secret.
- **No password in a persistent environment variable.** The socket path and the
  token are environment values; the password is not.
- **No reuse.** The password is served at most once per attempt. The socket is
  unlinked and its folder removed when the attempt ends, so the helper has
  nothing to connect to afterwards.
- **No answering the wrong question.** The helper only replies to a prompt that
  looks like a password prompt, so it cannot be talked into answering a host key
  confirmation or a key passphrase.

The password is copied out of the text field into a buffer the app can overwrite,
and that buffer is zeroed as soon as it has been served. `SECURITY.md` covers the
model, and its limits, properly.

### One password, one attempt

When the first authentication method rejects the password, `ssh` asks again for
the next method. Answering would be a silent retry, so SSH-Wakey does not; it
reports that it happened and you press Connect again. A wrong password therefore
costs one failed attempt per method offered, not a loop.

---

## SSH authentication limitations

- **Interactive password and keyboard-interactive only.** If a server offers a
  key you already have, `ssh` uses it and the typed password is never sent; the
  app says so.
- **No two-factor or multi-prompt login.** A challenge such as `Verification
  code:` is not a password prompt, so it goes unanswered and the attempt fails
  with an explanation.
- **Keys and passphrases are never handled.** SSH-Wakey does not create, read,
  unlock or store private keys. Use `ssh-agent` if you want key auth.
- **Host keys are your own.** The app uses your `~/.ssh/known_hosts`. With
  strict checking on, an unknown host is refused and the app offers to show you
  the fingerprint before adding it. A host key that has *changed* is always
  refused, and the app will not edit that entry for you.
- **One session per saved connection** at a time.

---

## FileVault and the startup screen

A Mac with FileVault turned on does not finish starting up by itself after a
restart. It stops at a login screen while its disk is still encrypted. That
screen looks ordinary, but almost nothing is running behind it, including the
part of macOS that answers SSH.

Whether you can reach a Mac sitting there depends on which version of macOS is
on **that** Mac. The version running SSH-Wakey makes no difference.

### macOS 26 (Tahoe) or newer on the target: you can get in

Apple added a way to unlock the disk over SSH. You connect the way you normally
would and enter the password for an account on that Mac. That password unlocks
the disk and lets it carry on starting up. There is nothing special to switch on
in SSH-Wakey.

The connection drops a second or two after it succeeds. That is not a failure:
the Mac closes it while it finishes starting. SSH-Wakey recognises a session that
ends within 30 seconds and says so, rather than reporting it as an error. Wait
about half a minute and connect again for a normal session.

### macOS 15 (Sequoia) or older on the target: you cannot

No SSH server is running at that screen, so there is nothing to connect to. No
SSH client can do it. Someone has to unlock that Mac at its own keyboard, and SSH
works normally from then on.

### What to set up first

All of this has to be arranged while you can still reach the Mac. None of it can
be done once it is already sitting at the FileVault screen waiting.

- **Turn on Remote Login, in advance.** On the Mac you want to reach: System
  Settings ▸ General ▸ Sharing ▸ Remote Login. This is what lets anything connect
  over SSH at all.
- **Plug it into Ethernet.** Wi-Fi does not start until after the disk is
  unlocked, so a Mac on Wi-Fi alone is not on the network at that screen. A cable
  is the difference between reaching it and not.
- **Know which account to use.** The password has to belong to a user who is
  allowed to unlock FileVault on that Mac.
- **Try it once on purpose.** Restart that Mac deliberately and unlock it over
  SSH while you are still next to it. Finding the gap then beats finding it
  during a real problem.

### If unlocking over SSH is not an option

These work on any version of macOS.

- **Restart in a way that skips the lock screen.** Before a planned restart, run
  `sudo fdesetup authrestart` on that Mac instead of restarting normally. It
  saves a one-time unlock key, so the Mac starts straight past the FileVault
  screen and comes back on the network by itself.
- **Have someone unlock it.** Anyone at the keyboard can type the password.
- **Use hardware that can see the screen.** A KVM, a remote management card or a
  device management tool reaches the startup screen directly. An SSH client
  cannot.

All of this is in the app as well, under **What SSH-Wakey does**, behind the **?**
button and the link that appears when a connection fails.

Sources for the Tahoe behaviour: [Jeff Geerling on managing FileVault Macs
remotely in Tahoe](https://www.jeffgeerling.com/blog/2025/you-can-finally-manage-macs-filevault-remotely-tahoe/)
and [Michael Tsai's summary of the Apple
documentation](https://mjtsai.com/blog/2025/09/22/tahoe-filevault-icloud-keychain-and-ssh/).

---

## Local network permission

macOS asks each app for permission before it can reach devices on your local
network, and that permission covers `ssh` too, because SSH-Wakey launches it.

If the prompt was dismissed or denied, every connection to a private address
fails as unreachable or times out, exactly as though the machine were switched
off. When a connection to a local address fails that way, SSH-Wakey says so and
offers a button straight to System Settings ▸ Privacy & Security ▸ Local
Network. If you have just granted it, connect again.

Addresses treated as local: `10.x`, `172.16–31.x`, `192.168.x`, `169.254.x`,
`127.x`, IPv6 loopback, link-local and unique-local, any `.local` name, and any
bare name with no dots.

---

## External dependencies

None. No packages, no frameworks beyond SwiftUI, AppKit and Foundation, and no
network access except the SSH connections you ask for.

The app runs these system binaries: `/usr/bin/ssh`, `/usr/bin/ssh-keyscan` and
`/usr/bin/ssh-keygen` for host key fingerprints, and `/usr/bin/open` to hand a
session to Terminal.

---

## Project layout

```
SSH-Wakey/
  main.swift               Entry point; askpass mode is decided here, before any UI
  SSHWakeyApp.swift        Scene and app delegate
  Models/
    SSHConnection.swift        Saved metadata, Codable
    ConnectionFileStore.swift  Atomic JSON load and save with tight permissions
    ConnectionStore.swift      Observable list the window binds to
    ConnectionValidator.swift  Field rules
    SSHArgumentParser.swift    Quote-aware tokeniser plus the option allow list
  SSH/
    AskpassProtocol.swift   Contract between the app and its own askpass mode
    AskpassChannel.swift    One-shot local password channel (app side)
    AskpassHelper.swift     The askpass client half
    SecureBuffer.swift      Wipeable heap buffer for the password
    SSHCommandBuilder.swift Argument arrays; no string interpolation anywhere
    SSHSessionManager.swift Runs the master, tracks state, owns live sessions
    SSHFailure.swift        Turns ssh's stderr into something worth reading
    HostKeyService.swift    Fingerprints and known_hosts
    TerminalHandoff.swift   Attaches Terminal to an authenticated session
    NetworkScope.swift      Tells a local address from a routable one
    ProcessRunner.swift     Small async wrapper around Process
  Views/                    SwiftUI window, editor, password prompt, host key sheet
SSH-WakeyTests/             136 tests
```

## Tests

136 unit tests covering persistence and its file permissions, timestamps, change
history, the per-row privacy toggle, which columns may be hidden and
how the table layout is saved, field and argument validation, command construction, failure
classification against real OpenSSH diagnostics, local address detection, the
password buffer, the Terminal handoff script, and the password channel itself. The channel tests run the real client code against the real
server code in process, including the cases where it must refuse: a bad token, a
prompt that is not a password prompt, and a second ask after the password has
already been served.

```bash
xcodebuild -project SSH-Wakey.xcodeproj -scheme SSH-Wakey -destination 'platform=macOS' test
```

# SSH-Wakey Managed for Jamf

This is the IT copy of SSH-Wakey. The public Standard app (`com.CadenGithubB.sshwakey`) never reads these keys. A work VPN or Mail profile on a personal Mac cannot take over someone’s home copy.

## What you install

1. The **SSH-Wakey Managed** app (`com.CadenGithubB.sshwakey.managed`), not the Standard app.
2. A configuration profile in **Computers → Configuration Profiles → Application & Custom Settings** whose preference domain is exactly:

```
com.CadenGithubB.sshwakey.managed
```

Upload [SSH-Wakey.json](SSH-Wakey.json) as the custom schema so Jamf draws the form.

Build the Managed app from this repo:

```
xcodebuild -project SSH-Wakey.xcodeproj -scheme "SSH-Wakey Managed" -configuration ManagedRelease -derivedDataPath build build
```

The product is `SSH-Wakey Managed.app`. Package that for a Jamf policy, or take
`SSH-Wakey-Managed.dmg` from a GitHub release (`./Scripts/make-dmg-managed.sh`
builds it). A policy install as root usually avoids Gatekeeper. Self Service
downloads of an ad-hoc signed app still get a quarantine warning; Developer ID
and notarisation are a later step, not part of this payload.

## What the employee can do

Wake only: log in, then disconnect. They cannot add, edit, remove or export machines, and they cannot open a session or Terminal through this app. They still type the office Mac password each time. Nothing in the profile is a password.

Until `Connections` is forced, the window says the organization has not assigned any machines. That is on purpose.

## Keys

All of these count only when the profile **forces** them. A local `defaults write` is ignored.

| Key | Type | Purpose |
|---|---|---|
| `OrganizationName` | string | Settings: “This copy is managed by ….” |
| `AllowDiagnostics` | boolean | Default true. Forced `false` hides Save Diagnostics and Activity. |
| `Connections` | array of dicts | The live list. `Username` and `Host` required; `Name` optional; `Port` optional (22). |

There are no extra `ssh` arguments in this payload on purpose. Do not add a password field.

Example:

```xml
<key>OrganizationName</key>
<string>Example Corp</string>
<key>AllowDiagnostics</key>
<true/>
<key>Connections</key>
<array>
  <dict>
    <key>Name</key>
    <string>Office Mac</string>
    <key>Username</key>
    <string>jsmith</string>
    <key>Host</key>
    <string>jsmith-mac.office.example</string>
  </dict>
</array>
```

Jamf can fill username or host per person with inventory variables or an extension attribute. The app only cares that the keys are forced.

## Local Network

SSH-Wakey cannot grant this, and neither can Jamf. On macOS 15 and later, Local Network is a user privacy switch. Apple’s own guidance is that device managers cannot set it with MDM or a configuration profile. A PPPC payload does not include this service; putting the Managed app in a Privacy Preferences Policy Control profile will not flip the toggle.

What actually happens:

1. The first Wake (or SSH) to a LAN address makes macOS ask the employee.
2. Allow is remembered for that signed binary. Deny looks like the office Mac is off.
3. Ad-hoc builds change identity on every rebuild, so the prompt can come back. A Developer ID–signed Managed app is what IT should ship if they want one Allow to stick.

The only Apple-documented way to skip the prompt is not per-app. From macOS 15.5, a *separate* preference domain `com.apple.network.local-network` can list office CIDRs (`AllowedEthernetLocalNetworkAddresses`, `AllowedWiFiLocalNetworkAddresses`). Those subnets then stop counting as “local,” so **every** program on the Mac can reach them without Local Network permission. That is a site-wide hole, not a grant for SSH-Wakey, it needs a restart, and it does not belong in this app’s payload.

Do not turn SSH-Wakey into a root `launchd` daemon to dodge the prompt. Daemons running as root are exempt; that would also be a different, more privileged product.

## Standard vs Managed on one Mac

They can both be installed. They use different bundle identifiers and different Application Support folders. A profile for the Managed id does not apply to Standard.

## Checking the payload without Jamf

Jamf is not required to prove the OS side. A root-owned plist at the path below is the same file a configuration profile writes:

```
/Library/Managed Preferences/com.CadenGithubB.sshwakey.managed.plist
```

[example-managed.plist](example-managed.plist) is a sample (documentation IPs only). After copying it into place, bounce `cfprefsd` and open the **Managed** app. `defaults write` is not a substitute: those keys are not forced, so the app ignores them.

To remove the sample:

```
sudo rm "/Library/Managed Preferences/com.CadenGithubB.sshwakey.managed.plist"
killall cfprefsd
```

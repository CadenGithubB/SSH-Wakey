# Changelog

## 1.3.0 (build 5) — 2026-09-20

### Added

- Optional App Lock for the standard encrypted connection vault. Unlock with
  Touch ID, the Mac login password, or the independent recovery passphrase.
  Five minutes without input in SSH-Wakey locks the vault and disconnects SSH;
  screen lock, sleep, user switching, and Lock Now do so immediately.
- A separately signed, sandboxed password-entry service. The main app and
  askpass adapter exchange authorization metadata and file descriptors only;
  the service writes the password directly to SSH and exits after one attempt.
- Release packaging checks for all three signed components, Hardened Runtime,
  and the password service's exact sandbox entitlement set.

### Hardened

- SSH options now use a strict allowlist. Connections ignore external SSH
  configuration and global host-key files, use app-managed host trust, and
  refuse unsafe host-key paths, permissions, symlinks, and repeated prompts.
- Vault parsing validates cryptographic metadata and preserves independent
  recovery. Security changes rotate the data key and reject stale file writes.
- Empty, corrupt, unreadable, or newer-format connection files stay unavailable;
  add, edit, export, and encryption actions cannot overwrite them as empty data.
- Managed profiles reject unsafe destinations. Diagnostics omit raw server text
  that could reflect a password; Terminal handoff cannot silently reconnect.
- Controlled secret buffers use locked memory and explicit erasure. Native
  password entry is confined to the short-lived service; framework, Swift,
  OpenSSH, and kernel copies cannot all be guaranteed physically erased.

### Upgrade and validation notes

- Vault format 1 remains readable. Once a vault is written as format 2, older
  versions refuse it. Keep a secure backup and verify the recovery passphrase
  before enabling App Lock; old backups retain their old credentials.
- Previously accepted SSH options may now be rejected. Hosts trusted only by
  system or user SSH configuration require independent verification in the app.
- Both standard and managed suites contain 388 tests. Validation includes
  sandbox-denial probes, synthetic native password submission/cancellation,
  and arm64/x86_64 release builds with signature and entitlement checks.
- Local artifacts remain ad-hoc signed. Developer ID signing, notarisation,
  and runtime testing across supported macOS versions and hardware configurations
  remain prerequisites for a broadly validated distribution release.

See [SECURITY.md](SECURITY.md) and the dated reports in [docs/](docs/) for the
security boundaries, validation evidence, and remaining limitations.

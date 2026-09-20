# SSH-Wakey working agreements

## Commit privacy

- Keep commits free of personal information and information about the developer's
  workstation. Do not commit local account names, hostnames, personal paths,
  device identifiers, actual network addresses, or machine-specific OS/toolchain
  versions and build numbers.
- Do not commit raw build/test logs, crash reports, diagnostics exports, test
  result bundles, credentials, private keys, saved connections, or local app data.
- Record validation as concise outcomes without workstation details or raw output.
  Product compatibility requirements and build targets may remain documented.
- Use clearly synthetic test fixtures. Never copy fixtures from real connection
  data, host-trust files, logs, or credentials.
- Review the staged diff, newly added files, and Git author/committer metadata
  before every commit and push. Ignore rules do not protect already tracked files.
- Preserve the project's established public GitHub/no-reply commit identity;
  never let Git substitute a local OS account or machine hostname.

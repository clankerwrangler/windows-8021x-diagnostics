# Windows 802.1X endpoint diagnostics

Collect Windows wired and wireless 802.1X evidence and report client-side findings.

Runs in Windows PowerShell 5.1. No extra packages. Collection does not change network configuration or attempt authentication.

## Usage

Run from the script folder in Windows PowerShell 5.1. Elevate the affected account where possible. Running as a different administrator inspects that administrator's CurrentUser certificate store, not the affected user's. Non-elevated collection can return partial results.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Get-8021xDiagnostics.ps1
```

Or run `Get-8021xDiagnostics.cmd`.

If Windows blocked the download: `Unblock-File .\Get-8021xDiagnostics.ps1`

Each live run saves a new folder under `Desktop\Dot1x-Report`. Use `-OutputDirectory` for another destination, `-InterfaceAlias` for one adapter, or `-ProfileName` for one profile.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Get-8021xDiagnostics.ps1 -InterfaceAlias 'Ethernet'
```

Live collection includes rendered event messages by default. `-OmitEventMessages` omits those messages, not other identifying metadata.

```powershell
Get-Help .\Get-8021xDiagnostics.ps1 -Full
```

## Reports

- **`report.txt`**: relevant configuration, concise findings and next checks, grouped history, and missing evidence. Start here.
- **`report.json`**: structured findings and collection status.
- **`evidence.json`**: collected metadata used by the rules.

Console output and `report.txt` are compact by default. Add `-Detailed` for all finding details and collector diagnostics. `report.json`, `evidence.json`, and `-PassThru` keep the complete structured data. See [report output](docs/report-output.md).

Reports can contain profile and server names, certificate identifiers, addresses, event messages, and user-identifying paths. Review the whole bundle before sharing.

See [implemented coverage](docs/coverage.md), the [troubleshooting guide](docs/troubleshooting.md), and [recorded test results](tests/test-results.md).

## License

[MIT License](LICENSE).

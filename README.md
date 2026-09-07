# Windows 802.1X endpoint diagnostics

Collect Windows wired and wireless 802.1X evidence and report client-side findings.

Runs in Windows PowerShell 5.1. No extra packages.

## Usage

From the script folder, as administrator on the affected account:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Get-8021xDiagnostics.ps1
```

Or run `Get-8021xDiagnostics.cmd`.

If Windows blocked the download: `Unblock-File .\Get-8021xDiagnostics.ps1`

Reports go to `Desktop\Dot1x-Report`. Optional: `-OutputDirectory`, `-InterfaceAlias`, `-OmitEventMessages`.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Get-8021xDiagnostics.ps1 -InterfaceAlias 'Ethernet'
```

```powershell
Get-Help .\Get-8021xDiagnostics.ps1 -Full
```

## Reports

- **`report.txt`**: findings and next steps
- **`report.json`**: the same findings as JSON
- **`evidence.json`**: collected metadata

Reports can include private network details. Review them before sharing.

See [coverage](docs/coverage.md) and [test results](tests/test-results.md).

## License

[MIT License](LICENSE).

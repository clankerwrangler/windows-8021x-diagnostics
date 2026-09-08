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

Each live run saves a new folder under `.\Dot1x-Report` in the current working directory (the directory you run the command from). Use `-OutputDirectory` for another destination, `-InterfaceAlias` for one adapter, or `-ProfileName` for one profile.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Get-8021xDiagnostics.ps1 -InterfaceAlias 'Ethernet'
```

Live collection includes rendered event messages by default. `-OmitEventMessages` omits those messages, not other identifying metadata.

```powershell
Get-Help .\Get-8021xDiagnostics.ps1 -Full
```

## Prepare client logging, then restore

In an elevated Windows PowerShell window, run (the execution policy applies only to this window):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Set-8021xLogging.ps1 -Enable
# Reproduce the wired or Wi-Fi authentication problem now.
.\Get-8021xDiagnostics.ps1
.\Set-8021xLogging.ps1 -Restore
```

The helper enables installed client diagnostic channels and raises smaller logs to 100 MiB. It saves original settings before changes, skips missing channels, and never clears logs. The collector stays read-only.

Optional: use `-Enable -IncludeSchannel` for extra Schannel event logging. This requires a reboot to apply; the helper never reboots or restarts services.

Restore with the same elevated account, even after an error or interrupted run. Recovery state is `%ProgramData%\Dot1xLogging\state.json`; keep it until `-Restore` succeeds. Repeated `-Enable` preserves the first baseline.

If the helper download is blocked: `Unblock-File .\Set-8021xLogging.ps1`. See [logging details and optional client tracing](docs/logging.md) for coverage, cleanup, and recovery.

## Reports

- **`report.txt`**: relevant configuration, concise findings and next checks, grouped history, and missing evidence. Start here.
- **`report.json`**: structured findings and collection status.
- **`evidence.json`**: collected metadata used by the rules.

Console output and `report.txt` are compact by default. Add `-Detailed` for all finding details and collector diagnostics. `report.json`, `evidence.json`, and `-PassThru` keep the complete structured data. See [report output](docs/report-output.md).

Reports can contain profile and server names, certificate identifiers, addresses, event messages, and user-identifying paths. Review the whole bundle before sharing.

See [implemented coverage](docs/coverage.md), the [troubleshooting guide](docs/troubleshooting.md), and [recorded test results](tests/test-results.md).

## License

[MIT License](LICENSE).

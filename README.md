# Windows 802.1X endpoint diagnostics

Troubleshoot wired Ethernet and enterprise Wi-Fi authentication from a Windows endpoint. The script collects link, service, profile, certificate, event-log, and IP/DNS evidence, then produces findings with practical next steps.

It runs in the built-in **Windows PowerShell 5.1** (`powershell.exe`) with **no extra dependencies or installer**. PowerShell 7 is not the target runtime.

## Usage

Run from the script folder in **Windows PowerShell 5.1**. Choose **Run as administrator** for the fullest machine, network, and event-log collection; non-elevated runs can have permission-related partial results. Elevate the affected Windows account where possible: running as another administrator inspects that administrator's `CurrentUser` certificate store, not the affected user's. Choose a writable destination you control.

Windows can block downloaded files. `Unblock-File .\Get-8021xDiagnostics.ps1` removes this script's download mark.

This process launch uses `-ExecutionPolicy Bypass` so the script can run without changing the machine or user execution policy. That is process-scoped. It is not `Set-ExecutionPolicy`.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Get-8021xDiagnostics.ps1
```

Or run `Get-8021xDiagnostics.cmd` from the same folder. A live run saves under `Desktop\Dot1x-Report` (a new folder per run) and includes event messages. Use `-OutputDirectory` to choose another destination, `-InterfaceAlias` to scope one adapter, and `-OmitEventMessages` if identities must stay out of the report.

To inspect one adapter, use its exact interface alias. Replace `Ethernet` with the alias on your endpoint:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Get-8021xDiagnostics.ps1 -InterfaceAlias 'Ethernet'
```

For all options, including profile filters, event-history limits, and structured output, use the built-in help:

```powershell
Get-Help .\Get-8021xDiagnostics.ps1 -Full
```

## Read the reports

- **`report.txt`**: Human-readable findings, supporting evidence, suggested next steps, and collection limitations. Start here.
- **`report.json`**: Structured findings and collection status for further processing.
- **`evidence.json`**: Collected metadata used to generate the findings.

Read each finding with its evidence and limitations. A partial collector means some information was unavailable; a historical failure does not necessarily describe the current connection.

Collection does not change network configuration. Reports can contain private network details, so review them before sharing. Endpoint evidence cannot prove every RADIUS or server-side cause.

See the [troubleshooting and coverage guide](docs/coverage.md) for deeper investigation and the [test results](tests/test-results.md) for verified behavior and remaining test limits.

## License

[MIT License](LICENSE).

# Windows 802.1X endpoint diagnostics

Collect Windows wired and Wi-Fi 802.1X evidence and report client-side findings. Collection does not change network configuration or attempt authentication; a separate, optional helper prepares client logging.

Requires Windows 10/11 and Windows PowerShell 5.1. No extra packages.

## Collect client evidence

To collect existing evidence without changing logging, follow steps 1 and 4 only.

1. **Prepare the PowerShell window.** Open Windows PowerShell 5.1 in the script folder. The logging helper requires elevation. Elevate the affected account where possible: running as a different administrator inspects that administrator's `CurrentUser` certificate store, not the affected user's. Non-elevated collection can return partial results.

   If Windows blocked the downloads, run:

   ```powershell
   Unblock-File .\Get-8021xDiagnostics.ps1, .\Set-8021xLogging.ps1
   ```

   If execution policy blocks the scripts, allow execution for this PowerShell process only, without changing persistent policy:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   ```

2. **Enable logging (optional).** Before reproducing the problem, run:

   ```powershell
   .\Set-8021xLogging.ps1 -Enable
   ```

   The helper saves original settings, enables selected installed client channels, and raises smaller logs to 100 MiB. It never clears logs. See [logging details](docs/logging.md) for coverage, disk usage, and optional Schannel logging (reboot required).

3. **Reproduce the authentication problem.** Note the time, affected adapter, and profile.

4. **Collect the evidence.** Run:

   ```powershell
   .\Get-8021xDiagnostics.ps1
   ```

   Each live run saves a new private folder under `.\Dot1x-Report` in the current working directory. The report shows its path.

   The collector does not read every channel enabled by the helper. Before restoring settings, inspect or export any needed supplemental events in Event Viewer; see [included channels](docs/logging.md#included-channels).

5. **Restore logging if you ran `-Enable`.** Use the same elevated account on the same machine, including after an error or interruption:

   ```powershell
   .\Set-8021xLogging.ps1 -Restore
   ```

   Keep the saved state until restoration succeeds; see [cleanup and recovery](docs/logging.md#cleanup-and-recovery) for errors. Restore does not delete reports.

Alternatively, `.\Get-8021xDiagnostics.cmd` runs only the collector. It does not elevate or enable logging.

## Reports

Open these files in the run folder:

- `report.txt`: Start here for relevant configuration, findings, next checks, grouped history, and missing evidence.
- `report.json`: Structured findings and collection status.
- `evidence.json`: Collected metadata used by the rules.

Historical failures do not establish the current connection state. Collection gaps are not proof of a healthy connection. See [report interpretation](docs/report-output.md) and [implemented coverage](docs/coverage.md).

Reports can contain profile and server names, certificate identifiers, addresses, event messages, and user-identifying paths. Review the whole bundle before sharing. Live collection includes rendered event messages by default; `-OmitEventMessages` omits those messages, not other identifying metadata.

## Collection options

Add collector options as needed:

- `-InterfaceAlias 'Ethernet'` or `-ProfileName 'PROFILE_NAME'`: Select an adapter or profile.
- `-OutputDirectory 'C:\Diagnostics'`: Choose the parent destination for new run folders.
- `-Detailed`: Include all finding details and collector diagnostics in the console and `report.txt`. JSON files retain complete structured data in either mode.
- `-PassThru`: Return structured findings and collection status to the PowerShell pipeline.

Read full help for either script:

```powershell
Get-Help .\Get-8021xDiagnostics.ps1 -Full
Get-Help .\Set-8021xLogging.ps1 -Full
```

See the [troubleshooting guide](docs/troubleshooting.md), [optional client tracing](docs/logging.md#optional-client-tracing), and [recorded test results](tests/test-results.md).

## License

[MIT License](LICENSE).

# Client logging preparation

Follow the [README workflow](../README.md#collect-client-evidence): enable logging, reproduce the issue, collect the report, and restore the original settings. Run the helper in elevated Windows PowerShell 5.1.

`-Enable` prepares the client event channels and starts a direct EapHost peer trace. `-Restore` finalizes the trace and restores the saved event-log settings.

## EapHost trace output

Each capture writes `EapHost.etl` to a private `EapHost-Trace-<GUID>` folder under `Dot1x-Report` in the current working directory. The helper prints the path. Restore uses the saved absolute path, including when you run it from another directory.

The ETL is a 256 MiB circular file, retaining the newest trace data when it reaches the limit. Restore stops and flushes the owned session. Keep the finalized ETL with the neighboring collector report folder. EapHost trace decoding uses ETW support tools and matching PDB/TMF metadata.

For another destination, pass the same `-OutputDirectory` to the helper and collector. To prepare only event channels, use `-Enable -EventsOnly`.

An existing EapHost capture from another session is preserved. If the helper reports a trace conflict, the configured event channels remain available; `-EventsOnly` selects that event-log workflow explicitly.

## Included channels

The helper discovers installed channels and enables this client allowlist:

- The collector's five `Microsoft-Windows-` channels: `WLAN-AutoConfig/Operational`, `Wired-AutoConfig/Operational`, `EapHost/Operational`, `CAPI2/Operational`, and `NTLM/Operational`.
- `Microsoft-Windows-OneX/Operational` and the `Operational` channels for `Microsoft-Windows-EapMethods-RasChap`, `RasTls`, `Sim`, and `Ttls`.
- Installed `Admin` and `Operational` channels under `Microsoft-Windows-Dhcp-Client`, `Microsoft-Windows-Dhcpv6-Client`, `Microsoft-Windows-DNS-Client`, `Microsoft-Windows-NetworkProfile`, `Microsoft-Windows-GroupPolicy`, `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider`, and `Microsoft-Windows-CertificateServicesClient-*`.

Each selected log smaller than 100 MiB gets a 100 MiB maximum. Larger logs retain their current limit. The total allowance can grow by several GiB. Existing event history is retained subject to Windows' size and retention settings.

The collector queries its five channels and selected System events. Supplemental channels are available in Event Viewer; export any events you need before Restore reduces their size limits. `System / EapHost` and `EapHost/Operational` have independent collection statuses. An unsupported provider/channel pairing appears as “Not applicable on this Windows installation.”

## Optional Schannel detail

To include Schannel event logging, start with:

```powershell
.\Set-8021xLogging.ps1 -Enable -IncludeSchannel
```

This saves the original `EventLogging` DWORD, or its absence, under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL` and sets it to `7`. Restore returns the original value or absence. A reboot applies each Schannel change.

If the saved baseline excludes Schannel, run `-Restore` before enabling with `-IncludeSchannel`.

## Cleanup and recovery

Run `-Restore` with the same elevated account on the same machine. Recovery records are stored privately under `%ProgramData%\Dot1xLogging`:

- `state.json` holds the original channel and optional Schannel settings.
- `eaphost-trace.json` identifies the helper's trace session and output path.

An existing channel baseline from an earlier helper version is preserved when the updated helper adds tracing. Repeated Enable reuses an active owned trace and the original channel settings. Completed captures are retained in their own output folders.

Restore attempts both trace cleanup and saved-setting restoration. If a step fails, keep the recovery files and rerun Restore after resolving the reported error. The helper removes recovery records after successful cleanup and retains the report and capture files.

The recovery records are saved before their corresponding changes. A caught initial-save failure cleans up that invocation's new record. A power interruption during the initial write can leave an incomplete record; preserve it until its state has been established.

## Additional client traces

For wired or Wi-Fi packet captures and RAS tracing, follow Microsoft's client data-collection procedure in [Sources](#sources). Choose the commands for the affected adapter.

Check `netsh trace show status` and `netsh trace show scenarios` before starting a capture, and preserve the existing RAS tracing configuration. After reproduction, stop the capture you started with `netsh trace stop` and restore the prior RAS tracing settings. Keep its ETL, any associated CAB, and relevant `%SystemRoot%\Tracing` files with the report bundle.

## Sources

- [Microsoft EapHost tracing](https://learn.microsoft.com/en-us/windows/win32/eaphost/enabling-tracing): peer provider, trace flags, and decoding metadata.
- [Microsoft wevtutil reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil): event-channel configuration and export.
- [Microsoft client 802.1X data collection](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/data-collection-for-troubleshooting-802-1x-authentication-issues): wired/Wi-Fi and RAS capture workflows.
- [Microsoft Schannel event logging](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/enable-schannel-event-logging): verbosity values and reboot requirements.

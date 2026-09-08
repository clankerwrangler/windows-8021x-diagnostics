# Client logging preparation

Use the [README workflow](../README.md#prepare-client-logging-then-restore) before reproducing an authentication failure. `Set-8021xLogging.ps1` runs elevated in Windows PowerShell 5.1. It changes logging settings only; it does not change authentication, TLS, certificate trust, profiles, or services.

## Included channels

`-Enable` discovers installed channels and enables this client allowlist:

- The collector's five `Microsoft-Windows-` channels: `WLAN-AutoConfig/Operational`, `Wired-AutoConfig/Operational`, `EapHost/Operational`, `CAPI2/Operational`, and `NTLM/Operational`.
- `Microsoft-Windows-OneX/Operational` and the `Operational` channels for `Microsoft-Windows-EapMethods-RasChap`, `RasTls`, `Sim`, and `Ttls`.
- Installed `Admin` and `Operational` channels under `Microsoft-Windows-Dhcp-Client`, `Microsoft-Windows-Dhcpv6-Client`, `Microsoft-Windows-DNS-Client`, `Microsoft-Windows-NetworkProfile`, `Microsoft-Windows-GroupPolicy`, `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider`, and `Microsoft-Windows-CertificateServicesClient-*`.

Missing channels and absent optional families are summarized and skipped. Access-denied, malformed native output, and other native failures are errors, not missing-channel results. Analytic/Debug channels and live traces are separate from this event-log preparation.

Each selected log smaller than 100 MiB gets a 100 MiB maximum. Larger logs stay at their current size. The total disk allowance can grow by several GiB if many channels are installed. Logs are never cleared. Enabling a channel does not recover earlier events or force every provider to emit events; effective policy and provider behavior still apply.

The collector still queries its original five channels and selected System events. It does not ingest the supplemental channels, EVTX files, or live traces. Use Event Viewer to inspect or export supplemental events before restoring settings if you need them. Restoring smaller original log sizes can reduce retained history as Windows enforces those limits.

## Optional Schannel detail

To include machine-wide Schannel event logging in the saved baseline, start with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-8021xLogging.ps1 -Enable -IncludeSchannel
```

This sets only the `EventLogging` DWORD to `7` under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL`. It preserves the original DWORD, including zero, or the value's absence. A non-DWORD value produces an error before any logging changes. `-Restore` restores the exact DWORD or removes the value if it was absent.

Microsoft requires a reboot to apply this setting and its restoration. The helper reports this requirement but never reboots or restarts services. Schannel detail is not guaranteed coverage of every EAP-TLS implementation.

If an existing baseline excludes Schannel, first run `-Restore`, then `-Enable -IncludeSchannel`. Repeated enable otherwise reuses the original channel selection and Schannel choice.

## Cleanup and recovery

Run `-Restore` on the same machine with the same elevated account. The private baseline lives at `%ProgramData%\Dot1xLogging\state.json`, outside the repository. Its protected ACL permits that account, SYSTEM, and Administrators. The helper validates the machine, caller, schema, channel names, and settings, and rejects unsafe ACLs, reparse paths, and hard-linked state files.

The baseline is saved and flushed before any settings change. It is never overwritten by a repeated enable. Enable attempts every saved channel and reports partial errors. Restore retries all saved settings idempotently; it removes the baseline only after every setting is restored. The empty private directory remains for reuse by the same account. A completed restore can be repeated without changing logging.

If a run fails or is interrupted, keep the baseline and rerun `-Restore`. Resolve the reported access or missing-channel error first if necessary. Do not delete the baseline to retry enable: that loses the original settings. A malformed, foreign, or unsafe baseline stops all logging changes; keep the file for recovery rather than replacing it with a new baseline. A caught initial-save error removes only the newly created file; cleanup failures are reported. Power loss during the first write can still leave an incomplete file, but no logging changes begin until that write succeeds. Distinguish that initial-save failure from an active baseline before repairing state; do not delete a file solely because a later run rejects it.

`-Restore` changes settings, not collected evidence. After reviewing or exporting what you need, remove your report and capture files separately. They can contain identifying information.

## Optional client tracing

Event-channel preparation is not packet, ETW, or RAS tracing. For a short client trace, follow Microsoft's client data-collection procedure linked in [Sources](#sources), choosing the wired or Wi-Fi commands for the affected adapter. The helper does not start, stop, ingest, or restore those traces.

Before starting a trace, check `netsh trace show status` and `netsh trace show scenarios`. Preserve the current RAS tracing configuration. After reproduction, stop the trace that you started with `netsh trace stop` and restore the prior RAS tracing settings. Keep the ETL, any associated CAB, and relevant `%SystemRoot%\Tracing` files separately from the collector report. Existing trace sessions need their own cleanup; `-Restore` does not stop them.

## Sources

- [Microsoft wevtutil command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil): channel enumeration, configuration, and export.
- [Microsoft client 802.1X data collection](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/data-collection-for-troubleshooting-802-1x-authentication-issues): optional wired/Wi-Fi and RAS traces.
- [Microsoft Schannel event logging](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/enable-schannel-event-logging): DWORD values and reboot requirement.

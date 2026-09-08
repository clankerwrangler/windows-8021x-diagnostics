# Report output

The console and `report.txt` show relevant configuration, observations with possible interpretations and next checks, grouped authentication history, and collection gaps. They do not print successful probe timings or generic collector limitations.

Incomplete interface, service, profile, and certificate summaries include the recorded probe reasons. Cleanup warnings remain separate.

Use `-InterfaceAlias` or `-ProfileName` to select a target. Without either, the configuration view selects active physical interfaces. For WLAN, the current profile is preferred when Windows reported one. An explicitly selected disconnected interface remains visible. Unrelated adapter/profile findings remain in the full JSON and detailed text.

The console and `report.txt` show capture and event times in the rendering machine's local time, with an explicit UTC offset for each instant, including daylight saving time. Detailed timestamp references use the same format. `report.json` and `evidence.json` retain UTC timestamps for correlation and ordering.

## More detail

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Get-8021xDiagnostics.ps1 -InterfaceAlias 'Ethernet' -Detailed
```

`-Detailed` applies to both the console and saved `report.txt`. It includes the original findings, rule IDs, confidence values, evidence references, limitations, and probe diagnostics. It also removes the default ten-group history display limit.

`report.json`, `evidence.json`, and `-PassThru` retain the complete structured findings and collected evidence metadata regardless of the text mode. `report.json` and `-PassThru` contain findings and collection status, not a duplicate of `evidence.json`. Finding records additionally carry `ReportScope` for presentation; the diagnosis criteria do not change.

Routine certificate candidates are a configuration summary, not a repair task. Cached-chain errors and unknown/offline chain assessments remain visible. This is candidate inventory, not proof of the certificate selected by Windows.

## History

Repeated outcomes are grouped using the recorded provider, interface GUID, profile, authentication mode, connection ID, EAP fields, event version, and normalized error codes. Raw events are retained in `evidence.json`.

A later success is linked to a failure only when the recorded context matches and includes an interface, profile, and identity mode or connection ID. A success with different or incomplete context does not establish recovery. The report describes recorded events, not current authorization.

Codes with unverified field namespaces are labeled as possible numeric interpretations. Unknown codes remain numeric. Missing timestamps stay explicitly uncorrelated. Events outside the captured lookback window are excluded from the history view.

Older groups beyond the default display limit are counted explicitly. `-Detailed` displays all groups. Failed process or temporary-file cleanup stays visible even when its collector is unrelated to the selected medium.

## Tests

`tests/Test-Report.ps1` exercises the presentation with synthetic evidence only. It is included in `tests/Run-Tests.ps1`. `tests/Test-IO.ps1` also checks the compact/detailed CLI and saved text paths while retaining full JSON findings.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Report.ps1 -ScriptPath .\Get-8021xDiagnostics.ps1
```

These tests do not attempt network authentication or establish real wired/WLAN collection coverage.

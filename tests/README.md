# Tests

Run the dependency-free synthetic suite on Windows PowerShell 5.1. No Pester, package, or runtime installation is required.

## Run the synthetic suite

Provide an existing private directory that you own. Restrict access to the execution identity, SYSTEM, and Administrators. The suite creates and removes its own test files and processes; it does not run live endpoint collection.

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1 -ScratchPath "C:\YOUR_PRIVATE_TEST_DIRECTORY"
```

The execution policy applies only to this process. The runner prints the source SHA-256, runtime versions, check results, and suite exit codes. Exit `0` means that all suites pass; exit `1` means that at least one suite fails.

## Coverage

- Offline diagnoses with positive and negative controls: service relevance, certificate dates/EKUs/stores, execution-user context, multiple adapters/profiles, and missing evidence without false authentication proof.
- Exact event providers and authentication IDs, time/interface/profile scope, historical failure followed by success, and unavailable or unsupported log queries.
- Safe profile and event XML parsing, external entity rejection, selected-field output, and omission of profile credentials.
- Native exit codes, argument boundaries, timeouts, owned-process cleanup, and output bounds.
- Script parsing, help, read-only source guards, and CLI failures.
- Reusable output destinations, unique private report directories, missing parent creation, literal/relative/trailing paths, saved-path visibility, and pipeline-only behavior.
- Preservation of existing files and ACLs, rejection of reparse paths, exclusive private directories, and create-new report files.

## Optional native checks

`Test-NativeChain.ps1` and `Test-CollectorSmoke.ps1` are separate opt-in tests, excluded from `Run-Tests.ps1`. Both require `-ExpectedSourceSha256` to identify the source being tested.

The chain test uses public synthetic DER fixtures in memory. It does not use private keys or write certificate stores.

The collector smoke test reads the endpoint's configuration and logs. Provide a private `-ScratchPath`; reports can contain identifying endpoint data. The test prints counts, statuses, and finding IDs, then deletes its generated reports. It does not change service, network, profile, certificate-store, or log settings.

Read [verified test results](test-results.md) for revision-specific outcomes and limits. Synthetic tests and a collector smoke test do not establish physical wired/Wi-Fi EAP authentication, RADIUS interoperability, or live revocation. Static guards are regression checks, not a complete security proof.

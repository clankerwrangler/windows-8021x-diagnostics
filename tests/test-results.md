# Recorded test results

Results apply to the listed source hashes, not later changes. CI runs record their tested commit, source SHA-256, UTC time, Windows version, and PowerShell runtime.

Tests ran on Windows 11 IoT Enterprise LTSC (`10.0.26100.0`) with Windows PowerShell `5.1.26100.9278`. They use built-in assertions; no Pester or additional packages are required.

## Client logging helper: 2026-09-08

- Collector SHA-256: `31709e1787f57bbcb7fbf5ec04b80923e05f8f2e318d7290f39a25dbf57323d9` (unchanged).
- Logging helper SHA-256: `1972cfe5757838c8b61b99e743c59ff777348d76d810e1b13c68e6eeda7f3557`.
- Logging test SHA-256: `6a529f2c3a130ae832f1cc1b22e3816e90c0d6440ba2469134325191ee993d38`.

The full Windows PowerShell 5.1 runner passed **223 cases across 11 suites**, with zero failures or timeouts. This includes 17 logging-helper cases covering channel selection, native exit codes, missing logs, original baselines, repeated enable, partial failures, exact restore, Schannel presence and DWORD values, and private state files. The runner was invoked without `-ScriptPath` to verify its default path resolution.

A separate elevated live client test enabled all 22 installed allowlisted channels, set optional Schannel logging, repeated enable without replacing the original baseline, and restored every original enabled state, size, and Schannel value. A second restore was a no-op. Independent `Get-WinEvent` metadata checks verified the channel settings. Native sizes of `1052672` bytes were preserved exactly; they must not be rounded to 64 KiB boundaries. An isolated temporary event channel also passed the native size roundtrip and was unregistered afterward.

No authentication was attempted, logs were not cleared, and no service, network connection, or computer was restarted. Schannel registry restoration was verified; reboot-dependent activation was not tested. The synthetic suite makes no live log-setting or registry changes.

Use a short private scratch path. An initial run under a deeply nested path failed one existing output-location case; the same assertion passed with a short path. No assertion or collector behavior was changed to obtain the pass.

## Historical run: output destination changes

Source SHA-256: `b5a43716734da2b318357a5918f9e0216a87fcd65070a8aeab9515327dd5c96c`.

| Focused suite | Passed | Failed |
| --- | ---: | ---: |
| Static parsing and help | 6 | 0 |
| Offline CLI and output | 21 | 0 |
| Native process handling | 7 | 0 |
| Private directory and wired transport ownership | 9 | 0 |
| **Total** | **43** | **0** |

All suites exited `0`; none timed out. Tests verified reusable output destinations, unique report directories, automatic parent creation, preservation of existing files and ACLs, literal/relative/trailing paths, saved-path visibility, and pipeline-only behavior. Private-directory, reparse rejection, create-new file, process timeout, and synthetic wired-file cleanup controls also passed.

This was a focused synthetic regression, not a complete-suite or live collector run on this revision. The optional smoke test's output-path update was parse-checked but not executed.

## Historical run: complete suite

Source SHA-256: `238db21095b1ce43d50f9126ee6a38d97e809481cf3be293f277f6090bf80c16`.

| Suite | Passed | Failed |
| --- | ---: | ---: |
| Static parsing and help | 6 | 0 |
| Offline diagnosis rules | 74 | 0 |
| Profile XML parsing | 12 | 0 |
| Synthetic event collection | 12 | 0 |
| Native process handling | 7 | 0 |
| Offline CLI and output | 15 | 0 |
| Private directory and wired transport ownership | 7 | 0 |
| Cache-only certificate chains using public DER fixtures | 4 | 0 |
| **Total** | **137** | **0** |

All suites exited `0`; none timed out. The chain tests used in-memory public certificates, without private keys or certificate-store writes. Missing issuers remained partial chains, and an untrusted root remained untrusted. API flags enforce cache-only retrieval; timing assertions are not packet-level evidence.

A separate bounded read-only collector smoke test passed on this revision. It retained `COLLECTION-INCOMPLETE` and `AUTH-NOT-VERIFIED` rather than treating partial collection as success. It also correctly classified an unsupported System/EapHost provider-channel pairing. No profiles or certificates were observed, so this smoke test does not verify enterprise profile or certificate collection.

## Limits

- These results do not establish physical wired/Wi-Fi EAP authentication, RADIUS interoperability, or server/authenticator behavior.
- Actual affected-user and nonadministrator execution, live revocation, and packet-level absence of network traffic were not tested. Synthetic access failures do not replace those checks.
- Concurrent output-parent creation and a real access-denied output destination were not exercised.
- A passing static guard or synthetic test is not a complete security proof.

See [the test guide](README.md) for coverage and execution instructions.

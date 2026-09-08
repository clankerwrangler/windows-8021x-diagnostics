# Implemented coverage

This page describes the script, not every possible cause of an 802.1X failure. See the [troubleshooting guide](troubleshooting.md) for manual checks and escalation.

| Area | Collected or evaluated automatically | Limits | Regression suites |
| --- | --- | --- | --- |
| Interfaces and services | Link and driver metadata; selected service states; target-specific relevance. | No radio control, reconnect, or active link test. | Rules, collection, static |
| IP configuration | IPv4/IPv6 addresses, DNS servers, default gateways; no-usable-address and no-DNS warnings. | No DNS query, DHCP renewal, route-selection test, or application probe. | Rules |
| Profiles | Native WLAN and per-interface wired export; selected OneX/EAP, validation, SSO, timer, and root-pin fields. | Not a complete method schema or effective GPO/MDM policy evaluation. Successful real enterprise-profile collection still needs validation. | XML, wired ownership, collection |
| Client certificates | User/machine personal-store metadata; structural candidates, dates, EKU and key-presence flags; cache-only chain status. | No selected-certificate proof, key operation, full profile-filter evaluation, server mapping, or live revocation. | Rules; optional native chain |
| Events | Bounded AutoConfig/EapHost/TLS/NTLM history and collection status; provider-qualified historical outcomes. | Query bounds apply before target filtering. Missing, disabled, denied, unsupported, and truncated history must be read as collection limits. | Collection, rules |
| Error references | Selected ONEX, HRESULT and RAS constant names; raw values and event versions retained. | Numeric matches are explicitly unverified. No event-version/field namespace contract has been validated. Unknown values are not labeled HRESULTs. | Error codes, rules |
| Reports | Text/JSON findings, collection status, optional structured historical context, private per-run output. | Message omission is not anonymization. This is a snapshot, not an authentication trace. | IO, rules, static |
| Process and file handling | Owned jobs, bounded output, timeouts, restricted temporary directories, reparse rejection, create-new reports. | Synthetic regression checks are not an exhaustive security assessment. | Process, IO, wired ownership |

`CodeDetails` on historical-failure findings separates `Namespace` (currently `Unknown`) from `CandidateNamespace` and `CandidateLabel`. `MappingStatus=UnverifiedNumericMatch` means only that a number matches a reference constant. See [error-code references](error-codes.md).

IP/DNS findings with matching history expose `AuthenticationContext`, including outcome, time, interface, profile, and `IsHistorical=true`. A missing context is `null`, not a successful attempt.

The script does not observe the RADIUS/NPS decision, applied VLAN/role/ACL, NAC posture, server-side certificate mapping, or complete EAP exchange. It states that scope once in the report header rather than emitting an always-present warning finding.

## Validation status

The full regression suite and a separate client logging enable/restore test passed on Windows PowerShell 5.1. See [test results](../tests/test-results.md) for source hashes, counts, and limits, and [tests](../tests/README.md) for execution instructions.

Still needed: real wired/WLAN enterprise-profile collection, affected-user and alternate-administrator contexts, populated user/machine certificate stores, sanitized native event fixtures across relevant builds, and correlated client/RADIUS lab attempts. No synthetic result substitutes for those checks.

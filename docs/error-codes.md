# Error-code references

The reference decoders require an explicit namespace. In particular, RAS error 691 is not an HRESULT. Hexadecimal, signed decimal and unsigned decimal representations preserve the same 32 bits.

| Namespace | Value | Constant |
| --- | --- | --- |
| HRESULT / SSPI | `0x8009030D` | `SEC_E_UNKNOWN_CREDENTIALS` |
| HRESULT / SSPI | `0x80090317` | `SEC_E_CONTEXT_EXPIRED` |
| HRESULT / SSPI | `0x80090325` | `SEC_E_UNTRUSTED_ROOT` |
| HRESULT / SSPI | `0x80090327` | `SEC_E_CERT_UNKNOWN` |
| HRESULT / certificate | `0x800B0114` | `CERT_E_INVALID_NAME` |
| HRESULT / EAPHost | `0x80420014` | `EAP_E_EAPHOST_IDENTITY_UNKNOWN` |
| HRESULT / EAP | `0x80420100` | `EAP_E_USER_CERT_NOT_FOUND` |
| RAS | `691` / `0x000002B3` | `ERROR_AUTHENTICATION_FAILURE` |

`CERT_E_INVALID_NAME` concerns certificate name constraints, not necessarily a mismatch with the configured RADIUS server hostname. `EAP_E_EAPHOST_IDENTITY_UNKNOWN` does not mean a client certificate is missing. `SEC_E_CERT_UNKNOWN` is an unspecified certificate-processing error, not a specific untrusted-root result.

## Event-field interpretation

The collector retains provider, event ID, version, field name, raw value and hexadecimal value. A recognized historical AutoConfig failure may also carry a candidate reference label. That label has `MappingStatus=UnverifiedNumericMatch`; the field's `Namespace` remains `Unknown`.

No provider/version/field-to-namespace contract is currently verified. Do not treat a candidate label as a diagnosis. Adding a verified contract requires a documented field definition and representative native fixtures for the relevant provider and event version. A matching numeric constant or a synthetic fixture alone is not enough.

Unknown values remain unmapped numeric codes. Other providers do not inherit AutoConfig label candidates.

## Primary references

Checked 7 September 2026. These references establish constants, not the meaning of every event field that contains the same number.

- [Microsoft: COM security and setup errors](https://learn.microsoft.com/en-us/windows/win32/com/com-error-codes-4)
- [Microsoft: EAP-related error and information constants](https://learn.microsoft.com/en-us/windows/win32/eaphost/eap-related-error-and-information-constants)
- [Microsoft: ONEX_EAP_ERROR](https://learn.microsoft.com/en-us/windows/win32/api/dot1x/ns-dot1x-onex_eap_error)
- [Microsoft: Routing and Remote Access error codes](https://learn.microsoft.com/en-us/windows/win32/rras/routing-and-remote-access-error-codes)
- [Microsoft: ONEX_REASON_CODE](https://learn.microsoft.com/en-us/windows/win32/api/dot1x/ne-dot1x-onex_reason_code)

`tests/Test-ErrorCodes.ps1` independently lists expected constants and checks adjacent distinctions, numeric representations, namespace separation, and unknown versions/providers.

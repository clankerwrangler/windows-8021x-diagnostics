<# Synthetic constant and namespace checks. References: ../docs/error-codes.md. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ScriptPath)
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
. $ScriptPath

# Expected values are independent of the implementation's decoder table.
$constants = @(
    @('8009030D','SEC_E_UNKNOWN_CREDENTIALS'),
    @('80090317','SEC_E_CONTEXT_EXPIRED'),
    @('80090325','SEC_E_UNTRUSTED_ROOT'),
    @('80090327','SEC_E_CERT_UNKNOWN'),
    @('800B0109','CERT_E_UNTRUSTEDROOT'),
    @('800B0114','CERT_E_INVALID_NAME'),
    @('80420014','EAP_E_EAPHOST_IDENTITY_UNKNOWN'),
    @('80420100','EAP_E_USER_CERT_NOT_FOUND')
)
foreach ($row in $constants) {
    Test-Case ('constant ' + $row[0] + ' is ' + $row[1]) {
        $code = [Convert]::ToUInt32($row[0],16)
        Assert-Equal ((Get-Dot1xHresultLabel $code) -split ':',2)[0] $row[1] 'Constant name differs from the reference.'
    }
}
Test-Case 'hex unsigned and signed representations preserve all 32 bits' {
    foreach ($row in $constants) {
        $code = [Convert]::ToUInt32($row[0],16)
        $signed = [BitConverter]::ToInt32([BitConverter]::GetBytes($code),0)
        foreach ($value in @(('0x' + $row[0]),$code.ToString([Globalization.CultureInfo]::InvariantCulture),$signed.ToString([Globalization.CultureInfo]::InvariantCulture))) {
            Assert-Equal (ConvertTo-Dot1xUInt32 $value) $code 'A 32-bit representation changed the numeric code.'
        }
    }
}
Test-Case 'UInt32 boundary values are accepted without overflow' {
    Assert-Equal (ConvertTo-Dot1xUInt32 '0') ([uint32]0) 'Zero was lost.'
    Assert-Equal (ConvertTo-Dot1xUInt32 '-1') ([uint32]::MaxValue) 'Signed all-ones was lost.'
    Assert-Equal (ConvertTo-Dot1xUInt32 '4294967295') ([uint32]::MaxValue) 'Unsigned maximum was lost.'
}
Test-Case 'invalid and out-of-range codes remain unknown' {
    foreach ($value in @('','garbage','0x100000000','4294967296','-2147483649','1.5')) {
        Assert-True ($null -eq (ConvertTo-Dot1xUInt32 $value)) 'Invalid input was accepted as a code.'
    }
}
Test-Case 'RAS error 691 is not an HRESULT entry' {
    Assert-True ($null -eq (Get-Dot1xHresultLabel 691)) 'A RAS number entered the HRESULT table.'
    Assert-True ((Get-Dot1xRasErrorLabel 691) -like 'ERROR_AUTHENTICATION_FAILURE:*') 'RAS error 691 has the wrong constant name.'
    Assert-True ($null -eq (Get-Dot1xRasErrorLabel 690)) 'An adjacent RAS value acquired the wrong label.'
}
Test-Case 'name constraints are not reduced to server hostname mismatch' {
    $label = Get-Dot1xHresultLabel ([Convert]::ToUInt32('800B0114',16))
    Assert-True ($label -match 'name constraints') 'The name-constraint meaning is missing.'
    Assert-True ($label -notmatch 'expected server name') 'Name constraints became a server-name verdict.'
}
Test-Case 'numeric matches do not establish an event field namespace' {
    foreach ($version in @($null,0,999)) {
        $event = [pscustomobject]@{
            ProviderName='Microsoft-Windows-Wired-AutoConfig'; Id=15514; Version=$version
            Fields=[pscustomobject]@{ReasonCode='0x50005';ErrorCode='0x800B0109';ResultCode='0xDEADBEEF';EapErrorCode='691'}
        }
        $details = @(Get-Dot1xEventCodeDetails $event)
        Assert-Equal $details.Count 4 'A code field was lost.'
        foreach ($detail in $details) { Assert-Equal $detail.Namespace 'Unknown' 'An unverified namespace was promoted to a contract.' }
        $error = @($details | Where-Object { $_.Field -eq 'ErrorCode' })[0]
        Assert-Equal $error.MappingStatus 'UnverifiedNumericMatch' 'A constant match became verified.'
        Assert-Equal $error.CandidateNamespace 'HRESULT' 'Reference namespace was lost.'
        Assert-Equal $error.EventVersion $version 'Event version was dropped.'
        $unknown = @($details | Where-Object { $_.Field -eq 'ResultCode' })[0]
        Assert-Equal $unknown.MappingStatus 'Unmapped' 'Unknown code was mapped.'
        Assert-Equal $unknown.RawValue '0xDEADBEEF' 'Raw code was changed.'
    }
}
Test-Case 'another provider does not inherit AutoConfig code candidates' {
    $event = [pscustomobject]@{ProviderName='Fixture-Other-Provider';Id=15514;Version=0;Fields=@{ErrorCode='0x800B0109'}}
    $detail = @(Get-Dot1xEventCodeDetails $event)[0]
    Assert-Equal $detail.MappingStatus 'Unmapped' 'Another provider inherited a decoder.'
    Assert-True ($null -eq $detail.CandidateLabel) 'Another provider inherited a named diagnosis.'
}
Test-Case 'unmapped event codes are not called HRESULTs' {
    $event = [pscustomobject]@{ProviderName='Microsoft-Windows-Wired-AutoConfig';Id=15514;Version=999;Fields=@{ErrorCode='0xDEADBEEF'}}
    $summary = Get-Dot1xAuthFailureSummary $event $event.ProviderName $event.Id
    Assert-True ($summary -match 'unmapped numeric code') 'Unknown code was not retained.'
    Assert-True ($summary -notmatch 'unmapped HRESULT') 'An unknown field acquired an HRESULT namespace.'
}
Test-Case 'message omission help does not promise anonymization' {
    $source = [IO.File]::ReadAllText($ScriptPath)
    Assert-True ($source -match 'can still identify users or networks') 'Identifying metadata warning is missing.'
    Assert-True ($source -notmatch 'identities must stay out') 'Message omission still promises identity removal.'
}
Complete-Tests

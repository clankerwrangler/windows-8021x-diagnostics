<#
.SYNOPSIS
Tests profile XML summarization using memory-only synthetic profiles.
#>
[CmdletBinding()]
param([string]$ScriptPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1'))
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
. (Join-Path $PSScriptRoot 'Xml-Fixtures.ps1')
. $ScriptPath
$guid = '11111111-1111-1111-1111-111111111111'
function Read-TestProfile {
    param([string]$Xml, [string]$Kind = 'Wireless')
    ConvertFrom-Dot1xProfileXml -XmlText $Xml -Kind $Kind -InterfaceGuid $guid -Name 'fixture-profile'
}
function Assert-XmlRejected {
    param([string]$Xml)
    $rejected = $false
    try { $null = Read-TestProfile $Xml } catch { $rejected = $true }
    Assert-True $rejected 'Unsafe or malformed XML was accepted.'
}
Test-Case 'wireless enterprise profile extracts selected metadata' {
    $p = Read-TestProfile (New-TestProfileXml)
    Assert-Equal $p.Kind 'Wireless' 'Profile kind was lost.'
    Assert-Equal $p.InterfaceGuid $guid 'Interface scope was lost.'
    Assert-Equal $p.OneXEnabled $true 'Enterprise flag was lost.'
    Assert-Equal $p.AuthMode 'machine' 'Authentication context was lost.'
    Assert-True ($p.EapTypes -contains 13) 'EAP-TLS type was lost.'
    Assert-True ($p.TrustedRootThumbprints -contains 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') 'Configured root value was lost.'
}
Test-Case 'wired enterprise profile uses OneXEnabled and preserves kind' {
    $p = Read-TestProfile -Xml (New-TestProfileXml -Kind Wired) -Kind Wired
    Assert-Equal $p.Kind 'Wired' 'Wired profile kind was lost.'
    Assert-Equal $p.OneXEnabled $true 'Wired enterprise flag was lost.'
}
Test-Case 'authMode values remain distinct' {
    foreach ($mode in @('machine','user','machineOrUser')) {
        $p = Read-TestProfile (New-TestProfileXml -AuthMode $mode)
        Assert-Equal $p.AuthMode $mode 'Authentication contexts were conflated.'
    }
}
Test-Case 'omitted server validation is unknown rather than false' {
    $p = Read-TestProfile (New-TestProfileXml)
    Assert-True ($null -eq $p.ServerValidationEnabled) 'Omitted validation setting was interpreted as disabled.'
}
Test-Case 'explicit server validation enable and disable remain distinct' {
    $p = Read-TestProfile (New-TestProfileXml -EapExtra '<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>')
    Assert-Equal $p.ServerValidationEnabled $true 'Explicit server validation enable was lost.'
    $p = Read-TestProfile (New-TestProfileXml -EapExtra '<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">false</PerformServerValidation>')
    Assert-Equal $p.ServerValidationEnabled $false 'Explicit server validation disable was lost.'
    $p = Read-TestProfile (New-TestProfileXml -EapExtra '<DisableServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</DisableServerValidation>')
    Assert-Equal $p.ServerValidationEnabled $false 'Inverse validation flag was misread.'
}
Test-Case 'nested PEAP and MSCHAPv2 retain outer and inner method context' {
    $xml = @'
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>fixture-peap</name><MSM><security><authEncryption><authentication>WPA2</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption><OneX xmlns="http://www.microsoft.com/networking/OneX/v1"><authMode>user</authMode><EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type></EapMethod><Config><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>25</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1"><ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>radius.fixture.invalid</ServerNames></ServerValidation><FastReconnect>true</FastReconnect><InnerEapOptional>false</InnerEapOptional><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap></EapType></Eap></Config></EapHostConfig></EAPConfig></OneX></security></MSM></WLANProfile>
'@
    $p = Read-TestProfile $xml
    Assert-True ($p.EapTypes -contains 25 -and $p.EapTypes -contains 26) 'Nested EAP methods were flattened or lost.'
    Assert-True (@($p.EapMethods | Where-Object { $_.Type -eq 25 -and $_.TunnelDepth -eq 0 }).Count -eq 1) 'Outer EAP context was lost.'
    Assert-True (@($p.EapMethods | Where-Object { $_.Type -eq 26 -and $_.TunnelDepth -eq 1 }).Count -eq 1) 'Inner EAP context was lost.'
}
Test-Case 'profile credentials and raw XML are not returned' {
    $extra = '<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>fixture-secret-key-DO-NOT-EMIT</keyMaterial></sharedKey><EapHostUserCredentials><Username>fixture-secret-user-DO-NOT-EMIT</Username><Password>fixture-secret-password-DO-NOT-EMIT</Password></EapHostUserCredentials><vendorSecret>fixture-secret-vendor-DO-NOT-EMIT</vendorSecret>'
    $p = Read-TestProfile (New-TestProfileXml -Extra $extra)
    $json = $p | ConvertTo-Json -Depth 20
    Assert-True ($json -notmatch 'fixture-secret-') 'A non-allowlisted secret value escaped the parser.'
    foreach ($name in @('Xml','RawXml','Password','Username','KeyMaterial','EapHostUserCredentials','vendorSecret')) { Assert-True ($null -eq $p.PSObject.Properties[$name]) 'A non-allowlisted secret field escaped the parser.' }
}
Test-Case 'malformed XML is rejected' { Assert-XmlRejected '<WLANProfile><name>fixture</WLANProfile>' }
Test-Case 'external XML entity is rejected before resolution' {
    Assert-XmlRejected '<!DOCTYPE WLANProfile [<!ENTITY ext SYSTEM "file:///C:/fixture-never-read.txt">]><WLANProfile><name>&ext;</name></WLANProfile>'
}
Test-Case 'internal XML entity expansion is also rejected' {
    Assert-XmlRejected '<!DOCTYPE WLANProfile [<!ENTITY a "fixture"><!ENTITY b "&a;&a;&a;">]><WLANProfile><name>&b;</name></WLANProfile>'
}
Test-Case 'oversized XML is rejected at the documented bound' {
    Assert-XmlRejected ('<WLANProfile><name>' + ('x' * 1048577) + '</name></WLANProfile>')
}
Test-Case 'unrelated XML Eap Type does not create a client-certificate requirement' {
    $xml=(New-TestProfileXml -EapType 25 -Extra '<Eap xmlns="urn:fixture:unrelated"><Type>13</Type></Eap>')
    $p=Read-TestProfile $xml
    Assert-True ($p.EapTypes -contains 25) 'Known outer EAP method was lost.'
    Assert-True ($p.EapTypes -notcontains 13) 'Unrelated namespace created a TLS requirement.'
}

Complete-Tests

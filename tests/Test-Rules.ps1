<#
.SYNOPSIS
Tests offline diagnosis rules with synthetic evidence. No collection runs.
#>
[CmdletBinding()]
param([string]$ScriptPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1'))
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
. $ScriptPath

$script:FixtureNow = [DateTimeOffset]::Parse('2026-01-15T12:00:00Z')
$script:GuidA = '11111111-1111-1111-1111-111111111111'
$script:GuidB = '22222222-2222-2222-2222-222222222222'
$script:ClientAuthOid = '1.3.6.1.5.5.7.3.2'
function New-TestCertificate {
    param([string]$Store = 'LocalMachine', [int]$ExpiresDays = 90, [bool]$HasPrivateKey = $true,
          [string[]]$EkuOids = @('1.3.6.1.5.5.7.3.2'), [bool]$Eligible = $true)
    [pscustomobject]@{
        Store = $Store; Thumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        NotBeforeUtc = $script:FixtureNow.AddDays(-30).ToString('o')
        NotAfterUtc = $script:FixtureNow.AddDays($ExpiresDays).ToString('o')
        EkuOids = $EkuOids; HasPrivateKey = $HasPrivateKey; ClientAuthEkuEligible = $Eligible
        Chain = [pscustomobject]@{ Status = 'NotEvaluated'; Limitations = @('No network chain or revocation evaluation.') }
    }
}
function New-TestEvidence {
    [pscustomobject]@{
        SchemaVersion = 1; CapturedAtUtc = $script:FixtureNow.ToString('o')
        Collection = [pscustomobject]@{ ExecutionUser = 'fixture-execution-user'; IsAdministrator = $true }
        Services = @(
            [pscustomobject]@{ Name = 'WlanSvc'; Status = 'Running'; StartMode = 'Auto' }
            [pscustomobject]@{ Name = 'dot3svc'; Status = 'Running'; StartMode = 'Auto' }
            [pscustomobject]@{ Name = 'EapHost'; Status = 'Stopped'; StartMode = 'Manual' }
        )
        Interfaces = @([pscustomobject]@{ InterfaceIndex = 10; InterfaceGuid = $script:GuidA; Alias = 'fixture-wireless'; Status = 'Up'; PhysicalMediaType = 9 })
        IpConfiguration = @([pscustomobject]@{
            InterfaceIndex = 10; IPv4Addresses = @([pscustomobject]@{ IPAddress = '192.0.2.10' })
            IPv6Addresses = @(); IPv4DefaultGateway = @([pscustomobject]@{ NextHop = '192.0.2.1' })
            IPv6DefaultGateway = @(); DnsServers = @('192.0.2.53')
        })
        Wireless = @([pscustomobject]@{ InterfaceGuid = $script:GuidA; State = 'Connected'; CurrentProfileName = 'fixture-profile'; OneXEnabled = $true })
        Wired = @()
        Profiles = @([pscustomobject]@{ Kind = 'Wireless'; InterfaceGuid = $script:GuidA; Name = 'fixture-profile'; OneXEnabled = $true; AuthMode = 'machine'; EapTypes = @(13); ServerValidationEnabled = $true })
        Certificates = @(New-TestCertificate)
        CertificateStores = @([pscustomobject]@{ Store = 'LocalMachine'; Status = 'Succeeded'; Truncated = $false }, [pscustomobject]@{ Store = 'CurrentUser'; Status = 'Succeeded'; Truncated = $false })
        Events = @(); EventLogs = @()
        Probes = @([pscustomobject]@{ Name = 'fixture'; Status = 'Succeeded'; DurationMs = 1; Limitations = @() })
    }
}
function Assert-HasFinding {
    param($Findings, [string]$Id)
    $rows = @(@($Findings) | Where-Object { $null -ne $_ -and $_.Id -eq $Id })
    Assert-True ($rows.Count -gt 0) ('Expected finding ' + $Id + '.')
}
function Assert-NoFinding {
    param($Findings, [string]$Id)
    $rows = @(@($Findings) | Where-Object { $null -ne $_ -and $_.Id -eq $Id })
    Assert-Equal $rows.Count 0 ('Unexpected finding ' + $Id + '.')
}
function Get-TestFindings { param($Evidence) @(@(Get-Dot1xDiagnosis -Evidence $Evidence) | Where-Object { $null -ne $_ }) }

Test-Case 'baseline does not invent service or address faults' {
    $f = Get-TestFindings (New-TestEvidence)
    foreach ($id in @('SERVICE-WLAN-NOT-RUNNING', 'SERVICE-WIRED-NOT-RUNNING', 'EAPHOST-DISABLED', 'PROFILE-SERVER-VALIDATION-DISABLED', 'CERT-NO-SUITABLE-CANDIDATE', 'IP-NO-USABLE-ADDRESS', 'DNS-NO-SERVERS', 'COLLECTION-INCOMPLETE')) { Assert-NoFinding $f $id }
    Assert-True (($f | ConvertTo-Json -Depth 20) -notmatch '(?i)all.clear|authentication (is |was )?verified') 'Baseline falsely asserts an all-clear.'
}
Test-Case 'empty evidence is unknown rather than an all-clear' {
    $f = Get-TestFindings ([pscustomobject]@{ SchemaVersion = 1; CapturedAtUtc = $script:FixtureNow.ToString('o') })
    Assert-HasFinding $f 'EVIDENCE-EMPTY'
}
Test-Case 'finding contract includes evidence and limitations' {
    $e = New-TestEvidence; $e.Services[0].Status = 'Stopped'
    foreach ($finding in Get-TestFindings $e) {
        foreach ($name in @('Id', 'Severity', 'Confidence', 'Category', 'Summary', 'Evidence', 'Remediation', 'Limitations')) { Assert-True ($null -ne $finding.PSObject.Properties[$name]) ('Finding lacks ' + $name + '.') }
        Assert-True ($finding.Severity -in @('Error', 'Warning', 'Information')) 'Severity is invalid.'
        Assert-True ($finding.Confidence -in @('High', 'Medium', 'Low')) 'Confidence is invalid.'
    }
}
Test-Case 'stopped WLAN service with enterprise wireless profile' {
    $e = New-TestEvidence; $e.Services[0].Status = 'Stopped'
    Assert-HasFinding (Get-TestFindings $e) 'SERVICE-WLAN-NOT-RUNNING'
}
Test-Case 'stopped WLAN service without enterprise wireless requirement' {
    $e = New-TestEvidence; $e.Services[0].Status = 'Stopped'; $e.Profiles = @(); $e.Wireless = @()
    Assert-NoFinding (Get-TestFindings $e) 'SERVICE-WLAN-NOT-RUNNING'
}
Test-Case 'stopped wired service with enterprise wired profile' {
    $e = New-TestEvidence; $e.Services[1].Status = 'Stopped'; $e.Profiles[0].Kind = 'Wired'; $e.Wireless = @()
    Assert-HasFinding (Get-TestFindings $e) 'SERVICE-WIRED-NOT-RUNNING'
}
Test-Case 'stopped wired service without enterprise wired requirement' {
    $e = New-TestEvidence; $e.Services[1].Status = 'Stopped'
    Assert-NoFinding (Get-TestFindings $e) 'SERVICE-WIRED-NOT-RUNNING'
}
Test-Case 'disabled EAPHost is a configuration concern' {
    $e = New-TestEvidence; $e.Services[2].StartMode = 'Disabled'
    Assert-HasFinding (Get-TestFindings $e) 'EAPHOST-DISABLED'
}
Test-Case 'stopped demand-start EAPHost is not disabled' {
    Assert-NoFinding (Get-TestFindings (New-TestEvidence)) 'EAPHOST-DISABLED'
}
Test-Case 'explicitly disabled profile server validation' {
    $e = New-TestEvidence; $e.Profiles[0].ServerValidationEnabled = $false
    Assert-HasFinding (Get-TestFindings $e) 'PROFILE-SERVER-VALIDATION-DISABLED'
}
Test-Case 'omitted server validation setting is not explicit disablement' {
    $e = New-TestEvidence; $e.Profiles[0].ServerValidationEnabled = $null
    Assert-NoFinding (Get-TestFindings $e) 'PROFILE-SERVER-VALIDATION-DISABLED'
}
Test-Case 'each enterprise profile retains its server-validation concern' {
    $e = New-TestEvidence
    $e.Profiles += [pscustomobject]@{ Kind = 'Wireless'; InterfaceGuid = $script:GuidB; Name = 'fixture-second'; OneXEnabled = $true; AuthMode = 'machine'; EapTypes = @(25,26); ServerValidationEnabled = $false }
    Assert-HasFinding (Get-TestFindings $e) 'PROFILE-SERVER-VALIDATION-DISABLED'
}
Test-Case 'missing machine certificate with successful store enumeration' {
    $e = New-TestEvidence; $e.Certificates = @()
    Assert-HasFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'PEAP password profile does not require a client certificate' {
    $e = New-TestEvidence; $e.Certificates = @(); $e.Profiles[0].EapTypes = @(25,26)
    Assert-NoFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'current-user certificate does not satisfy a machine profile' {
    $e = New-TestEvidence; $e.Certificates = @(New-TestCertificate -Store CurrentUser)
    Assert-HasFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'machine certificate does not satisfy a user profile' {
    $e = New-TestEvidence; $e.Profiles[0].AuthMode = 'user'
    Assert-HasFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'user profile evaluates the execution-user store' {
    $e = New-TestEvidence; $e.Profiles[0].AuthMode = 'user'; $e.Certificates = @(New-TestCertificate -Store CurrentUser)
    Assert-NoFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'expired certificate alone is not a suitable candidate' {
    $e = New-TestEvidence; $e.Certificates = @(New-TestCertificate -ExpiresDays -1)
    Assert-HasFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'unrelated expired certificate does not invalidate a usable candidate' {
    $e = New-TestEvidence; $e.Certificates += New-TestCertificate -ExpiresDays -1
    $e.Certificates[1].Thumbprint = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
    Assert-NoFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'not-yet-valid certificate is not a suitable candidate' {
    $e = New-TestEvidence; $e.Certificates[0].NotBeforeUtc = $script:FixtureNow.AddDays(1).ToString('o')
    Assert-HasFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'certificate without private-key metadata is not a candidate' {
    $e = New-TestEvidence; $e.Certificates = @(New-TestCertificate -HasPrivateKey $false)
    Assert-HasFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'HasPrivateKey does not prove successful private-key use or EAP' {
    $e = New-TestEvidence
    $e.Certificates[0].HasPrivateKey = $true
    $f = Get-TestFindings $e
    $candidate = @($f | Where-Object { $_.Id -eq 'CERT-CANDIDATES-PRESENT' })
    Assert-Equal $candidate.Count 1 'Expected a structural candidate, not authentication proof.'
    Assert-True (($candidate[0].Limitations -join ' ') -match 'HasPrivateKey.*presence only') 'Key-presence limitation was lost.'
    Assert-True (($f.Summary -join ' ') -notmatch '(?i)(key (is )?usable|authentication (succeeded|verified))') 'Key metadata became a successful operation or authentication verdict.'
}
Test-Case 'absent EKU is eligible metadata rather than wrong EKU' {
    $e = New-TestEvidence; $e.Certificates = @(New-TestCertificate -EkuOids @() -Eligible $true)
    Assert-NoFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'explicit server-only EKU is not client-auth eligible' {
    $e = New-TestEvidence; $e.Certificates = @(New-TestCertificate -EkuOids @('1.3.6.1.5.5.7.3.1') -Eligible $false)
    Assert-HasFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'multi-EKU including client authentication remains eligible' {
    $e = New-TestEvidence; $e.Certificates = @(New-TestCertificate -EkuOids @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'))
    Assert-NoFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'unreadable certificate store is not evidence of certificate absence' {
    $e = New-TestEvidence; $e.Certificates = @(); $e.CertificateStores[0].Status = 'Failed'
    Assert-NoFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'truncated certificate store is not a complete absence proof' {
    $e = New-TestEvidence; $e.Certificates = @(); $e.CertificateStores[0].Truncated = $true
    Assert-NoFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'unevaluated chain is not reported as trusted or unrevoked' {
    $f = Get-TestFindings (New-TestEvidence)
    Assert-True (($f | ConvertTo-Json -Depth 20) -notmatch '(?i)chain (is |was )?(valid|trusted)|certificate (is |was )?unrevoked') 'Offline metadata is overstated as chain/revocation proof.'
}
Test-Case 'missing usable address on the relevant up adapter' {
    $e = New-TestEvidence; $e.IpConfiguration[0].IPv4Addresses = @()
    Assert-HasFinding (Get-TestFindings $e) 'IP-NO-USABLE-ADDRESS'
}
Test-Case 'APIPA-only address is not a usable enterprise address' {
    $e = New-TestEvidence; $e.IpConfiguration[0].IPv4Addresses[0].IPAddress = '169.254.10.20'
    Assert-HasFinding (Get-TestFindings $e) 'IP-NO-USABLE-ADDRESS'
}
Test-Case 'APIPA plus usable IPv6 does not become no usable address' {
    $e = New-TestEvidence; $e.IpConfiguration[0].IPv4Addresses[0].IPAddress = '169.254.10.20'; $e.IpConfiguration[0].IPv6Addresses = @([pscustomobject]@{ IPAddress = '2001:db8::10' })
    Assert-NoFinding (Get-TestFindings $e) 'IP-NO-USABLE-ADDRESS'
}
Test-Case 'link-local IPv6 alone does not prove a usable enterprise address' {
    $e = New-TestEvidence; $e.IpConfiguration[0].IPv4Addresses = @(); $e.IpConfiguration[0].IPv6Addresses = @([pscustomobject]@{ IPAddress = 'fe80::10' })
    Assert-HasFinding (Get-TestFindings $e) 'IP-NO-USABLE-ADDRESS'
}
Test-Case 'no DNS configuration is separate from authentication proof' {
    $e = New-TestEvidence; $e.IpConfiguration[0].DnsServers = @()
    $f = Get-TestFindings $e; Assert-HasFinding $f 'DNS-NO-SERVERS'
}
Test-Case 'unrelated usable VPN does not conceal relevant adapter IP failure' {
    $e = New-TestEvidence; $e.IpConfiguration[0].IPv4Addresses = @()
    $e.Interfaces += [pscustomobject]@{ InterfaceIndex = 20; InterfaceGuid = $script:GuidB; Alias = 'fixture-vpn'; Status = 'Up'; PhysicalMediaType = 0 }
    $e.IpConfiguration += [pscustomobject]@{ InterfaceIndex = 20; IPv4Addresses = @([pscustomobject]@{ IPAddress = '198.51.100.10' }); IPv6Addresses = @(); IPv4DefaultGateway = @(); IPv6DefaultGateway = @(); DnsServers = @('198.51.100.53') }
    Assert-HasFinding (Get-TestFindings $e) 'IP-NO-USABLE-ADDRESS'
}
Test-Case 'failed collection is not equivalent to an empty successful query' {
    $e = New-TestEvidence; $e.Probes[0].Status = 'Failed'
    $f = Get-TestFindings $e; Assert-HasFinding $f 'COLLECTION-INCOMPLETE'
}
Test-Case 'timed-out collection remains incomplete' {
    $e = New-TestEvidence; $e.Probes[0].Status = 'TimedOut'
    Assert-HasFinding (Get-TestFindings $e) 'COLLECTION-INCOMPLETE'
}
Test-Case 'partially collected evidence remains incomplete' {
    $e = New-TestEvidence; $e.Probes[0].Status = 'Partial'
    Assert-HasFinding (Get-TestFindings $e) 'COLLECTION-INCOMPLETE'
}
Test-Case 'unreadable logs cannot establish authentication proof' {
    $e = New-TestEvidence; $e.Probes = @([pscustomobject]@{ Name = 'Events'; Status = 'Failed'; DurationMs = 1; Limitations = @('Synthetic access denial.') })
    $e.EventLogs = @([pscustomobject]@{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; Status = 'Failed' })
    $f = Get-TestFindings $e; Assert-HasFinding $f 'COLLECTION-INCOMPLETE'
}
Test-Case 'profile credential-like extra fields do not enter finding output' {
    $e = New-TestEvidence; $e.Profiles[0].ServerValidationEnabled = $false
    $e.Profiles[0] | Add-Member NoteProperty RawXml '<keyMaterial>fixture-sensitive-DO-NOT-EMIT</keyMaterial>'
    $e.Profiles[0] | Add-Member NoteProperty Password 'fixture-sensitive-DO-NOT-EMIT'
    $json = (Get-TestFindings $e) | ConvertTo-Json -Depth 20
    Assert-True ($json -notmatch 'fixture-sensitive-DO-NOT-EMIT|keyMaterial|RawXml') 'Finding output leaked non-allowlisted profile data.'
}
function New-TestEvent {
    param([string]$Provider = 'Microsoft-Windows-WLAN-AutoConfig', [int]$Id = 12013,
          [int]$MinutesAgo = 30, [string]$Guid = $script:GuidA, [int]$Level = 2,
          [string]$Profile = 'fixture-profile')
    [pscustomobject]@{
        ProviderName = $Provider; LogName = ($Provider + '/Operational'); Id = $Id; Level = $Level
        TimeCreatedUtc = $script:FixtureNow.AddMinutes(-$MinutesAgo).ToString('o')
        RecordId = (1000 + $MinutesAgo); InterfaceGuid = $Guid
        Fields = [pscustomobject]@{ ReasonCode = '0x00050005'; ProfileName = $Profile }
    }
}
Test-Case 'empty evidence has an explicit empty-evidence finding' {
    Assert-HasFinding (Get-TestFindings ([pscustomobject]@{})) 'EVIDENCE-EMPTY'
    Assert-NoFinding (Get-TestFindings (New-TestEvidence)) 'EVIDENCE-EMPTY'
}
Test-Case 'missing scoped interface is not silently an all-clear' {
    $e = New-TestEvidence; $e.Collection | Add-Member NoteProperty InterfaceAlias 'fixture-missing'
    Assert-HasFinding (Get-TestFindings $e) 'TARGET-NOT-FOUND'
}
Test-Case 'matching scoped interface is not reported absent' {
    $e = New-TestEvidence; $e.Collection | Add-Member NoteProperty InterfaceAlias 'fixture-wireless'
    Assert-NoFinding (Get-TestFindings $e) 'TARGET-NOT-FOUND'
}
Test-Case 'near-expiry concern requires all usable candidates to expire soon' {
    $e = New-TestEvidence; $e.Certificates = @(New-TestCertificate -ExpiresDays 10)
    Assert-HasFinding (Get-TestFindings $e) 'CERT-CANDIDATES-EXPIRING'
    $e.Certificates += New-TestCertificate -ExpiresDays 90
    Assert-NoFinding (Get-TestFindings $e) 'CERT-CANDIDATES-EXPIRING'
}
Test-Case 'candidate-present finding has a negative missing-candidate control' {
    Assert-HasFinding (Get-TestFindings (New-TestEvidence)) 'CERT-CANDIDATES-PRESENT'
    $e = New-TestEvidence; $e.Certificates = @()
    Assert-NoFinding (Get-TestFindings $e) 'CERT-CANDIDATES-PRESENT'
}
Test-Case 'execution-user store limitation remains explicit under system context' {
    $e = New-TestEvidence; $e.Collection.ExecutionUser = 'NT AUTHORITY\SYSTEM'; $e.Profiles[0].AuthMode = 'user'; $e.Certificates = @()
    $f = Get-TestFindings $e
    $certFinding = @($f | Where-Object { $_.Id -eq 'CERT-NO-SUITABLE-CANDIDATE' })
    Assert-Equal $certFinding.Count 1 'Expected a scoped candidate assessment.'
    Assert-True (($certFinding[0].Limitations -join ' ') -match '(?i)CurrentUser.*(collector|execution).*(affected|user)') 'CurrentUser conclusion was not scoped to the execution identity.'
}
Test-Case 'known WLAN failure event is historical evidence' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -Provider 'Microsoft-Windows-WLAN-AutoConfig' -Id 12013)
    Assert-HasFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
}
Test-Case 'event ID collision under another provider has no auth interpretation' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -Provider 'Fixture-Other-Provider' -Id 12013)
    Assert-NoFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
}
Test-Case 'wireless failure ID is not inherited by wired provider' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 12013)
    Assert-NoFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
}
Test-Case 'localized event messages do not change numeric provider interpretation' {
    $a = New-TestEvidence; $a.Events = @(New-TestEvent)
    $a.Events[0] | Add-Member NoteProperty Message 'Authentication failed. Synthetic message.'
    $b = New-TestEvidence; $b.Events = @(New-TestEvent)
    $b.Events[0] | Add-Member NoteProperty Message 'Authentifizierung fehlgeschlagen. Synthetische Nachricht.'
    Assert-Equal ((Get-TestFindings $a | ForEach-Object { $_.Id }) -join ',') ((Get-TestFindings $b | ForEach-Object { $_.Id }) -join ',') 'Localized message changed event interpretation.'
}
Test-Case 'event outside the lookback window is excluded' {
    $e = New-TestEvidence; $e.Collection | Add-Member NoteProperty LookbackHours 24
    $e.Events = @(New-TestEvent -MinutesAgo 1441)
    Assert-NoFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
    $e.Events = @(New-TestEvent -MinutesAgo 1439)
    Assert-HasFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
}
Test-Case 'future event is not snapshot evidence' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -MinutesAgo -1)
    Assert-NoFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
}
Test-Case 'interface scope does not inherit another adapter failure' {
    $e = New-TestEvidence; $e.Collection | Add-Member NoteProperty InterfaceAlias 'fixture-wireless'; $e.Events = @(New-TestEvent -Guid $script:GuidB)
    Assert-NoFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
}
Test-Case 'profile scope does not inherit another profile failure' {
    $e = New-TestEvidence; $e.Collection | Add-Member NoteProperty ProfileName 'fixture-profile'; $e.Events = @(New-TestEvent -Profile 'fixture-other')
    Assert-NoFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
}
Test-Case 'historical failure followed by success is not called a current failure' {
    $e = New-TestEvidence; $e.IpConfiguration[0].IPv4Addresses = @()
    $e.Events = @((New-TestEvent -Id 12013 -MinutesAgo 60), (New-TestEvent -Id 12012 -MinutesAgo 10))
    $f = Get-TestFindings $e
    Assert-HasFinding $f 'AUTH-HISTORICAL-FAILURE'
    $ip = @($f | Where-Object { $_.Id -eq 'IP-NO-USABLE-ADDRESS' })
    Assert-Equal $ip[0].AuthenticationContext.Outcome 'Success' 'Current context used the older failure rather than later success.'
    Assert-Equal $ip[0].AuthenticationContext.IsHistorical $true 'A historical success became current authorization.'
}
Test-Case 'success on another adapter does not supersede this adapter history' {
    $e = New-TestEvidence; $e.IpConfiguration[0].IPv4Addresses = @()
    $e.Events = @((New-TestEvent -Id 12013 -MinutesAgo 60 -Guid $script:GuidA), (New-TestEvent -Id 12012 -MinutesAgo 10 -Guid $script:GuidB))
    $f = Get-TestFindings $e; $ip = @($f | Where-Object { $_.Id -eq 'IP-NO-USABLE-ADDRESS' })
    Assert-Equal $ip[0].AuthenticationContext.Outcome 'Failure' 'Another adapter success concealed the matching failure history.'
    Assert-Equal $ip[0].AuthenticationContext.InterfaceGuid $script:GuidA 'History was attributed to another adapter.'
}
Test-Case 'known TLS supporting provider warning remains correlation-only' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -Provider 'Microsoft-Windows-EapHost' -Id 2002)
    $f = Get-TestFindings $e; Assert-HasFinding $f 'TLS-EAP-SUPPORTING-HISTORY'
}
Test-Case 'lookalike TLS provider name does not inherit provider meaning' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -Provider 'Fixture-Unrelated-EapHost' -Id 2002)
    Assert-NoFinding (Get-TestFindings $e) 'TLS-EAP-SUPPORTING-HISTORY'
}
Test-Case 'informational TLS supporting event is not treated as warning history' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -Provider 'Microsoft-Windows-EapHost' -Id 2002 -Level 4)
    Assert-NoFinding (Get-TestFindings $e) 'TLS-EAP-SUPPORTING-HISTORY'
}
Test-Case 'NTLM reason context is provider-scoped and does not prove EAP failure' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -Provider 'Microsoft-Windows-NTLM' -Id 4013)
    $f = Get-TestFindings $e; Assert-HasFinding $f 'NTLM-CREDENTIAL-GUARD-CONTEXT'
    $e.Events[0].ProviderName = 'Fixture-Other-Provider'
    Assert-NoFinding (Get-TestFindings $e) 'NTLM-CREDENTIAL-GUARD-CONTEXT'
}
Test-Case 'unavailable WLAN connection query is not proof of disconnection' {
    $e = New-TestEvidence; $e.Wireless[0] | Add-Member NoteProperty ConnectionQueryCode 5
    Assert-HasFinding (Get-TestFindings $e) 'WLAN-CURRENT-STATE-UNAVAILABLE'
    $e.Wireless[0].ConnectionQueryCode = 0
    Assert-NoFinding (Get-TestFindings $e) 'WLAN-CURRENT-STATE-UNAVAILABLE'
}

Test-Case 'wired adapter-connected event is not authentication success' {
    $e = New-TestEvidence; $e.IpConfiguration[0].IPv4Addresses = @()
    $e.Events = @(New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15501)
    $f = Get-TestFindings $e; $ip = @($f | Where-Object { $_.Id -eq 'IP-NO-USABLE-ADDRESS' })
    Assert-True ($null -eq $ip[0].AuthenticationContext) 'Adapter-connected event was interpreted as authentication success.'
}
Test-Case 'wired profile-applied event is not authentication failure' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15502)
    Assert-NoFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
}

Test-Case 'verified wired authentication failure is historical evidence' {
    $e = New-TestEvidence; $e.Events = @(New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15514)
    Assert-HasFinding (Get-TestFindings $e) 'AUTH-HISTORICAL-FAILURE'
}
Test-Case 'verified wired authentication success supplies historical context only' {
    $e = New-TestEvidence; $e.IpConfiguration[0].IPv4Addresses = @()
    $e.Events = @(New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15505)
    $f = Get-TestFindings $e; $ip = @($f | Where-Object { $_.Id -eq 'IP-NO-USABLE-ADDRESS' })
    Assert-Equal $ip[0].AuthenticationContext.Outcome 'Success' 'Verified wired success was not recognized as historical context.'
    Assert-Equal $ip[0].AuthenticationContext.IsHistorical $true 'Wired history became current authorization.'
    Assert-NoFinding $f 'AUTH-HISTORICAL-FAILURE'
}

Test-Case 'absent normalized EKU flag still treats absent EKU as unrestricted metadata' {
    $e = New-TestEvidence; $e.Certificates = @(New-TestCertificate -EkuOids @())
    $e.Certificates[0].PSObject.Properties.Remove('ClientAuthEkuEligible')
    Assert-NoFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'raw wrong EKU without a normalized flag remains ineligible' {
    $e = New-TestEvidence; $e.Certificates = @(New-TestCertificate -EkuOids @('1.3.6.1.5.5.7.3.3') -Eligible $false)
    $e.Certificates[0].PSObject.Properties.Remove('ClientAuthEkuEligible')
    Assert-HasFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}
Test-Case 'unrelated code-signing certificate does not invalidate a usable client candidate' {
    $e = New-TestEvidence; $e.Certificates += New-TestCertificate -EkuOids @('1.3.6.1.5.5.7.3.3') -Eligible $false
    Assert-NoFinding (Get-TestFindings $e) 'CERT-NO-SUITABLE-CANDIDATE'
}

Test-Case 'targeted WLAN service clue survives unavailable profile collection' {
    $e=New-TestEvidence; $e.Profiles=@(); $e.Services[0].Status='Stopped'; $e.Interfaces[0].PhysicalMediaType='Native 802.11'
    $e.Collection|Add-Member NoteProperty InterfaceAlias 'fixture-wireless'
    $e.Probes=@([pscustomobject]@{Name='Wireless';Status='Failed';DurationMs=1;Limitations=@('Synthetic unavailable profile query.')})
    $f=Get-TestFindings $e; $service=@($f|Where-Object{$_.Id -eq 'SERVICE-WLAN-NOT-RUNNING'})
    Assert-Equal $service.Count 1 'Targeted service dependency was hidden by failed profile collection.'
    Assert-Equal $service[0].Severity 'Information' 'Indicated service relevance was overstated as a proven cause.'
}
Test-Case 'targeted wired service clue does not require a readable profile' {
    $e=New-TestEvidence; $e.Profiles=@(); $e.Services[1].Status='Stopped'; $e.Interfaces[0].PhysicalMediaType='802.3'
    $e.Collection|Add-Member NoteProperty InterfaceAlias 'fixture-wireless'
    $e.Probes=@([pscustomobject]@{Name='Wired';Status='Failed';DurationMs=1;Limitations=@('Synthetic unavailable profile query.')})
    Assert-HasFinding (Get-TestFindings $e) 'SERVICE-WIRED-NOT-RUNNING'
}
Test-Case 'targeted inactive adapter reports only its local link fact' {
    foreach($status in @('Disabled','Disconnected','NotPresent')){
        $e=New-TestEvidence;$e.Interfaces[0].Status=$status;$e.Collection|Add-Member NoteProperty InterfaceAlias 'fixture-wireless'
        $f=Get-TestFindings $e;Assert-HasFinding $f 'TARGET-INTERFACE-NOT-UP'
    }
}
Test-Case 'an unrelated disabled adapter is not a targeted link failure' {
    $e=New-TestEvidence;$e.Collection|Add-Member NoteProperty InterfaceAlias 'fixture-wireless'
    $e.Interfaces+=[pscustomobject]@{InterfaceIndex=20;InterfaceGuid=$script:GuidB;Alias='fixture-unused';Status='Disabled';PhysicalMediaType='802.3'}
    Assert-NoFinding (Get-TestFindings $e) 'TARGET-INTERFACE-NOT-UP'
}
Test-Case 'complete profile queries permit only within-scope not-observed evidence' {
    $e=New-TestEvidence;$e.Collection|Add-Member NoteProperty ProfileName 'fixture-missing'
    $e.Probes=@([pscustomobject]@{Name='Wireless';Status='Succeeded';DurationMs=1;Limitations=@()},[pscustomobject]@{Name='Wired';Status='Succeeded';DurationMs=1;Limitations=@()})
    $f=Get-TestFindings $e;$missing=@($f|Where-Object{$_.Id -eq 'PROFILE-NOT-OBSERVED'})
    Assert-Equal $missing.Count 1 'Missing requested profile was silently ignored.'
    Assert-Equal $missing[0].Confidence 'Medium' 'Completed profile coverage did not retain its limited scope.'
}
Test-Case 'failed partial or skipped profile query cannot establish absence' {
    foreach($status in @('Failed','Partial','Skipped')){
        $e=New-TestEvidence;$e.Collection|Add-Member NoteProperty ProfileName 'fixture-missing'
        $e.Probes=@([pscustomobject]@{Name='Wireless';Status='Succeeded';DurationMs=1;Limitations=@()},[pscustomobject]@{Name='Wired';Status=$status;DurationMs=1;Limitations=@('Synthetic visibility limit.')})
        $missing=@((Get-TestFindings $e)|Where-Object{$_.Id -eq 'PROFILE-NOT-OBSERVED'})
        Assert-Equal $missing.Count 1 'Unavailable requested-profile evidence was silently ignored.'
        Assert-Equal $missing[0].Confidence 'Low' 'Incomplete profile visibility was overstated as absence.'
    }
}
Test-Case 'observed requested profile is not reported missing' {
    $e=New-TestEvidence;$e.Collection|Add-Member NoteProperty ProfileName 'fixture-profile'
    Assert-NoFinding (Get-TestFindings $e) 'PROFILE-NOT-OBSERVED'
}
Test-Case 'wired failure HRESULT names an untrusted root' {
    $e = New-TestEvidence
    $ev = New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15514
    $ev.Fields = [pscustomobject]@{ ReasonCode = '0x50005'; ErrorCode = '0x800b0109' }
    $e.Events = @($ev)
    $f = @(Get-TestFindings $e | Where-Object { $_.Id -eq 'AUTH-HISTORICAL-FAILURE' })
    Assert-Equal $f.Count 1 'Expected one historical failure finding.'
    Assert-True ($f[0].Summary -match 'CERT_E_UNTRUSTEDROOT') 'Untrusted-root HRESULT was not named.'
    Assert-True ($f[0].Summary -match 'ONEX_EAP_FAILURE_RECEIVED') 'ONEX EAP failure reason was not named.'
    Assert-True ($f[0].Summary -notmatch '(?i)RADIUS policy') 'Summary claimed a RADIUS policy verdict.'
}
Test-Case 'revocation-offline HRESULT is named without claiming current revocation' {
    $e = New-TestEvidence
    $ev = New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15514
    $ev.Fields = [pscustomobject]@{ ReasonCode = '0x50005'; ErrorCode = '0x80092013' }
    $e.Events = @($ev)
    $summary = @((Get-TestFindings $e | Where-Object { $_.Id -eq 'AUTH-HISTORICAL-FAILURE' }).Summary) -join ' '
    Assert-True ($summary -match 'CRYPT_E_REVOCATION_OFFLINE') 'Revocation-offline HRESULT was not named.'
    Assert-True ($summary -match '(?i)timed out|unreachable') 'Revocation-offline meaning was omitted.'
}
Test-Case 'unknown HRESULT stays unmapped' {
    $e = New-TestEvidence
    $ev = New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15514
    $ev.Fields = [pscustomobject]@{ ErrorCode = '0xDEADBEEF' }
    $e.Events = @($ev)
    $summary = @((Get-TestFindings $e | Where-Object { $_.Id -eq 'AUTH-HISTORICAL-FAILURE' }).Summary) -join ' '
    Assert-True ($summary -match '0xDEADBEEF') 'Unknown HRESULT was dropped.'
    Assert-True ($summary -match 'unmapped') 'Unknown HRESULT was treated as a named diagnosis.'
    Assert-True ($summary -notmatch 'CERT_E_|CRYPT_E_|SEC_E_') 'Unknown HRESULT was mapped to a named constant.'
}
Test-Case 'high-bit HRESULT literals still match CERT_E_UNTRUSTEDROOT' {
    Assert-True ((Get-Dot1xHresultLabel ([Convert]::ToUInt32('800B0109',16))) -match 'CERT_E_UNTRUSTEDROOT') '0x800B0109 did not decode.'
    Assert-True ((Get-Dot1xHresultLabel ([Convert]::ToUInt32('80092013',16))) -match 'CRYPT_E_REVOCATION_OFFLINE') '0x80092013 did not decode.'
}
Test-Case 'name-constraint credential and identity codes retain distinct reference labels' {
    $e = New-TestEvidence
    $name = New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15514
    $name.Fields = [pscustomobject]@{ ErrorCode = '0x800b0114' }
    $cred = New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15514 -MinutesAgo 20
    $cred.Fields = [pscustomobject]@{ ErrorCode = '0x2b3' }
    $identityFailure = New-TestEvent -Provider 'Microsoft-Windows-Wired-AutoConfig' -Id 15514 -MinutesAgo 10
    $identityFailure.Fields = [pscustomobject]@{ ErrorCode = '0x80420014' }
    $e.Events = @($name,$cred,$identityFailure)
    $text = @((Get-TestFindings $e | Where-Object { $_.Id -eq 'AUTH-HISTORICAL-FAILURE' }).Summary) -join ' | '
    Assert-True ($text -match 'CERT_E_INVALID_NAME') 'Certificate name-constraint HRESULT was not named.'
    Assert-True ($text -match 'ERROR_AUTHENTICATION_FAILURE') 'RAS credential error 691 was not named.'
    Assert-True ($text -match 'EAP_E_EAPHOST_IDENTITY_UNKNOWN') 'EAP peer-identity failure was not named.'
    Assert-True ($text -notmatch 'EAP_E_USER_CERT_NOT_FOUND|no certificate could be found') 'Identity failure was relabeled as certificate absence.'
}

Complete-Tests

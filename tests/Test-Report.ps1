#requires -Version 5.1
<#
.SYNOPSIS
Checks report selection, grouping, and formatting with synthetic evidence only.
#>
[CmdletBinding()]
param([string]$ScriptPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. $ScriptPath
$script:ReportPassed = 0
$script:ReportFailed = New-Object 'System.Collections.Generic.List[string]'
$script:ReportAssertions = 0
function Assert-Report {
    param([bool]$Condition, [string]$Message)
    $script:ReportAssertions++
    if (-not $Condition) { throw $Message }
}
function Test-ReportCase {
    param([string]$Name, [scriptblock]$Body)
    $before = $script:ReportAssertions
    try {
        & $Body
        if ($script:ReportAssertions -eq $before) { throw 'Test made no assertion.' }
        $script:ReportPassed++
        Write-Output ('PASS ' + $Name)
    } catch {
        $script:ReportFailed.Add($Name)
        Write-Output ('FAIL ' + $Name + ': ' + $_.Exception.Message)
    }
}
function New-ReportFixture {
    [pscustomobject]@{
        SchemaVersion=1; CapturedAtUtc='2026-09-07T19:00:00Z'
        Collection=[pscustomobject]@{ InterfaceAlias='Ethernet'; ProfileName=''; LookbackHours=24; Limitations=@('GLOBAL-BOILERPLATE-SENTINEL') }
        Interfaces=@([pscustomobject]@{ Alias='Ethernet'; InterfaceIndex=1; InterfaceGuid='11111111-1111-1111-1111-111111111111'; Status='Up'; PhysicalMediaType='802.3'; MediaType='802.3'; HardwareInterface=$true; Virtual=$false })
        Profiles=@([pscustomobject]@{ Name='Corp'; Kind='Wired'; InterfaceGuid='11111111-1111-1111-1111-111111111111'; OneXEnabled=$true; AuthMode='machine'; EapTypes=@(25,26); ServerValidationEnabled=$true })
        Services=@([pscustomobject]@{ Name='dot3svc'; Status='Running'; StartMode='Auto' },[pscustomobject]@{ Name='EapHost'; Status='Stopped'; StartMode='Manual' })
        IpConfiguration=@([pscustomobject]@{ InterfaceIndex=1; IPv4Addresses=@([pscustomobject]@{ IPAddress='192.0.2.10'; AddressState='Preferred' }); IPv6Addresses=@(); DnsServers=@('192.0.2.53') })
        Wireless=@(); Wired=@(); Certificates=@()
        CertificateStores=@([pscustomobject]@{ Store='LocalMachine'; Status='Succeeded'; Truncated=$false },[pscustomobject]@{ Store='CurrentUser'; Status='Succeeded'; Truncated=$false })
        Events=@(); EventLogs=@()
        Probes=@([pscustomobject]@{ Name='Interfaces'; Status='Succeeded'; DurationMs=12345; CleanupConfirmed=$true; Limitations=@() })
    }
}
function New-ReportEvent {
    param([string]$Code='0x800B0109', [int]$Id=15514, [string]$Time='2026-09-07T18:00:00Z',
        [string]$Guid='11111111-1111-1111-1111-111111111111', [string]$Profile='Corp',
        [string]$Mode='machine', [string]$Connection='session-1', [int]$Version=0)
    [pscustomobject]@{
        ProviderName='Microsoft-Windows-Wired-AutoConfig'; Id=$Id; Version=$Version; Level=2
        TimeCreatedUtc=$Time; RecordId=1; InterfaceGuid=$Guid
        Fields=[pscustomobject]@{ ProfileName=$Profile; AuthMode=$Mode; ConnectionId=$Connection; ErrorCode=$Code }
    }
}
function New-ReportObject {
    param($Evidence)
    [pscustomobject]@{ SchemaVersion=1; CapturedAtUtc=$Evidence.CapturedAtUtc; Collection=$Evidence.Collection;
        Probes=@($Evidence.Probes); Findings=@(Get-Dot1xDiagnosis -Evidence $Evidence) }
}
function Get-FixtureHistory {
    param($Evidence)
    @(Get-Dot1xReportHistory -Evidence $Evidence -Scope (Get-Dot1xReportScope $Evidence))
}
function New-ReportCertificate {
    [pscustomobject]@{
        Store='LocalMachine'; Thumbprint='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        NotBeforeUtc='2026-01-01T00:00:00Z'; NotAfterUtc='2027-09-01T00:00:00Z'
        HasPrivateKey=$true; ClientAuthEkuEligible=$true; EkuOids=@('1.3.6.1.5.5.7.3.2')
        Chain=[pscustomobject]@{ Assessment='NoErrorsInCachedAssessment'; TrustErrorMask='0x00000000'; Status=@() }
    }
}

Test-ReportCase 'empty evidence does not become a clean report' {
    $e=New-ReportFixture; $e.Interfaces=@(); $e.Profiles=@(); $e.Probes=@()
    $text=Format-Dot1xReport -Report (New-ReportObject $e) -Evidence $e
    Assert-Report ($text -match 'Not enough|Target interface not observed') 'Empty scope was not explained.'
    Assert-Report ($text -notmatch 'No issues identified') 'Empty evidence became a clean report.'
}
Test-ReportCase 'default output hides successful probe details and boilerplate' {
    $e=New-ReportFixture; $text=Format-Dot1xReport -Report (New-ReportObject $e) -Evidence $e
    Assert-Report ($text -notmatch 'confidence=|12345 ms|GLOBAL-BOILERPLATE-SENTINEL|Next step \(not executed\)') 'Default contains internal report detail.'
    Assert-Report ($text -match 'Ethernet|Corp') 'Configuration was omitted.'
    Assert-Report ($text -match 'No matching authentication outcomes in the collected history') 'Absent history was not scoped.'
}
Test-ReportCase 'detailed mode retains finding IDs and collector diagnostics' {
    $e=New-ReportFixture; $e.Services[0].Status='Stopped'; $r=New-ReportObject $e
    $text=Format-Dot1xReport -Report $r -Evidence $e -Detailed
    Assert-Report ($text -match 'SERVICE-WIRED-NOT-RUNNING') 'Detailed rule ID missing.'
    Assert-Report ($text -match 'GLOBAL-BOILERPLATE-SENTINEL') 'Detailed collection limitations missing.'
    Assert-Report ($text -match '12345 ms') 'Detailed probe timing missing.'
}
Test-ReportCase 'formatting does not mutate evidence or full findings' {
    $e=New-ReportFixture; $e.Events=@(New-ReportEvent); $r=New-ReportObject $e
    $beforeE=$e|ConvertTo-Json -Depth 30 -Compress; $beforeR=$r|ConvertTo-Json -Depth 30 -Compress
    $null=Format-Dot1xReport -Report $r -Evidence $e
    $null=Format-Dot1xReport -Report $r -Evidence $e -Detailed
    Assert-Report (($e|ConvertTo-Json -Depth 30 -Compress) -ceq $beforeE) 'Evidence was mutated.'
    Assert-Report (($r|ConvertTo-Json -Depth 30 -Compress) -ceq $beforeR) 'Full report was mutated.'
}
Test-ReportCase 'two hundred repeated failures form one history group' {
    $e=New-ReportFixture; $e.Events=@(1..200|ForEach-Object { New-ReportEvent })
    $h=@(Get-FixtureHistory $e)
    Assert-Report ($h.Count -eq 1 -and $h[0].Count -eq 200) 'Repeated failures were not grouped.'
    $text=Format-Dot1xReport -Report (New-ReportObject $e) -Evidence $e
    Assert-Report (([regex]::Matches($text,'Next:')).Count -eq 1) 'Repair advice was repeated for each event.'
    Assert-Report ($text.Length -lt 2500) 'Repeated failures produce an unbounded default report.'
}
Test-ReportCase 'a later same-context success is shown without a current-success verdict' {
    $e=New-ReportFixture; $e.Events=@((New-ReportEvent),(New-ReportEvent -Id 15505 -Code '' -Time '2026-09-07T18:30:00Z'))
    $h=@(Get-FixtureHistory $e|Where-Object {$_.Outcome -eq 'Failure'})
    Assert-Report ($h[0].LaterSuccessUtc -eq '2026-09-07 18:30:00') 'Later same-context success missing.'
    $text=Format-Dot1xReport -Report (New-ReportObject $e) -Evidence $e
    Assert-Report ($text -match 'Later same-context success recorded') 'Success was not presented.'
    Assert-Report ($text -notmatch 'currently authenticated|authentication verified|then reconnect') 'Historical success was overstated.'
    Assert-Report ($text -notmatch '1 success event\(s\)') 'Linked success was printed twice.'
}
Test-ReportCase 'success on another adapter does not supersede a failure' {
    $e=New-ReportFixture; $e.Collection.InterfaceAlias=''
    $e.Events=@((New-ReportEvent),(New-ReportEvent -Id 15505 -Time '2026-09-07T18:30:00Z' -Guid '22222222-2222-2222-2222-222222222222'))
    $h=@(Get-FixtureHistory $e|Where-Object {$_.Outcome -eq 'Failure'})
    Assert-Report (-not $h[0].LaterSuccessUtc) 'Another adapter supplied recovery evidence.'
}
Test-ReportCase 'success on another profile does not supersede a failure' {
    $e=New-ReportFixture; $e.Events=@((New-ReportEvent),(New-ReportEvent -Id 15505 -Time '2026-09-07T18:30:00Z' -Profile 'Other'))
    $h=@(Get-FixtureHistory $e|Where-Object {$_.Outcome -eq 'Failure'})
    Assert-Report (-not $h[0].LaterSuccessUtc) 'Another profile supplied recovery evidence.'
}
Test-ReportCase 'user and machine authentication contexts stay separate' {
    $e=New-ReportFixture; $e.Events=@((New-ReportEvent),(New-ReportEvent -Id 15505 -Time '2026-09-07T18:30:00Z' -Mode 'user'))
    $h=@(Get-FixtureHistory $e|Where-Object {$_.Outcome -eq 'Failure'})
    Assert-Report (-not $h[0].LaterSuccessUtc) 'User success concealed machine failure history.'
}
Test-ReportCase 'different connection IDs are not treated as the same context' {
    $e=New-ReportFixture; $e.Events=@((New-ReportEvent),(New-ReportEvent -Id 15505 -Time '2026-09-07T18:30:00Z' -Connection 'session-2'))
    $h=@(Get-FixtureHistory $e|Where-Object {$_.Outcome -eq 'Failure'})
    Assert-Report (-not $h[0].LaterSuccessUtc) 'Another connection supplied recovery evidence.'
}
Test-ReportCase 'missing identity context does not manufacture recovery' {
    $e=New-ReportFixture; $e.Events=@((New-ReportEvent -Mode '' -Connection ''),(New-ReportEvent -Mode '' -Connection '' -Id 15505 -Time '2026-09-07T18:30:00Z'))
    $h=@(Get-FixtureHistory $e|Where-Object {$_.Outcome -eq 'Failure'})
    Assert-Report (-not $h[0].ContextKnown -and -not $h[0].LaterSuccessUtc) 'Unknown context became a matched recovery.'
}
Test-ReportCase 'unassigned interface records are not merged' {
    $e=New-ReportFixture; $e.Collection.InterfaceAlias=''; $e.Events=@((New-ReportEvent -Guid ''),(New-ReportEvent -Guid ''))
    Assert-Report (@(Get-FixtureHistory $e).Count -eq 2) 'Unassigned interfaces were grouped as one connection.'
}
Test-ReportCase 'different error codes and event versions remain separate' {
    $e=New-ReportFixture; $e.Events=@((New-ReportEvent),(New-ReportEvent -Code '0x80092013'),(New-ReportEvent -Version 2))
    Assert-Report (@(Get-FixtureHistory $e).Count -eq 3) 'Distinct codes or versions were merged.'
}
Test-ReportCase 'hex signed and unsigned forms group by normalized code' {
    $e=New-ReportFixture
    $u=[Convert]::ToUInt32('800B0109',16); $signed=[BitConverter]::ToInt32([BitConverter]::GetBytes($u),0)
    $e.Events=@((New-ReportEvent),(New-ReportEvent -Code $u.ToString()),(New-ReportEvent -Code $signed.ToString()))
    $h=@(Get-FixtureHistory $e)
    Assert-Report ($h.Count -eq 1 -and $h[0].Count -eq 3) 'Equivalent numeric codes were split.'
}
Test-ReportCase 'interface and profile filters apply before grouping' {
    $e=New-ReportFixture; $e.Collection.ProfileName='Corp'
    $e.Events=@((New-ReportEvent),(New-ReportEvent -Guid '22222222-2222-2222-2222-222222222222'),(New-ReportEvent -Profile 'Other'))
    $h=@(Get-FixtureHistory $e)
    Assert-Report ($h.Count -eq 1 -and $h[0].Count -eq 1) 'Target filters leaked another connection.'
}
Test-ReportCase 'time window excludes old and future outcomes' {
    $e=New-ReportFixture; $e.Events=@((New-ReportEvent),(New-ReportEvent -Time '2026-09-05T18:00:00Z'),(New-ReportEvent -Time '2026-09-07T20:00:00Z'))
    $h=@(Get-FixtureHistory $e)
    Assert-Report ($h.Count -eq 1 -and $h[0].Count -eq 1) 'Time bounds were lost.'
}
Test-ReportCase 'timezone offsets are compared as instants' {
    $e=New-ReportFixture; $e.Events=@((New-ReportEvent -Time '2026-09-07T19:00:00+02:00'),(New-ReportEvent -Id 15505 -Time '2026-09-07T17:30:00Z'))
    $h=@(Get-FixtureHistory $e|Where-Object {$_.Outcome -eq 'Failure'})
    Assert-Report ($h[0].FirstUtc -eq '2026-09-07 17:00:00' -and $h[0].LaterSuccessUtc -eq '2026-09-07 17:30:00') 'Offset handling changed chronology.'
}
Test-ReportCase 'an event without a usable timestamp remains explicitly uncorrelated' {
    $e=New-ReportFixture; $e.Events=@(New-ReportEvent -Time 'invalid')
    $h=@(Get-FixtureHistory $e)
    Assert-Report ($h.Count -eq 1 -and $h[0].LastUtc -eq 'time not recorded') 'An undated event disappeared.'
    Assert-Report (-not $h[0].ContextKnown -and -not $h[0].LaterSuccessUtc) 'An undated event established a timeline.'
}
Test-ReportCase 'numeric interpretations remain possible meanings not verdicts' {
    $e=New-ReportFixture; $e.Events=@(New-ReportEvent)
    $text=Format-Dot1xReport -Report (New-ReportObject $e) -Evidence $e
    Assert-Report ($text -match 'Possible meaning \(numeric match\)') 'Unverified code was presented as a verdict.'
    Assert-Report ($text -match 'CERT_E_UNTRUSTEDROOT') 'Useful candidate interpretation was lost.'
}
Test-ReportCase 'unknown codes remain visible without a fabricated interpretation' {
    $e=New-ReportFixture; $e.Events=@(New-ReportEvent -Code '0xDEADBEEF')
    $h=@(Get-FixtureHistory $e)
    Assert-Report (($h[0].Codes -join ' ') -match '0xDEADBEEF') 'Unknown code was dropped.'
    Assert-Report ($h[0].PossibleMeanings.Count -eq 0) 'Unknown code acquired an interpretation.'
}
Test-ReportCase 'routine certificate candidates become a configuration summary' {
    $e=New-ReportFixture; $e.Profiles[0].EapTypes=@(13); $e.Certificates=@(New-ReportCertificate)
    $r=New-ReportObject $e; $view=New-Dot1xReportView -Report $r -Evidence $e
    Assert-Report ((@($view.Configuration)-join ' ') -match 'Certificate candidates.*1.*LocalMachine=1') 'Candidate summary missing.'
    Assert-Report (@($view.Issues|Where-Object {$_.Id -eq 'CERT-CANDIDATES-PRESENT'}).Count -eq 0) 'Routine candidates remain an issue card.'
    Assert-Report (@($r.Findings|Where-Object {$_.Id -eq 'CERT-CANDIDATES-PRESENT'}).Count -eq 1) 'Full candidate finding was deleted.'
}
Test-ReportCase 'candidate chain problems stay visible without claiming certificate selection' {
    $e=New-ReportFixture; $e.Profiles[0].EapTypes=@(13); $c=New-ReportCertificate
    $c.Chain.Assessment='CachedChainErrors'; $c.Chain.TrustErrorMask='0x00000020'; $c.Chain.Status=@('UntrustedRoot'); $e.Certificates=@($c)
    $view=New-Dot1xReportView -Report (New-ReportObject $e) -Evidence $e
    Assert-Report (($view.Configuration -join ' ') -match 'Cached chains: 1 with errors') 'Candidate chain concern was hidden.'
    Assert-Report (($view.Configuration -join ' ') -match 'selected certificate unknown') 'Candidate was treated as selected.'
}
Test-ReportCase 'missing certificate finding has scoped interpretation and next check' {
    $e=New-ReportFixture; $e.Profiles[0].EapTypes=@(13)
    $r=New-ReportObject $e; $view=New-Dot1xReportView -Report $r -Evidence $e
    $issue=@($view.Issues|Where-Object {$_.Id -eq 'CERT-NO-SUITABLE-CANDIDATE'})
    Assert-Report ($issue.Count -eq 1 -and $issue[0].Title -match 'Corp.*Ethernet') 'Scoped certificate finding missing.'
    Assert-Report ($issue[0].Meaning -match 'LocalMachine' -and $issue[0].NextCheck -match 'enrollment') 'Certificate check is not actionable.'
}
Test-ReportCase 'incomplete certificate enumeration remains a gap not absence' {
    $e=New-ReportFixture; $e.Profiles[0].EapTypes=@(13); $e.CertificateStores[0].Status='Failed'
    $e.Probes+= [pscustomobject]@{Name='CertificatesLocalMachine';Status='Failed';DurationMs=1;Limitations=@('Access denied.')}
    $view=New-Dot1xReportView -Report (New-ReportObject $e) -Evidence $e
    Assert-Report (@($view.Issues|Where-Object {$_.Id -eq 'CERT-NO-SUITABLE-CANDIDATE'}).Count -eq 0) 'Unreadable store was called empty.'
    Assert-Report (($view.Gaps -join ' ') -match 'Machine certificates.*candidate absence is unknown') 'Store collection gap missing.'
}
Test-ReportCase 'informational target-not-found finding is not filtered by severity' {
    $e=New-ReportFixture; $e.Collection.InterfaceAlias='Missing'
    $view=New-Dot1xReportView -Report (New-ReportObject $e) -Evidence $e
    Assert-Report (@($view.Issues|Where-Object {$_.Id -eq 'TARGET-NOT-FOUND'}).Count -eq 1) 'Informational target failure was hidden.'
}
Test-ReportCase 'unrelated VPN address notices stay out of the default view' {
    $e=New-ReportFixture; $e.Collection.InterfaceAlias=''
    $e.Interfaces+=[pscustomobject]@{Alias='VPN';InterfaceIndex=2;InterfaceGuid='22222222-2222-2222-2222-222222222222';Status='Up';PhysicalMediaType='Unspecified';HardwareInterface=$false;Virtual=$true}
    $e.IpConfiguration+=[pscustomobject]@{InterfaceIndex=2;IPv4Addresses=@();IPv6Addresses=@();DnsServers=@()}
    $r=New-ReportObject $e; $view=New-Dot1xReportView -Report $r -Evidence $e
    Assert-Report (@($r.Findings|Where-Object {$_.Id -eq 'IP-NO-USABLE-ADDRESS'}).Count -eq 1) 'Full VPN evidence was removed.'
    Assert-Report (@($view.Issues|Where-Object {$_.Id -eq 'IP-NO-USABLE-ADDRESS'}).Count -eq 0) 'Unrelated VPN notice dominates the view.'
}
Test-ReportCase 'current WLAN profile is selected without showing every stored profile' {
    $e=New-ReportFixture; $e.Interfaces[0].PhysicalMediaType='Native 802.11'; $e.Interfaces[0].MediaType='Native 802.11'
    $e.Profiles[0].Kind='Wireless'; $e.Profiles[0].Name='Current'
    $e.Profiles+=[pscustomobject]@{Name='Old';Kind='Wireless';InterfaceGuid=$e.Interfaces[0].InterfaceGuid;OneXEnabled=$true;AuthMode='machine';EapTypes=@(13);ServerValidationEnabled=$false}
    $e.Wireless=@([pscustomobject]@{InterfaceGuid=$e.Interfaces[0].InterfaceGuid;CurrentProfileName='Current';ConnectionQueryCode=0})
    $r=New-ReportObject $e; $view=New-Dot1xReportView -Report $r -Evidence $e
    Assert-Report (($view.Configuration -join ' ') -notmatch 'Old') 'Unused stored profile was listed as current configuration.'
    Assert-Report (@($view.Issues|Where-Object {$_.Title -match 'Old'}).Count -eq 0) 'Unused stored profile finding remained in the default view.'
    Assert-Report (@($r.Findings|Where-Object {$_.Summary -match 'Old'}).Count -gt 0) 'Underlying stored-profile findings were deleted.'
}
Test-ReportCase 'cleanup failures stay visible even for irrelevant collectors' {
    $e=New-ReportFixture; $e.Probes+=[pscustomobject]@{Name='Wireless';Status='Failed';DurationMs=1;CleanupConfirmed=$false;Limitations=@('Owned process cleanup unconfirmed at C:\fixture\transport.')}
    $view=New-Dot1xReportView -Report (New-ReportObject $e) -Evidence $e
    Assert-Report (($view.Gaps -join ' ') -match 'Cleanup needs attention.*C:\\fixture\\transport') 'Cleanup warning or exact path was hidden.'
}
Test-ReportCase 'temporary-file cleanup failure remains visible after worker success' {
    $e=New-ReportFixture; $e.Probes+=[pscustomobject]@{Name='Wired';Status='Partial';DurationMs=1;CleanupConfirmed=$true;Limitations=@('Private wired transport cleanup is incomplete at C:\fixture\xml. Treat remaining files as sensitive.')}
    $view=New-Dot1xReportView -Report (New-ReportObject $e) -Evidence $e
    Assert-Report (($view.Gaps -join ' ') -match 'C:\\fixture\\xml') 'Temporary XML warning was hidden by successful process cleanup.'
}
Test-ReportCase 'disabled and truncated logs are distinct collection gaps' {
    $e=New-ReportFixture
    $e.EventLogs=@([pscustomobject]@{LogName='Microsoft-Windows-CAPI2/Operational';ProviderFilter='';Enabled=$false;QueryStatus='NoEvents';Truncated=$false},[pscustomobject]@{LogName='Microsoft-Windows-Wired-AutoConfig/Operational';ProviderFilter='';Enabled=$true;QueryStatus='Succeeded';Truncated=$true})
    foreach ($log in $e.EventLogs) { $e.Probes+=[pscustomobject]@{Name=('Events:'+$log.LogName+':');Status='Partial';DurationMs=1;Limitations=@('fixture gap')} }
    $view=New-Dot1xReportView -Report (New-ReportObject $e) -Evidence $e
    Assert-Report (($view.Gaps -join ' ') -match 'Logging is disabled') 'Disabled log became empty history.'
    Assert-Report (($view.Gaps -join ' ') -match 'Event limit reached') 'Truncation disappeared.'
}
Test-ReportCase 'long saved paths remain intact on one line' {
    $e=New-ReportFixture; $r=New-ReportObject $e
    $path='C:\fixture\'+('long-directory-'*12)+'\report'
    $r|Add-Member NoteProperty OutputDirectory $path
    $text=Format-Dot1xReport -Report $r -Evidence $e
    Assert-Report ($text.Contains('Saved reports: '+$path)) 'Saved path was split or truncated.'
}
Test-ReportCase 'control characters cannot forge report lines' {
    $e=New-ReportFixture; $e.Collection.InterfaceAlias="Ethernet`nFORGED"; $e.Interfaces[0].Alias=$e.Collection.InterfaceAlias
    $text=Format-Dot1xReport -Report (New-ReportObject $e) -Evidence $e
    Assert-Report ($text -notmatch '(?m)^FORGED') 'A diagnostic string forged a report line.'
    Assert-Report ($text -match 'Ethernet FORGED') 'Sanitized identifying data was lost.'
}
Test-ReportCase 'history display bounds are explicit and detailed mode expands them' {
    $e=New-ReportFixture; $e.Events=@(1..11|ForEach-Object {New-ReportEvent -Code ('0x{0:X8}' -f (10000+$_))})
    $r=New-ReportObject $e; $short=Format-Dot1xReport -Report $r -Evidence $e
    $long=Format-Dot1xReport -Report $r -Evidence $e -Detailed
    Assert-Report ($short -match '1 older group\(s\) not shown') 'Display limit silently lost groups.'
    Assert-Report ($long -notmatch 'older group\(s\) not shown') 'Detailed mode did not expand history.'
}
Test-ReportCase 'legacy callers without evidence keep their findings visible' {
    $e=New-ReportFixture; $e.Events=@(New-ReportEvent); $r=New-ReportObject $e
    $text=Format-Dot1xReport -Report $r
    Assert-Report ($text -match 'historical 802.1X failure') 'Legacy historical finding was silently filtered.'
    Assert-Report ($text -match 'cannot be reconstructed') 'Missing detailed evidence was not explained.'
}
Test-ReportCase 'unknown future rules stay visible' {
    $e=New-ReportFixture; $r=New-ReportObject $e
    $r.Findings+= [pscustomobject]@{Id='FUTURE-RULE';Severity='Information';Confidence='Low';Summary='Future observation';Evidence=@();Remediation=@('Future check');Limitations=@('Future limitation')}
    $text=Format-Dot1xReport -Report $r -Evidence $e
    Assert-Report ($text -match 'Future observation' -and $text -match 'Future check' -and $text -match 'Future limitation') 'Unrecognized rule was discarded.'
}
Test-ReportCase 'detailed parameter is available on the CLI and both render paths' {
    $command=Get-Command -Name $ScriptPath
    Assert-Report ($command.Parameters.ContainsKey('Detailed')) 'CLI Detailed switch missing.'
    Assert-Report ((Get-Command Write-Dot1xReport).Parameters.ContainsKey('Detailed')) 'File-output Detailed switch missing.'
    Assert-Report ((Get-Command Format-Dot1xReport).Parameters.ContainsKey('Detailed')) 'Console formatter Detailed switch missing.'
}

[pscustomobject]@{Passed=$script:ReportPassed;Failed=$script:ReportFailed.Count;FailedNames=@($script:ReportFailed)}|ConvertTo-Json -Compress
if ($script:ReportFailed.Count -gt 0) { throw ('Report tests failed: ' + ($script:ReportFailed -join '; ')) }

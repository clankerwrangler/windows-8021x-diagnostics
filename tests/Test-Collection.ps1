<#
.SYNOPSIS
Tests event collection failure states with synthetic Get-WinEvent responses only.
#>
[CmdletBinding()]
param([string]$ScriptPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1'))
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
. $ScriptPath
$script:MockMode = 'NoEvents'
$script:MockRecords = @()
$script:ObservedFilter = $null
$script:ObservedMaxEvents = 0
function Get-WinEvent {
    [CmdletBinding()]
    param([string]$ListLog, [hashtable]$FilterHashtable, [int]$MaxEvents)
    if ($ListLog) {
        if ($script:MockMode -eq 'LogDenied') { throw (New-Object UnauthorizedAccessException('Synthetic log denial.')) }
        return [pscustomobject]@{ IsEnabled = ($script:MockMode -ne 'Disabled') }
    }
    $script:ObservedFilter = $FilterHashtable; $script:ObservedMaxEvents = $MaxEvents
    if ($script:MockMode -eq 'QueryDenied') { throw (New-Object UnauthorizedAccessException('Synthetic query denial.')) }
    if ($script:MockMode -in @('MismatchExact','MismatchPrefix','MismatchSuffix','MismatchWrongCase','OtherInvalidArgument')) {
        $id = switch ($script:MockMode) {
            'MismatchExact' { 'LogsAndProvidersDontOverlap' }
            'MismatchPrefix' { 'PrefixLogsAndProvidersDontOverlap' }
            'MismatchSuffix' { 'LogsAndProvidersDontOverlapSuffix' }
            'MismatchWrongCase' { 'logsandprovidersdontoverlap' }
            'OtherInvalidArgument' { 'OtherInvalidArgument' }
        }
        $errorRecord = New-Object Management.Automation.ErrorRecord((New-Object Exception('Synthetic provider/channel error.')),$id,[Management.Automation.ErrorCategory]::InvalidArgument,$null)
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }

    if ($script:MockMode -in @('NoEvents','Disabled')) {
        $errorRecord = New-Object Management.Automation.ErrorRecord((New-Object Exception('Synthetic no matching events.')),'NoMatchingEventsFound',[Management.Automation.ErrorCategory]::ObjectNotFound,$null)
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }
    return $script:MockRecords
}
function New-TestEventContext {
    [pscustomobject]@{
        LogName = 'System'; ProviderName = 'Microsoft-Windows-EapHost'
        StartTimeUtc = '2026-01-15T11:00:00Z'; EndTimeUtc = '2026-01-15T12:00:00Z'
        MaxEventsPerLog = 2; InterfaceAlias = ''; ProfileName = ''; AllowedGuids = @(); IncludeEventMessages = $false
    }
}
function New-TestRecord {
    param([string]$Xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="ReasonCode">1234</Data><Data Name="ProfileName">fixture-profile</Data><Data Name="UserName">fixture-private-user-DO-NOT-EMIT</Data><Data Name="Password">fixture-private-password-DO-NOT-EMIT</Data><Data Name="ProfileContent">fixture-private-profile-DO-NOT-EMIT</Data></EventData></Event>')
    $record = [pscustomobject]@{
        ProviderName = 'Microsoft-Windows-EapHost'; Id = 2002; Level = 2; Version = 1
        TimeCreated = [datetime]::Parse('2026-01-15T11:30:00Z'); RecordId = 1
        Message = ('fixture-private-message-DO-NOT-EMIT ' + ('x' * 2100)); FixtureXml = $Xml
    }
    $record | Add-Member ScriptMethod ToXml { return $this.FixtureXml }
    $record | Add-Member ScriptMethod Dispose { }
    return $record
}
function Invoke-TestEvents {
    param($Context = (New-TestEventContext))
    $script:ProbeLimits = New-Object 'System.Collections.Generic.List[string]'
    Get-Dot1xEvents -Context $Context -Limitations $script:ProbeLimits
}
Test-Case 'successful empty event query is distinct from collection failure' {
    $script:MockMode = 'NoEvents'; $result = Invoke-TestEvents
    Assert-Equal $result.EventLogs[0].QueryStatus 'NoEvents' 'Empty successful query was not represented distinctly.'
    Assert-Equal @($result.Events).Count 0 'Empty query produced records.'
    Assert-Equal $script:ProbeLimits.Count 0 'Empty successful query was marked as failed.'
}
Test-Case 'inaccessible log is not a successful empty query' {
    $script:MockMode = 'LogDenied'; $result = Invoke-TestEvents
    Assert-Equal $result.EventLogs[0].QueryStatus 'Unavailable' 'Denied log was presented as a successful query.'
    Assert-True ($script:ProbeLimits.Count -gt 0) 'Denied log has no limitation.'
}
Test-Case 'access denied after readable metadata is still unavailable' {
    $script:MockMode = 'QueryDenied'; $result = Invoke-TestEvents
    Assert-Equal $result.EventLogs[0].Available $true 'Readable log metadata was lost.'
    Assert-Equal $result.EventLogs[0].QueryStatus 'Unavailable' 'Denied record query was presented as successful.'
}
Test-Case 'disabled log remains disabled and reports incomplete visibility' {
    $script:MockMode = 'Disabled'; $result = Invoke-TestEvents
    Assert-Equal $result.EventLogs[0].Enabled $false 'Disabled log state was not retained.'
    Assert-True ($script:ProbeLimits.Count -gt 0) 'Disabled log had no visibility limitation.'
}
Test-Case 'event query is bounded by provider and both snapshot timestamps' {
    $script:MockMode = 'NoEvents'; $context = New-TestEventContext; $null = Invoke-TestEvents $context
    Assert-Equal $script:ObservedFilter.ProviderName $context.ProviderName 'Provider filter was lost.'
    Assert-Equal $script:ObservedFilter.StartTime.ToUniversalTime() ([datetime]::Parse($context.StartTimeUtc).ToUniversalTime()) 'Window start was lost.'
    Assert-Equal $script:ObservedFilter.EndTime.ToUniversalTime() ([datetime]::Parse($context.EndTimeUtc).ToUniversalTime()) 'Window end was lost.'
    Assert-True ($script:ObservedMaxEvents -le 3) 'Query exceeded the bounded truncation check.'
}
Test-Case 'event fields and default messages exclude non-allowlisted identity data' {
    $script:MockMode = 'Records'; $script:MockRecords = @(New-TestRecord); $result = Invoke-TestEvents
    Assert-Equal @($result.Events).Count 1 'Synthetic structured record was not collected.'
    Assert-Equal $result.EventLogs[0].QueryStatus 'Succeeded' 'A valid provider/channel pair was reclassified.'
    Assert-Equal $result.Events[0].Fields.ReasonCode '1234' 'Provider-specific numeric reason field was lost.'
    Assert-True (($result | ConvertTo-Json -Depth 15) -notmatch 'fixture-private-') 'Default event collection retained private fixture values.'
}
Test-Case 'optional event messages are explicit and length-bounded' {
    $script:MockMode = 'Records'; $script:MockRecords = @(New-TestRecord)
    $context = New-TestEventContext; $context.IncludeEventMessages = $true
    $result = Invoke-TestEvents $context
    Assert-Equal $result.Events[0].Message.Length 2048 'Optional message length bound was not enforced.'
}
Test-Case 'event truncation is reported rather than hidden' {
    $script:MockMode = 'Records'; $script:MockRecords = @((New-TestRecord),(New-TestRecord),(New-TestRecord))
    $result = Invoke-TestEvents
    Assert-Equal @($result.Events).Count 2 'Event count bound was not enforced.'
    Assert-Equal $result.EventLogs[0].Truncated $true 'Truncation was not reported.'
    Assert-True ($script:ProbeLimits.Count -gt 0) 'Truncation had no limitation.'
}
Test-Case 'external XML entity in an event is rejected and marks partial collection' {
    $script:MockMode = 'Records'; $script:MockRecords = @(New-TestRecord -Xml '<!DOCTYPE Event [<!ENTITY ext SYSTEM "file:///C:/fixture-never-read.txt">]><Event><EventData><Data Name="ReasonCode">&ext;</Data></EventData></Event>')
    $result = Invoke-TestEvents
    Assert-Equal @($result.Events).Count 0 'Unsafe event XML was accepted.'
    Assert-True ($script:ProbeLimits.Count -gt 0) 'Rejected event XML was silently treated as a complete query.'
}
Test-Case 'exact named-provider channel mismatch is unsupported rather than no events' {
    $script:MockMode='MismatchExact';$context=New-TestEventContext;$result=Invoke-TestEvents $context
    Assert-Equal $result.EventLogs[0].QueryStatus 'UnsupportedProviderChannel' 'Exact provider/channel mismatch was not classified.'
    Assert-Equal $result.EventLogs[0].ErrorCode 'LogsAndProvidersDontOverlap' 'Fixed mismatch category was lost.'
    Assert-Equal $result.EventLogs[0].Available $true 'Available log metadata was lost.'
    Assert-Equal $result.EventLogs[0].Enabled $true 'Enabled log metadata was lost.'
    Assert-Equal @($result.Events).Count 0 'Unsupported query invented event records.'
    Assert-True ($script:ProbeLimits.Count -gt 0) 'Unsupported query has no limitation.'
    $payload=Invoke-Dot1xWorker -Name Events -Context $context
    $e=[pscustomobject]@{SchemaVersion=1;CapturedAtUtc=$context.EndTimeUtc;Events=$payload.Data.Events;EventLogs=$payload.Data.EventLogs;Probes=@([pscustomobject]@{Name='Events';Status=$payload.Status;DurationMs=1;Limitations=$payload.Limitations})}
    $findings=@(Get-Dot1xDiagnosis -Evidence $e)
    Assert-True (@($findings|Where-Object{$_.Id -eq 'COLLECTION-INCOMPLETE'}).Count -gt 0) 'Unsupported visibility was concealed.'
}
Test-Case 'empty provider does not inherit named-provider mismatch classification' {
    $script:MockMode='MismatchExact';$context=New-TestEventContext;$context.ProviderName=''
    $result=Invoke-TestEvents $context
    Assert-Equal $result.EventLogs[0].QueryStatus 'Unavailable' 'Unscoped error was reclassified as a named-provider mismatch.'
}
Test-Case 'lookalike and unrelated invalid-argument errors remain query failures' {
    foreach($mode in @('MismatchPrefix','MismatchSuffix','MismatchWrongCase','OtherInvalidArgument')){
        $script:MockMode=$mode;$result=Invoke-TestEvents
        Assert-Equal $result.EventLogs[0].QueryStatus 'Unavailable' 'A non-exact error inherited the unsupported classification.'
        Assert-True ($script:ProbeLimits.Count -gt 0) 'A non-exact query failure was hidden.'
    }
}

Complete-Tests

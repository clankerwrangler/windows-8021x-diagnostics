<#
.SYNOPSIS
Tests logging preparation with synthetic native/registry responses and private scratch files.
.DESCRIPTION
Uses only wevtutil el for the read-only native boundary regression; logging mutations and
Schannel access are mocked. Filesystem tests use owned fixtures.
#>
[CmdletBinding()]
param(
    [string]$ScriptPath,
    [Parameter(Mandatory=$true)][string]$ScratchPath
)
if (-not $ScriptPath) { $ScriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1' }
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
$helperPath = Join-Path (Split-Path $ScriptPath -Parent) 'Set-8021xLogging.ps1'
. $helperPath
$script:realLoggingNative = ${function:Invoke-LoggingNative}

function Assert-Throws {
    param([scriptblock]$Body, [string]$Pattern = '.')
    $message = ''
    try { & $Body } catch { $message = $_.Exception.Message }
    Assert-True ($message -match $Pattern) ('Expected failure matching: ' + $Pattern + '; actual: ' + $message)
}
function New-TestLoggingStore {
    $store = [pscustomobject]@{ Json=$null; Saves=0; Deletes=0; FailSave=$false; FailDelete=$false; TraceJson=$null; TraceSaves=0; TraceDeletes=0; FailTraceSave=$false; FailTraceDelete=$false }
    $store | Add-Member ScriptMethod Read { return $this.Json }
    $store | Add-Member ScriptMethod SaveNew {
        param($text)
        if ($this.FailSave) { throw 'Synthetic state disk failure' }
        if ($null -ne $this.Json) { throw 'Baseline overwrite' }
        $this.Json=$text; $this.Saves++
    }
    $store | Add-Member ScriptMethod DeleteBaseline {
        if ($this.FailDelete) { throw 'Synthetic cleanup failure' }
        $this.Json=$null; $this.Deletes++
    }
    $store | Add-Member ScriptMethod ReadTrace { return $this.TraceJson }
    $store | Add-Member ScriptMethod SaveNewTrace {
        param($text)
        if ($this.FailTraceSave) { throw 'Synthetic trace intent disk failure' }
        if ($null -ne $this.TraceJson) { throw 'Trace intent overwrite' }
        $this.TraceJson=$text; $this.TraceSaves++
    }
    $store | Add-Member ScriptMethod DeleteTrace {
        if ($this.FailTraceDelete) { throw 'Synthetic trace intent cleanup failure' }
        $this.TraceJson=$null; $this.TraceDeletes++
    }
    return $store
}
function Reset-TestLogging {
    $script:installed = @(Get-LoggingCoreChannels) + @(
        'Microsoft-Windows-Dhcp-Client/Admin', 'Microsoft-Windows-DNS-Client/Operational',
        'Microsoft-Windows-NetworkProfile/Operational', 'Microsoft-Windows-GroupPolicy/Operational',
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin',
        'Microsoft-Windows-CertificateServicesClient-AutoEnrollment/Operational',
        'Microsoft-Windows-OneX/Operational', 'Microsoft-Windows-EapMethods-RasChap/Operational',
        'Microsoft-Windows-EapMethods-RasTls/Operational', 'Microsoft-Windows-EapMethods-Sim/Operational',
        'Microsoft-Windows-EapMethods-Ttls/Operational', 'Microsoft-Windows-Dhcpv6-Client/Admin',
        'Microsoft-Windows-Dhcpv6-Client/Operational',
        'Microsoft-Windows-EapHost/Debug', 'Microsoft-Windows-Dhcp-Client/Analytic', 'Security')
    $script:configuration = @{}
    foreach ($name in $script:installed) { $script:configuration[$name] = [pscustomobject]@{ Enabled=$false; MaximumSize=1048576L } }
    $script:configuration['Microsoft-Windows-WLAN-AutoConfig/Operational'].Enabled = $true
    $script:configuration['Microsoft-Windows-WLAN-AutoConfig/Operational'].MaximumSize = 209715200L
    $script:schannel = [pscustomobject]@{ Present=$false; Value=$null }
    $script:nativeCalls = New-Object 'System.Collections.Generic.List[object]'
    $script:schannelWrites = New-Object 'System.Collections.Generic.List[object]'
    $script:nativeFailures = @{}
    $script:nativeFailureText = 'Synthetic native denied or unavailable'
    $script:failSchannel = $false
    $script:store = New-TestLoggingStore
    $script:traceCalls=New-Object 'System.Collections.Generic.List[string]'
    $script:traceActive=@{}; $script:traceFiles=@{}
    $script:traceFailureAction=''; $script:traceFailAfterStart=$false; $script:traceFileFailure=$false; $script:traceLeaseDeletes=0
}
# Only this adapter is replaced: enumeration, XML parsing, exit handling, channel
# allowlisting, baseline serialization, and enable/restore orchestration stay real.
function Invoke-LoggingNative {
    param([string[]]$Arguments)
    $script:nativeCalls.Add(@($Arguments))
    $action = $Arguments[0]
    $key = $action
    if ($Arguments.Count -gt 1) { $key += ':' + $Arguments[1] }
    if ($script:nativeFailures.ContainsKey($key)) { return [pscustomobject]@{ ExitCode=$script:nativeFailures[$key]; Text=$script:nativeFailureText } }
    if ($action -eq 'el') { return [pscustomobject]@{ ExitCode=0; Text=($script:installed -join "`r`n") } }
    $name = $Arguments[1]
    if ($script:installed -notcontains $name) { return [pscustomobject]@{ ExitCode=15007; Text='Synthetic missing channel' } }
    $setting = $script:configuration[$name]
    if ($action -eq 'sl') {
        if ($null -eq $script:store.Json) { throw 'A logging mutation preceded a durable baseline.' }
        $setting.Enabled = [bool]::Parse($Arguments[2].Substring(3))
        $setting.MaximumSize = [long]::Parse($Arguments[3].Substring(4))
        return [pscustomobject]@{ ExitCode=0; Text='' }
    }
    if ($action -ne 'gl') { throw 'Unexpected native action' }
    $text = '<channel xmlns="http://schemas.microsoft.com/win/2004/08/events" name="' + $name + '" enabled="' + $setting.Enabled.ToString().ToLowerInvariant() + '"><logging><maxSize>' + $setting.MaximumSize + '</maxSize></logging></channel>'
    [pscustomobject]@{ ExitCode=0; Text=$text }
}
function Get-LoggingSchannel { return $script:schannel }
function Set-LoggingSchannel {
    param($Setting)
    if ($script:failSchannel) { throw 'Synthetic registry denied' }
    if ($null -eq $script:store.Json) { throw 'A registry mutation preceded a durable baseline.' }
    $script:schannelWrites.Add($Setting)
    $script:schannel = [pscustomobject]@{ Present=$Setting.Present; Value=$Setting.Value }
}
function New-LoggingTraceLease {
    param([string]$Path,[string]$Caller,[bool]$Create)
    $lease=[pscustomobject]@{Path=$Path}
    $lease | Add-Member ScriptMethod ValidateTraceFile {
        param($Name,$AllowMissing,$Finalized)
        if ($script:traceFileFailure) { throw 'Synthetic trace output validation failure' }
        $file=[IO.Path]::Combine($this.Path,$Name)
        if ($script:traceFiles.ContainsKey($file)) { return $true }
        if ($AllowMissing) { return $false }
        throw 'Synthetic missing trace file'
    }
    $lease | Add-Member ScriptMethod DeleteEmptyDirectory { $script:traceLeaseDeletes++ }
    $lease | Add-Member ScriptMethod Dispose { }
    return $lease
}
function Invoke-LoggingTraceNative {
    param([string]$Action,$State)
    if ($null -eq $script:store.TraceJson) { throw 'An ETW operation preceded durable trace intent.' }
    $script:traceCalls.Add($Action)
    if ($script:traceFailureAction -eq $Action) { throw ('Synthetic trace '+$Action+' failure') }
    $id=$State.SessionGuid
    if ($Action -eq 'Query') {
        if ($script:traceActive.ContainsKey($id)) { return [pscustomobject]@{Handle=1;SessionGuid=$id} }
        return $null
    }
    if ($Action -eq 'Stop') { $script:traceActive.Remove($id); return }
    if ($Action -ne 'Ensure') { throw 'Unexpected ETW action' }
    $script:traceActive[$id]=$true; $script:traceFiles[$State.TracePath]=$true
    if ($script:traceFailAfterStart) { throw 'Synthetic provider enable failure after session start' }
    return [pscustomobject]@{Handle=1;SessionGuid=$id}
}
function Invoke-TestLogging {
    param([bool]$Restoring=$false, [bool]$Schannel=$false, [bool]$EventsOnly=$false, [string]$OutputDirectory='')
    Invoke-LoggingSession $script:store 'fixture-machine' 'fixture-caller' $Restoring $Schannel $OutputDirectory $EventsOnly
}
function Get-TestMutations { @($script:nativeCalls | Where-Object { $_[0] -eq 'sl' }) }

Test-Case 'helper parses, imports without execution, and documents both modes' {
    $tokens=$null; $errors=$null
    $ast = [Management.Automation.Language.Parser]::ParseFile($helperPath,[ref]$tokens,[ref]$errors)
    Assert-Equal @($errors).Count 0 'Helper parse errors.'
    Assert-True ([bool](Get-Command Invoke-LoggingSession)) 'Import did not expose the orchestration function.'
    Assert-True (-not ('Dot1xLoggingV2.Store' -as [type])) 'Dot-source compiled platform code.'
    Assert-True ((Get-Help $helperPath -Full).Synopsis -match 'client') 'Help omits client scope.'
    $commands = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] },$true))
    foreach ($command in $commands) {
        Assert-True ($command.GetCommandName() -notmatch '^(Restart-Computer|Restart-Service|Set-Service|Clear-EventLog|Set-Net.*|netsh|auditpol)$') 'Unexpected non-logging mutation command.'
    }
}
Test-Case 'defaults are the exact collector channels plus narrow client Admin and Operational families' {
    Reset-TestLogging
    $core = @(Get-LoggingCoreChannels)
    Assert-Equal $core.Count 5 'Core list changed.'
    foreach ($family in @('WLAN-AutoConfig','Wired-AutoConfig','EapHost','CAPI2','NTLM')) {
        Assert-True ($core -contains ('Microsoft-Windows-' + $family + '/Operational')) 'A collector channel is missing.'
    }
    foreach ($name in $script:installed[0..17]) { Assert-True (Test-LoggingChannel $name) 'Expected client channel was excluded.' }
    foreach ($name in @('Security','System','Microsoft-Windows-NPS/Operational','Microsoft-Windows-OneX/Debug','Microsoft-Windows-EapMethods-Unrelated/Operational','Microsoft-Windows-EapMethods-RasTls/Analytic','Microsoft-Windows-EapHost/Debug','Microsoft-Windows-EapHost/Analytic','Microsoft-Windows-Dhcp-Client/Analytic','Microsoft-Windows-CertificateServicesClient-X/Debug','Microsoft-Windows-CertificateServicesClient-X/Operational/extra','Microsoft-Windows-NTLM/Operational /e:false','Other-Microsoft-Windows-DNS-Client/Operational')) {
        Assert-True (-not (Test-LoggingChannel $name)) 'A channel outside the allowlist was accepted.'
    }
    Invoke-TestLogging
    Assert-Equal @(Get-TestMutations).Count 18 'Unexpected enabled channel count.'
    Assert-Equal $script:schannelWrites.Count 0 'Default enable changed Schannel.'
    Assert-Equal $script:configuration[$core[0]].MaximumSize 209715200L 'Enable shrank a large log.'
    Assert-Equal $script:configuration[$core[1]].MaximumSize 104857600L 'Enable did not enlarge a small log.'
}
Test-Case 'missing installed logs are skipped without native setting queries' {
    Reset-TestLogging
    $script:installed = @('Microsoft-Windows-CAPI2/Operational')
    Invoke-TestLogging
    Assert-Equal @(Get-TestMutations).Count 1 'Missing logs were not skipped.'
    Assert-Equal ($script:store.Json | ConvertFrom-Json).Channels.Count 1 'Baseline includes missing logs.'
}
Test-Case 'native non-aligned log sizes remain exact in the original baseline' {
    Reset-TestLogging
    $name = 'Microsoft-Windows-CAPI2/Operational'
    $script:configuration[$name].MaximumSize = 1052672L
    Invoke-TestLogging
    $saved = $script:store.Json | ConvertFrom-Json
    Assert-LoggingState $saved 'fixture-machine' 'fixture-caller'
    $original = @($saved.Channels | Where-Object { $_.Name -eq $name })
    Assert-Equal $original.Count 1 'The native-size channel is missing from the baseline.'
    Assert-Equal $original[0].MaximumSize 1052672L 'Snapshot or serialization rounded the original native size.'
    Assert-Equal $script:configuration[$name].MaximumSize 104857600L 'Enable did not enlarge the native-size log.'
    Invoke-TestLogging -Restoring $true
    Assert-Equal $script:configuration[$name].MaximumSize 1052672L 'Restore rounded the original native size.'
    Assert-Equal $script:configuration[$name].Enabled $false 'Restore lost the original disabled state.'
    Assert-Equal $script:store.Deletes 1 'Exact native-size restoration did not complete.'
}
Test-Case 'repeated enable preserves the first baseline and never shrinks newer larger sizes' {
    Reset-TestLogging
    Invoke-TestLogging
    $original = $script:store.Json
    $name = 'Microsoft-Windows-Wired-AutoConfig/Operational'
    $script:configuration[$name].MaximumSize = 314572800L
    Invoke-TestLogging
    Assert-Equal $script:store.Json $original 'Repeated enable overwrote the baseline.'
    Assert-Equal $script:store.Saves 1 'Repeated enable saved a new baseline.'
    Assert-Equal $script:configuration[$name].MaximumSize 314572800L 'Repeated enable shrank a log.'
    Assert-Throws { Invoke-TestLogging -Schannel $true } 'Run -Restore'
    Assert-Equal $script:schannelWrites.Count 0 'Schannel was changed without a matching baseline.'
}
Test-Case 'snapshot and durable save failures prevent all logging changes' {
    Reset-TestLogging
    $script:nativeFailures['gl:Microsoft-Windows-CAPI2/Operational'] = 5
    Assert-Throws { Invoke-TestLogging } 'exit=5'
    Assert-Equal $script:store.Saves 0 'Incomplete snapshot was saved.'
    Assert-Equal @(Get-TestMutations).Count 0 'Snapshot failure changed logging.'
    Reset-TestLogging; $script:store.FailSave = $true
    Assert-Throws { Invoke-TestLogging } 'disk failure'
    Assert-Equal @(Get-TestMutations).Count 0 'Save failure changed logging.'
}
Test-Case 'partial native enable failure is visible and preserves recoverable original states' {
    Reset-TestLogging
    $name = 'Microsoft-Windows-CAPI2/Operational'
    $script:nativeFailures['sl:' + $name] = 5
    Assert-Throws { Invoke-TestLogging } 'incomplete[\s\S]*exit=5'
    Assert-Equal $script:store.Saves 1 'Original baseline was not saved.'
    Assert-Equal @(Get-TestMutations).Count 18 'A failure prevented other channels from being attempted.'
    Assert-Equal ($script:store.Json | ConvertFrom-Json).Channels[0].Enabled $false 'Baseline captured a mutated state.'
    $script:nativeFailures.Clear()
    Invoke-TestLogging -Restoring $true
    Assert-Equal $script:configuration[$name].Enabled $false 'Restore missed the original disabled state.'
    Assert-Equal $script:store.Deletes 1 'Successful restore did not remove the baseline.'
}
Test-Case 'partial restore and cleanup failures retain baseline and permit idempotent retry' {
    Reset-TestLogging; Invoke-TestLogging
    $original = $script:store.Json
    $name = 'Microsoft-Windows-CAPI2/Operational'
    $script:nativeFailures['sl:' + $name] = 15007
    Assert-Throws { Invoke-TestLogging -Restoring $true } 'incomplete[\s\S]*exit=15007'
    Assert-Equal $script:store.Json $original 'Partial restore removed the baseline.'
    $script:nativeFailures.Clear(); $script:store.FailDelete = $true
    Assert-Throws { Invoke-TestLogging -Restoring $true } 'cleanup failure'
    Assert-Equal $script:store.Json $original 'Cleanup failure lost the baseline.'
    $script:store.FailDelete = $false
    Invoke-TestLogging -Restoring $true
    foreach ($row in ($original | ConvertFrom-Json).Channels) {
        Assert-Equal $script:configuration[$row.Name].Enabled $row.Enabled 'Original enabled state was not restored.'
        Assert-Equal $script:configuration[$row.Name].MaximumSize $row.MaximumSize 'Original size was not restored.'
    }
    $before = @(Get-TestMutations).Count
    Invoke-TestLogging -Restoring $true
    Assert-Equal @(Get-TestMutations).Count $before 'Repeated completed restore changed settings.'
}
Test-Case 'Schannel absence, zero, and high-bit DWORD values restore exactly' {
    foreach ($value in @($null,0L,3L,4294967295L)) {
        Reset-TestLogging
        $script:schannel = [pscustomobject]@{ Present=($null -ne $value); Value=$value }
        Invoke-TestLogging -Schannel $true
        Assert-Equal $script:schannel.Value 7L 'Optional Schannel verbosity was not enabled.'
        $baseline = $script:store.Json
        Invoke-TestLogging
        Assert-Equal $script:store.Json $baseline 'Repeated enable lost the Schannel baseline.'
        Invoke-TestLogging -Restoring $true
        Assert-Equal $script:schannel.Present ($null -ne $value) 'Schannel presence was not restored.'
        Assert-True ($script:schannel.Value -eq $value) 'Schannel DWORD was not restored exactly.'
    }
}
Test-Case 'Schannel errors preserve the baseline through enable and restore' {
    Reset-TestLogging; $script:failSchannel = $true
    Assert-Throws { Invoke-TestLogging -Schannel $true } 'registry denied'
    Assert-True ($null -ne $script:store.Json) 'Schannel failure lost the baseline.'
    Assert-Throws { Invoke-TestLogging -Restoring $true } 'registry denied'
    Assert-Equal $script:store.Deletes 0 'Failed Schannel restore removed the baseline.'
    $script:failSchannel = $false; Invoke-TestLogging -Restoring $true
    Assert-Equal $script:store.Deletes 1 'Schannel retry failed to complete restoration.'
}
Test-Case 'malformed, foreign, and command-bearing baselines never reach native mutations' {
    Reset-TestLogging
    $valid = New-LoggingState 'fixture-machine' 'fixture-caller' $false | ConvertTo-Json -Depth 6 -Compress
    $invalid = @('{', '{}', $valid.Replace('fixture-machine','other-machine'), $valid.Replace('fixture-caller','other-caller'),
        $valid.Replace('"Enabled":false','"Enabled":"false"'), $valid.Replace('"MaximumSize":1048576','"MaximumSize":-1'),
        $valid.Replace('Microsoft-Windows-CAPI2/Operational','Security'), $valid.Replace('Microsoft-Windows-CAPI2/Operational','Microsoft-Windows-CAPI2/Operational /e:false'),
        $valid.Replace('"Version":1','"Version":2'), $valid.Replace('"Version":1','"Command":"anything","Version":1'),
        $valid.Replace('"Schannel":null','"Schannel":{"Present":true,"Value":4294967296}'),
        $valid.Replace('"Schannel":null','"Schannel":{"Present":false,"Value":7}'))
    foreach ($json in $invalid) {
        $script:store.Json = $json
        Assert-Throws { Invoke-TestLogging -Restoring $true }
        Assert-Equal @(Get-TestMutations).Count 0 'Untrusted state reached a logging mutation.'
        Assert-Equal $script:store.Deletes 0 'Untrusted state was deleted.'
    }
}
Test-Case 'enumeration native errors are not treated as missing optional logs' {
    Reset-TestLogging; $script:nativeFailures['el'] = 5
    Assert-Throws { Invoke-TestLogging } 'exit=5'
    Assert-Equal $script:store.Saves 0 'Failed enumeration produced a baseline.'
    Assert-Equal @(Get-TestMutations).Count 0 'Failed enumeration changed settings.'
    $script:nativeFailureText = 'x' * 4096
    $message = ''
    try { Invoke-TestLogging } catch { $message = $_.Exception.Message }
    Assert-True ($message.Length -lt 1200 -and $message -match '\[truncated\]') 'Native failure text is unbounded.'
}

Test-Case 'default enable saves trace intent before ETW and reuses the active capture' {
    Reset-TestLogging; Invoke-TestLogging
    $baseline=$script:store.Json; $trace=$script:store.TraceJson
    $saved=$trace|ConvertFrom-Json
    Assert-LoggingTraceState $saved 'fixture-machine' 'fixture-caller'
    Assert-Equal $script:store.TraceSaves 1 'Default enable did not save one trace intent.'
    Assert-Equal @($script:traceCalls|Where-Object {$_ -eq 'Ensure'}).Count 1 'Default enable did not start capture.'
    Invoke-TestLogging -OutputDirectory (Join-Path $ScratchPath 'other-output')
    Assert-Equal $script:store.Json $baseline 'Trace reuse overwrote the original channel baseline.'
    Assert-Equal $script:store.TraceJson $trace 'Active capture was replaced by a new intent.'
    Assert-Equal $script:traceActive.Count 1 'Repeated enable created another active capture.'
    Assert-Equal $script:store.TraceSaves 1 'Repeated enable overwrote the trace intent.'
}
Test-Case 'events-only preserves the original path and later default enable adds trace to v1 state' {
    Reset-TestLogging; Invoke-TestLogging -EventsOnly $true
    $baseline=$script:store.Json
    Assert-Equal ($baseline|ConvertFrom-Json).Version 1 'The original baseline format changed.'
    Assert-Equal $script:traceCalls.Count 0 'Events-only touched ETW.'
    Assert-True ($null -eq $script:store.TraceJson) 'Events-only created trace intent.'
    Invoke-TestLogging
    Assert-Equal $script:store.Json $baseline 'Adding trace rewrote an active v1 baseline.'
    Assert-Equal $script:store.TraceSaves 1 'Trace was not added to an active v1 baseline.'
    Reset-TestLogging; Invoke-TestLogging -EventsOnly $true; Invoke-TestLogging -Restoring $true
    Assert-Equal $script:traceCalls.Count 0 'Legacy baseline restore touched ETW.'
    Assert-Equal $script:store.Deletes 1 'Legacy baseline restoration changed.'
}
Test-Case 'trace intent save failure preserves channel enable and prevents ETW start' {
    Reset-TestLogging; $script:store.FailTraceSave=$true
    Assert-Throws { Invoke-TestLogging } 'trace intent disk failure'
    Assert-Equal @(Get-TestMutations).Count 18 'Trace save failure blocked original channel preparation.'
    Assert-Equal $script:traceCalls.Count 0 'ETW started before durable trace intent.'
    Assert-True ($null -ne $script:store.Json) 'Original channel recovery state was lost.'
    Assert-True ($null -eq $script:store.TraceJson) 'Failed trace save published an intent.'
    Invoke-TestLogging -Restoring $true
    Assert-Equal $script:store.Deletes 1 'Channel restoration depended on trace creation.'
}
Test-Case 'unknown trace query preserves intent and reports failure without another start' {
    Reset-TestLogging; Invoke-TestLogging
    $trace=$script:store.TraceJson
    $script:traceFailureAction='Query'
    Assert-Throws { Invoke-TestLogging } 'trace Query failure'
    Assert-Equal $script:store.TraceJson $trace 'Unknown query deleted the saved trace identity.'
    Assert-Equal @($script:traceCalls|Where-Object {$_ -eq 'Ensure'}).Count 1 'Unknown query was treated as absence.'
    Assert-Equal @(Get-TestMutations).Count 36 'Unknown trace query blocked original channel preparation.'
}
Test-Case 'interrupted provider enable remains recoverable from saved intent' {
    Reset-TestLogging; $script:traceFailAfterStart=$true
    Assert-Throws { Invoke-TestLogging } 'provider enable failure after session start'
    Assert-Equal $script:traceActive.Count 1 'Fixture did not model a started session.'
    Assert-True ($null -ne $script:store.TraceJson) 'Interrupted start lost the trace intent.'
    Invoke-TestLogging -Restoring $true
    Assert-Equal $script:traceActive.Count 0 'Restore missed the session started before provider failure.'
    Assert-Equal $script:store.TraceDeletes 1 'Recovered trace intent was not removed.'
    Assert-Equal $script:traceFiles.Count 1 'Restore deleted the captured file.'
}
Test-Case 'trace stop errors retain both recovery records while original settings restore' {
    Reset-TestLogging; Invoke-TestLogging
    $baseline=$script:store.Json; $trace=$script:store.TraceJson
    $script:traceFailureAction='Stop'
    Assert-Throws { Invoke-TestLogging -Restoring $true } 'trace Stop failure'
    Assert-Equal @(Get-TestMutations).Count 36 'Trace stop failure prevented channel restoration attempts.'
    Assert-Equal $script:store.Json $baseline 'Trace stop failure lost the channel baseline.'
    Assert-Equal $script:store.TraceJson $trace 'Trace stop failure lost trace recovery identity.'
    $script:traceFailureAction=''; Invoke-TestLogging -Restoring $true
    Assert-Equal $script:traceActive.Count 0 'Stop retry did not recover the session.'
    Assert-True ($null -eq $script:store.Json -and $null -eq $script:store.TraceJson) 'Completed recovery left state behind.'
    Assert-Equal $script:traceFiles.Count 1 'Stop retry deleted the captured file.'
}
Test-Case 'channel restore errors still stop owned trace and preserve retry state' {
    Reset-TestLogging; Invoke-TestLogging
    $script:nativeFailures['sl:Microsoft-Windows-CAPI2/Operational']=5
    Assert-Throws { Invoke-TestLogging -Restoring $true } 'exit=5'
    Assert-Equal $script:traceActive.Count 0 'Channel restore failure prevented owned trace stop.'
    Assert-True ($null -ne $script:store.TraceJson -and $null -ne $script:store.Json) 'Partial recovery lost required state.'
    $script:nativeFailures.Clear(); Invoke-TestLogging -Restoring $true
    Assert-Equal @($script:traceCalls|Where-Object {$_ -eq 'Stop'}).Count 2 'Already-stopped trace recovery was not idempotent.'
    Assert-Equal $script:store.TraceDeletes 1 'Completed recovery did not remove trace intent.'
}
Test-Case 'output validation errors cannot prevent owned trace stop' {
    Reset-TestLogging; Invoke-TestLogging; $script:traceFileFailure=$true
    Assert-Throws { Invoke-TestLogging -Restoring $true } 'trace output validation failure'
    Assert-Equal $script:traceActive.Count 0 'Unsafe output path prevented owned session recovery.'
    Assert-True ($null -ne $script:store.TraceJson) 'Output validation failure discarded recovery context.'
    Assert-Equal $script:traceFiles.Count 1 'Output validation failure removed captured evidence.'
    $script:traceFileFailure=$false; Invoke-TestLogging -Restoring $true
    Assert-Equal $script:store.TraceDeletes 1 'Output validation retry did not finish recovery.'
}
Test-Case 'malformed channel state leaves independently valid trace recovery available' {
    Reset-TestLogging; Invoke-TestLogging
    $baseline=$script:store.Json; $script:store.Json='{'
    $before=@(Get-TestMutations).Count
    Assert-Throws { Invoke-TestLogging -Restoring $true }
    Assert-Equal @(Get-TestMutations).Count $before 'Malformed channel state authorized a settings change.'
    Assert-Equal $script:traceActive.Count 0 'Malformed channel state blocked valid trace recovery.'
    Assert-True ($null -ne $script:store.TraceJson) 'Incomplete combined recovery lost trace context.'
    $script:store.Json=$baseline; Invoke-TestLogging -Restoring $true
    Assert-Equal $script:store.Deletes 1 'Validated channel recovery could not resume.'
}
Test-Case 'malformed or foreign trace intent cannot authorize ETW or deletion' {
    Reset-TestLogging; Invoke-TestLogging
    $valid=$script:store.TraceJson
    $invalid=@('{','{}',$valid.Replace('fixture-machine','other-machine'),$valid.Replace('fixture-caller','other-caller'),
        $valid.Replace('"Version":1','"Version":2'),$valid.Replace('"Version":1','"Command":"anything","Version":1'),
        $valid.Replace('EapHost.etl','other.etl'),$valid.Replace('EapHost-Trace-','other-'))
    foreach ($json in $invalid) {
        $script:store.TraceJson=$json; $script:traceCalls.Clear()
        Assert-Throws { Invoke-TestLogging -Restoring $true }
        Assert-Equal $script:traceCalls.Count 0 'Invalid intent authorized an ETW operation.'
        Assert-Equal $script:store.TraceDeletes 0 'Invalid trace intent was deleted.'
        Assert-True ($null -ne $script:store.Json) 'Invalid trace intent discarded channel recovery state.'
    }
}
Test-Case 'orphan trace intent restores even when the channel baseline is absent' {
    Reset-TestLogging; Invoke-TestLogging
    $script:store.Json=$null; $before=@(Get-TestMutations).Count
    Invoke-TestLogging -Restoring $true
    Assert-Equal $script:traceActive.Count 0 'Absent channel baseline hid owned trace recovery.'
    Assert-Equal @(Get-TestMutations).Count $before 'Absent channel baseline invented settings to restore.'
    Assert-Equal $script:store.TraceDeletes 1 'Orphan trace intent was not finalized.'
    Assert-Equal $script:traceFiles.Count 1 'Orphan recovery deleted the ETL.'
}
Test-Case 'ended captures are retained and a fresh intent uses the requested report parent' {
    Reset-TestLogging; Invoke-TestLogging
    $baseline=$script:store.Json; $prior=$script:store.TraceJson|ConvertFrom-Json
    $script:traceActive.Clear()
    $output=Join-Path $ScratchPath 'next-report-parent'
    Invoke-TestLogging -OutputDirectory $output
    $next=$script:store.TraceJson|ConvertFrom-Json
    Assert-Equal $script:store.Json $baseline 'Fresh trace changed the channel baseline.'
    Assert-True ($next.SessionGuid -ne $prior.SessionGuid -and $next.TracePath -ne $prior.TracePath) 'Ended capture was reopened for overwrite.'
    Assert-True $script:traceFiles.ContainsKey($prior.TracePath) 'Ended capture was deleted.'
    Assert-Equal ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($next.TracePath))) ([IO.Path]::GetFullPath($output)) 'Fresh capture ignored the selected report parent.'
    Assert-Equal $script:store.TraceSaves 2 'Fresh capture did not save a new intent.'
    Assert-Equal $script:store.TraceDeletes 1 'Ended capture intent was not finalized.'
}
Test-Case 'ended capture cleanup failure cannot replace its saved intent' {
    Reset-TestLogging; Invoke-TestLogging
    $trace=$script:store.TraceJson; $script:traceActive.Clear(); $script:store.FailTraceDelete=$true
    Assert-Throws { Invoke-TestLogging } 'trace intent cleanup failure'
    Assert-Equal $script:store.TraceJson $trace 'Failed intent cleanup replaced trace identity.'
    Assert-Equal $script:store.TraceSaves 1 'Failed intent cleanup created another capture.'
    Assert-Equal $script:traceFiles.Count 1 'Failed intent cleanup removed the prior ETL.'
}
Test-Case 'trace output and events-only switches belong only to Enable' {
    $command=Get-Command $helperPath
    foreach ($name in @('OutputDirectory','EventsOnly')) {
        Assert-True $command.Parameters.ContainsKey($name) 'An Enable option is missing.'
        Assert-True ($command.Parameters[$name].ParameterSets.ContainsKey('Enable') -and -not $command.Parameters[$name].ParameterSets.ContainsKey('Restore')) 'An Enable option is accepted by Restore.'
    }
}

Test-Case 'real native boundary returns the actual wevtutil exit code without changing logging' {
    $global:LASTEXITCODE = 77
    $result = & $script:realLoggingNative @('el')
    Assert-Equal $result.ExitCode 0 'Successful native enumeration lost its exit code.'
    Assert-True (-not [string]::IsNullOrWhiteSpace($result.Text)) 'Native enumeration returned no channels.'
}

# Real state-store tests stay inside the supplied scratch directory. No native
# logger or registry adapter is restored for these tests.
$caseRoot = Join-Path $ScratchPath ('logging-fixtures-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($caseRoot)
$caller = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
try {
    Test-Case 'updated initializer coexists with an older Store CLR type in the same shell' {
        Add-Type -TypeDefinition 'namespace Dot1xLogging { public sealed class Store { public static int OldMarker=1; } }'
        Initialize-LoggingStore
        Assert-Equal ([Dot1xLogging.Store]::OldMarker) 1 'The older CLR fixture was not loaded.'
        Assert-True ($null -ne [Dot1xLoggingV2.Store].GetMethod('ReadTrace')) 'The updated initializer reused the old Store type.'
        Assert-True ($null -ne ('Dot1xLoggingV2.DirectoryLease' -as [type])) 'The updated directory lease was not loaded.'
    }
    Test-Case 'state store compiles and preserves private durable baseline across reopening and retries' {
        Initialize-LoggingStore
        $path = Join-Path $caseRoot 'private'
        $lease = New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try {
            Assert-True ($null -eq $lease.Read()) 'Fresh store has a baseline.'
            $lease.SaveNew('{"fixture":1}')
            Assert-Throws { $lease.SaveNew('{"fixture":2}') } 'must not be overwritten'
            Assert-Throws { $other = New-Object Dot1xLoggingV2.Store($path,$caller,$true); try { $other.Read() } finally { $other.Dispose() } } 'open failed'
            $acl = (New-Object IO.DirectoryInfo($path)).GetAccessControl()
            Assert-True $acl.AreAccessRulesProtected 'Directory is not protected.'
            Assert-Equal $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value $caller 'Wrong directory owner.'
        } finally { $lease.Dispose() }
        $lease = New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { Assert-Equal $lease.Read() '{"fixture":1}' 'Baseline did not survive reopening.'; $lease.DeleteBaseline() }
        finally { $lease.Dispose() }
        Assert-True (-not [IO.File]::Exists((Join-Path $path 'state.json'))) 'Completed restore left the baseline.'
    }
    Test-Case 'state store keeps channel and trace intents independent across reopening' {
        $path=Join-Path $caseRoot 'two state slots'
        $lease=New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { $lease.SaveNew('{"original":1}'); $lease.SaveNewTrace('{"trace":1}') } finally { $lease.Dispose() }
        $lease=New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try {
            Assert-Equal $lease.Read() '{"original":1}' 'Trace intent changed the original baseline bytes.'
            Assert-Equal $lease.ReadTrace() '{"trace":1}' 'Trace intent did not survive reopening.'
            Assert-Throws { $lease.SaveNewTrace('{"trace":2}') } 'must not be overwritten'
            $lease.DeleteTrace(); $lease.SaveNewTrace('{"trace":2}')
            Assert-Throws { $other=New-Object Dot1xLoggingV2.Store($path,$caller,$true); try { $other.ReadTrace() } finally { $other.Dispose() } } 'open failed'
            $lease.DeleteTrace()
        } finally { $lease.Dispose() }
        Assert-Equal ([IO.File]::ReadAllText((Join-Path $path 'state.json'))) '{"original":1}' 'Trace replacement changed channel state.'
        Assert-True (-not [IO.File]::Exists((Join-Path $path 'eaphost-trace.json'))) 'Trace intent deletion did not close its owned file.'
    }
    Test-Case 'trace intent uses the same protected ACL and single-link validation as channel state' {
        $path=Join-Path $caseRoot 'unsafe trace intent'
        $lease=New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { $lease.SaveNewTrace('{"trace":1}') } finally { $lease.Dispose() }
        $file=Join-Path $path 'eaphost-trace.json'
        $acl=Get-Acl -LiteralPath $file; $original=$acl.Sddl
        $acl.SetAccessRuleProtection($false,$true); Set-Acl -LiteralPath $file -AclObject $acl
        $lease=New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { Assert-Throws { $lease.ReadTrace() } 'unsafe' } finally { $lease.Dispose() }
        $acl.SetSecurityDescriptorSddlForm($original); Set-Acl -LiteralPath $file -AclObject $acl
        $null=New-Item -Path (Join-Path $caseRoot 'trace state alias.json') -ItemType HardLink -Target $file -ErrorAction Stop
        $lease=New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { Assert-Throws { $lease.ReadTrace() } 'hard link' } finally { $lease.Dispose() }
        Assert-Equal ([IO.File]::ReadAllText($file)) '{"trace":1}' 'Invalid trace intent was altered.'
    }
    Test-Case 'trace output resolves the PowerShell location and literal FileSystem paths' {
        Push-Location -LiteralPath $caseRoot
        try {
            Assert-Equal (Resolve-LoggingOutputDirectory) (Join-Path $caseRoot 'Dot1x-Report') 'Default trace output ignored the PowerShell location.'
            Assert-Equal (Resolve-LoggingOutputDirectory '.\output [literal]') (Join-Path $caseRoot 'output [literal]') 'Literal relative output path changed.'
            Assert-Throws { Resolve-LoggingOutputDirectory 'Env:TEMP' } 'FileSystem provider'
        } finally { Pop-Location }
    }
    Test-Case 'trace directory creates private ancestors and preserves an existing parent ACL' {
        Initialize-LoggingStore
        $parent = Join-Path $caseRoot 'trace existing parent'
        $null = [IO.Directory]::CreateDirectory($parent)
        $before = (Get-Acl -LiteralPath $parent).Sddl
        $newParent = Join-Path $parent 'new private parent'
        $path = Join-Path $newParent 'EapHost-Trace-11111111111111111111111111111111'
        $lease = New-Object Dot1xLoggingV2.DirectoryLease($path,$caller,$true,$true)
        try {
            Assert-Equal $lease.Path $path 'Trace lease did not retain the canonical path.'
            Assert-Equal (Get-Acl -LiteralPath $parent).Sddl $before 'An existing output parent ACL changed.'
            foreach ($directory in @($newParent,$path)) {
                $acl = Get-Acl -LiteralPath $directory
                Assert-True $acl.AreAccessRulesProtected 'New trace directory inherits unrelated access.'
                Assert-Equal $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value $caller 'New trace directory has a foreign owner.'
                $allowed = @($caller,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique
                $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
                Assert-Equal $rules.Count $allowed.Count 'New trace directory has unexpected access entries.'
                foreach ($rule in $rules) {
                    Assert-True ($allowed -contains $rule.IdentityReference.Value) 'Trace directory grants access to another principal.'
                    Assert-Equal $rule.FileSystemRights ([Security.AccessControl.FileSystemRights]::FullControl) 'Trace directory has unexpected rights.'
                    Assert-Equal $rule.AccessControlType ([Security.AccessControl.AccessControlType]::Allow) 'Trace directory has an unexpected access type.'
                }
            }
            Assert-True (-not $lease.ValidateTraceFile('EapHost.etl',$true)) 'A fresh trace lease contains an ETL.'
            Assert-Throws { $lease.ValidateTraceFile('EapHost.etl',$false) } 'open failed'
            Assert-Throws { $other = New-Object Dot1xLoggingV2.DirectoryLease($path,$caller,$true,$true); $other.Dispose() } 'creation failed'
            [IO.File]::WriteAllText((Join-Path $path 'EapHost.etl'),'synthetic ETL bytes')
            Assert-True $lease.ValidateTraceFile('EapHost.etl',$false) 'Ordinary inherited-ACL ETL was rejected.'
            Assert-Throws { $lease.DeleteEmptyDirectory() } 'cleanup failed'
            Assert-Equal ([IO.File]::ReadAllText((Join-Path $path 'EapHost.etl'))) 'synthetic ETL bytes' 'Populated trace output was changed during cleanup.'
        } finally { $lease.Dispose() }
        $lease = New-Object Dot1xLoggingV2.DirectoryLease($path,$caller,$false,$false)
        try {
            Assert-True $lease.ValidateTraceFile('EapHost.etl',$false) 'Completed ETL did not survive reopening.'
            Assert-Throws { $lease.DeleteEmptyDirectory() } 'Only this lease'
        } finally { $lease.Dispose() }
    }
    Test-Case 'trace resume rejects missing or unsafe output without repairing it' {
        $missing = Join-Path $caseRoot 'missing trace'
        Assert-Throws { $lease = New-Object Dot1xLoggingV2.DirectoryLease($missing,$caller,$false,$false); $lease.Dispose() } 'open failed'
        Assert-True (-not [IO.Directory]::Exists($missing)) 'Resume created missing output.'
        $unsafe = Join-Path $caseRoot 'unsafe trace'
        $null = [IO.Directory]::CreateDirectory($unsafe)
        $before = (Get-Acl -LiteralPath $unsafe).Sddl
        Assert-Throws { $lease = New-Object Dot1xLoggingV2.DirectoryLease($unsafe,$caller,$false,$false); $lease.Dispose() } 'unsafe'
        Assert-Equal (Get-Acl -LiteralPath $unsafe).Sddl $before 'Resume replaced an unsafe output ACL.'
    }
    Test-Case 'trace output rejects junction ancestors and hard-linked or reparse ETL files' {
        $target = Join-Path $caseRoot 'trace junction target'
        $null = [IO.Directory]::CreateDirectory($target)
        $junction = Join-Path $caseRoot 'trace junction'
        $null = New-Item -Path $junction -ItemType Junction -Target $target -ErrorAction Stop
        try {
            Assert-Throws { $lease = New-Object Dot1xLoggingV2.DirectoryLease((Join-Path $junction 'new trace'),$caller,$true,$true); $lease.Dispose() } 'reparse point'
            Assert-Equal @([IO.Directory]::EnumerateFileSystemEntries($target)).Count 0 'Trace creation wrote through a junction.'
        } finally { [IO.Directory]::Delete($junction) }
        $path = Join-Path $caseRoot 'linked trace files'
        $lease = New-Object Dot1xLoggingV2.DirectoryLease($path,$caller,$true,$true)
        try {
            $etl = Join-Path $path 'EapHost.etl'
            [IO.File]::WriteAllText($etl,'keep linked bytes')
            $alias = Join-Path $caseRoot 'etl alias'
            $null = New-Item -Path $alias -ItemType HardLink -Target $etl -ErrorAction Stop
            Assert-Throws { $lease.ValidateTraceFile('EapHost.etl',$false) } 'hard link'
            Assert-Equal ([IO.File]::ReadAllText($alias)) 'keep linked bytes' 'Hard-linked ETL was modified.'
            $reparse = Join-Path $path 'reparse.etl'
            $null = New-Item -Path $reparse -ItemType Junction -Target $target -ErrorAction Stop
            try { Assert-Throws { $lease.ValidateTraceFile('reparse.etl',$false) } 'reparse point|open failed' }
            finally { [IO.Directory]::Delete($reparse) }
            Assert-Throws { $lease.ValidateTraceFile('..\etl alias',$false) } 'one local filename'
        } finally { $lease.Dispose() }
    }
    Test-Case 'trace file validation accepts explicit private ACLs and rejects foreign or incomplete access' {
        $path = Join-Path $caseRoot 'trace file ACLs'
        $lease = New-Object Dot1xLoggingV2.DirectoryLease($path,$caller,$true,$true)
        try {
            $etl = Join-Path $path 'EapHost.etl'
            [IO.File]::WriteAllText($etl,'private synthetic bytes')
            $original = (Get-Acl -LiteralPath $etl).Sddl
            $acl = Get-Acl -LiteralPath $etl
            $acl.SetAccessRuleProtection($true,$true)
            Set-Acl -LiteralPath $etl -AclObject $acl
            # Reload the persisted explicit ACEs; PurgeAccessRules skips inherited ACEs.
            $acl = Get-Acl -LiteralPath $etl
            $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
            Assert-True ($acl.AreAccessRulesProtected -and @($rules | Where-Object { $_.IsInherited }).Count -eq 0) 'Explicit ACL fixture retained inherited ACEs.'
            Assert-True $lease.ValidateTraceFile('EapHost.etl',$false,$true) 'Equivalent explicit private ACL was rejected.'
            $foreign = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($foreign,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($rule); Set-Acl -LiteralPath $etl -AclObject $acl
            Assert-Throws { $lease.ValidateTraceFile('EapHost.etl',$true) } 'ACL is unsafe'
            $acl.RemoveAccessRuleSpecific($rule)
            $acl.PurgeAccessRules((New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))
            Set-Acl -LiteralPath $etl -AclObject $acl
            $savedAcl = Get-Acl -LiteralPath $etl
            $savedRules = @($savedAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
            Assert-True ($savedAcl.AreAccessRulesProtected -and @($savedRules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-18' }).Count -eq 0) ('Incomplete ACL fixture still grants SYSTEM: '+$savedAcl.Sddl)
            Assert-Throws { $lease.ValidateTraceFile('EapHost.etl',$true) } 'ACL is incomplete'
            $acl.SetSecurityDescriptorSddlForm($original); Set-Acl -LiteralPath $etl -AclObject $acl
            Assert-True $lease.ValidateTraceFile('EapHost.etl',$false,$true) 'Restored inherited ACL remained invalid.'
        } finally { $lease.Dispose() }
    }
    Test-Case 'finalized trace validation rejects a competing writer and holds the directory path' {
        $path = Join-Path $caseRoot 'trace writer'
        $lease = New-Object Dot1xLoggingV2.DirectoryLease($path,$caller,$true,$true)
        try {
            $etl = Join-Path $path 'EapHost.etl'
            [IO.File]::WriteAllText($etl,'synthetic pending trace')
            $writer = New-Object IO.FileStream($etl,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
            try {
                Assert-True $lease.ValidateTraceFile('EapHost.etl',$false) 'Active-writer metadata validation was rejected.'
                Assert-Throws { $lease.ValidateTraceFile('EapHost.etl',$false,$true) } 'open failed'
            } finally { $writer.Dispose() }
            Assert-True $lease.ValidateTraceFile('EapHost.etl',$false,$true) 'Closed trace failed finalized validation.'
            Assert-Throws { [IO.Directory]::Move($path,($path+'-moved')) }
            Assert-True ([IO.Directory]::Exists($path)) 'Leased trace directory moved.'
            Assert-True (-not [IO.Directory]::Exists($path+'-moved')) 'Leased trace directory acquired a moved alias.'
        } finally { $lease.Dispose() }
    }
    Test-Case 'only a newly created empty trace leaf can be removed through its lease' {
        $path = Join-Path $caseRoot 'empty trace cleanup'
        $lease = New-Object Dot1xLoggingV2.DirectoryLease($path,$caller,$true,$true)
        try { $lease.DeleteEmptyDirectory() } finally { $lease.Dispose() }
        Assert-True (-not [IO.Directory]::Exists($path)) 'New empty trace output was not removed.'
        Assert-True ([IO.Directory]::Exists($caseRoot)) 'Cleanup removed the existing parent.'
    }
    Test-Case 'state store rejects unsafe existing ACL without rewriting it' {
        $path = Join-Path $caseRoot 'unsafe'
        $null = [IO.Directory]::CreateDirectory($path)
        $before = (Get-Acl -LiteralPath $path).Sddl
        Assert-Throws { $lease = New-Object Dot1xLoggingV2.Store($path,$caller,$true); $lease.Dispose() } 'unsafe'
        Assert-Equal (Get-Acl -LiteralPath $path).Sddl $before 'Unsafe directory ACL was silently replaced.'
    }
    Test-Case 'state store rejects foreign owner, inherited state ACL, and oversized state' {
        $path = Join-Path $caseRoot 'validation'
        $lease = New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { $lease.SaveNew('{"fixture":1}') } finally { $lease.Dispose() }
        Assert-Throws { $other = New-Object Dot1xLoggingV2.Store($path,'S-1-5-21-1-2-3-1001',$true); $other.Dispose() } 'unsafe'
        $file = Join-Path $path 'state.json'
        $acl = Get-Acl -LiteralPath $file; $original = $acl.Sddl
        $acl.SetAccessRuleProtection($false,$true); Set-Acl -LiteralPath $file -AclObject $acl
        $lease = New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { Assert-Throws { $lease.Read() } 'unsafe' } finally { $lease.Dispose() }
        $acl.SetSecurityDescriptorSddlForm($original); Set-Acl -LiteralPath $file -AclObject $acl
        [IO.File]::WriteAllText($file,('x' * 65537))
        $lease = New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { Assert-Throws { $lease.Read() } 'size is invalid' } finally { $lease.Dispose() }
    }
    Test-Case 'state store rejects reparse paths and hard-linked baselines' {
        $target = Join-Path $caseRoot 'target'
        $null = [IO.Directory]::CreateDirectory($target)
        $junction = Join-Path $caseRoot 'junction'
        $null = New-Item -Path $junction -ItemType Junction -Target $target -ErrorAction Stop
        try { Assert-Throws { $lease = New-Object Dot1xLoggingV2.Store((Join-Path $junction 'state'),$caller,$true); $lease.Dispose() } 'reparse point' }
        finally { [IO.Directory]::Delete($junction) }
        Assert-Equal @([IO.Directory]::EnumerateFileSystemEntries($target)).Count 0 'Reparse target was changed.'
        $path = Join-Path $caseRoot 'hardlink'
        $lease = New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { $lease.SaveNew('{"fixture":1}') } finally { $lease.Dispose() }
        $file = Join-Path $path 'state.json'
        $null = New-Item -Path (Join-Path $caseRoot 'alias.json') -ItemType HardLink -Target $file -ErrorAction Stop
        $lease = New-Object Dot1xLoggingV2.Store($path,$caller,$true)
        try { Assert-Throws { $lease.Read() } 'hard link' } finally { $lease.Dispose() }
        Assert-Equal ([IO.File]::ReadAllText($file)) '{"fixture":1}' 'Hard-linked baseline was modified.'
    }
} finally { [IO.Directory]::Delete($caseRoot,$true) }
Complete-Tests

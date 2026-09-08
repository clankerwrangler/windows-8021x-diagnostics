<#
.SYNOPSIS
Checks helper-owned ETW lifecycle on a disposable GitHub Windows runner.
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ScratchPath,
    [string]$HelperPath
)
if (-not $PSBoundParameters.ContainsKey('HelperPath')) { $HelperPath=Join-Path (Split-Path $PSScriptRoot -Parent) 'Set-8021xLogging.ps1' }
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'This native fixture requires a disposable GitHub Windows runner.' }
. $HelperPath
Initialize-LoggingStore
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $caller=$identity.User.Value
    if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The native fixture requires an elevated runner.' }
} finally { $identity.Dispose() }
function Assert-NativeTrace { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Dot1xEtwFixture {
    public sealed class Provider : IDisposable {
        [DllImport("advapi32.dll",ExactSpelling=true)] static extern uint EventRegister(ref Guid provider,IntPtr callback,IntPtr context,out ulong handle);
        [DllImport("advapi32.dll",ExactSpelling=true)] static extern uint EventUnregister(ulong handle);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint EventWriteString(ulong handle,byte level,ulong keyword,string text);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint StartTraceW(out ulong handle,string name,IntPtr properties);
        public static void StartDifferentMode(string name,IntPtr properties) { ulong value; uint code=StartTraceW(out value,name,properties); if(code!=0) throw new Win32Exception((int)code); }
        ulong handle;
        public Provider(Guid id) { uint code=EventRegister(ref id,IntPtr.Zero,IntPtr.Zero,out handle); if(code!=0) throw new Win32Exception((int)code); }
        public void Write() { uint code=EventWriteString(handle,0,1,"dot1x synthetic lifecycle event"); if(code!=0) throw new Win32Exception((int)code); }
        public void Dispose() { if(handle!=0) { uint code=EventUnregister(handle); if(code!=0) throw new Win32Exception((int)code); handle=0; } }
    }
}
'@
$flags=[Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static
$ensure=[Dot1xLoggingV2.EapHostTrace].GetMethod('EnsureForProvider',$flags)
$guard=[Dot1xLoggingV2.EapHostTrace].GetMethod('CheckProvider',$flags)
Assert-NativeTrace ($null -ne $ensure -and $null -ne $guard) 'Native test boundaries are unavailable.'
$root=New-Object Dot1xLoggingV2.DirectoryLease((Join-Path $ScratchPath ('native-eaphost-'+[guid]::NewGuid().ToString('N'))),$caller,$false,$true)
$sessions=New-Object 'System.Collections.Generic.List[object]'
$providers=New-Object 'System.Collections.Generic.List[object]'
function New-NativeTraceFixture {
    $id=[guid]::NewGuid()
    $lease=New-Object Dot1xLoggingV2.DirectoryLease((Join-Path $root.Path ('EapHost-Trace-'+$id.ToString('N'))),$caller,$false,$true)
    $item=[pscustomobject]@{Id=$id;Name=('Dot1xLogging-EapHost-'+$id.ToString('N'));Path=(Join-Path $lease.Path 'EapHost.etl');Lease=$lease}
    $sessions.Add($item)
    return $item
}
function Invoke-NativeFixtureEnsure {
    param([guid]$Provider,$Item)
    # Reflection does not apply PowerShell's normal PSObject argument conversion.
    $arguments=[object[]]@(([guid]$Provider).PSObject.BaseObject,([guid]$Item.Id).PSObject.BaseObject,([string]$Item.Name).PSObject.BaseObject,([string]$Item.Path).PSObject.BaseObject)
    $ensure.Invoke($null,$arguments)
}
function Assert-NativeForeignGuard {
    param([guid]$Provider)
    $message=''
    try { $guard.Invoke($null,[object[]]@(([guid]$Provider).PSObject.BaseObject,$null)) }
    catch { $message=$_.Exception.ToString() }
    Assert-NativeTrace ($message -match 'already enabled by another session') 'Provider metadata did not identify the foreign enabled session.'
}
$clean=$true
$integrationDirectory=$null
try {
    Write-Output ('RECEIPT helper_sha256='+(Get-FileHash -LiteralPath $HelperPath -Algorithm SHA256).Hash.ToLowerInvariant()+' ps='+$PSVersionTable.PSVersion.ToString())
    # A registered provider proves re-query and LoggerId-to-handle matching.
    $registeredId=[guid]::NewGuid()
    $provider=New-Object Dot1xEtwFixture.Provider($registeredId); $providers.Add($provider)
    $item=New-NativeTraceFixture
    $first=Invoke-NativeFixtureEnsure $registeredId $item
    $provider.Write()
    $again=Invoke-NativeFixtureEnsure $registeredId $item
    Assert-NativeTrace ($first.Handle -eq $again.Handle) 'Repeated enable replaced the owned session.'
    Assert-NativeTrace ($again.MaximumFileSize -eq 256) 'The circular file bound was lost.'
    Assert-NativeForeignGuard $registeredId
    $other=New-NativeTraceFixture
    $conflict=''
    try { $null=Invoke-NativeFixtureEnsure $registeredId $other } catch { $conflict=$_.Exception.ToString() }
    Assert-NativeTrace ($conflict -match 'already enabled by another session') 'A foreign activation was accepted.'
    Assert-NativeTrace ($null -eq [Dot1xLoggingV2.EapHostTrace]::Query($other.Id,$other.Name,$other.Path)) 'The conflict started a second trace session.'
    [Dot1xLoggingV2.EapHostTrace]::Stop($item.Id,$item.Name,$item.Path)
    [Dot1xLoggingV2.EapHostTrace]::Stop($item.Id,$item.Name,$item.Path)
    Assert-NativeTrace ($item.Lease.ValidateTraceFile('EapHost.etl',$false,$true)) 'The finalized synthetic ETL is missing or unsafe.'
    Assert-NativeTrace ((New-Object IO.FileInfo($item.Path)).Length -gt 0) 'The finalized synthetic ETL is empty.'
    Write-Output 'PASS registered provider, owned LoggerId, conflict, repeat, stop, and finalized ETL'

    # Enable before registration: the guard must see PRE_ENABLE information.
    $dormantId=[guid]::NewGuid()
    $dormant=New-NativeTraceFixture
    $first=Invoke-NativeFixtureEnsure $dormantId $dormant
    Assert-NativeForeignGuard $dormantId
    $again=Invoke-NativeFixtureEnsure $dormantId $dormant
    Assert-NativeTrace ($first.Handle -eq $again.Handle) 'Pre-enabled session ownership was not retained.'
    $late=New-Object Dot1xEtwFixture.Provider($dormantId); $providers.Add($late)
    $late.Write()
    Assert-NativeForeignGuard $dormantId
    $null=Invoke-NativeFixtureEnsure $dormantId $dormant
    [Dot1xLoggingV2.EapHostTrace]::Stop($dormant.Id,$dormant.Name,$dormant.Path)
    Assert-NativeTrace ($dormant.Lease.ValidateTraceFile('EapHost.etl',$false,$true)) 'The late-registration ETL is missing or unsafe.'
    Write-Output 'PASS pre-enabled provider guard and later registration'

    # Unexpected settings remain recoverable when GUID, name, and path are owned.
    $changed=New-NativeTraceFixture
    $newProperties=[Dot1xLoggingV2.EapHostTrace].GetMethod('NewProperties',$flags)
    $arguments=[object[]]@(([guid]$changed.Id).PSObject.BaseObject,([string]$changed.Path).PSObject.BaseObject,([bool]$true).PSObject.BaseObject)
    $properties=$newProperties.Invoke($null,$arguments)
    try {
        $type=[Dot1xLoggingV2.EapHostTrace].Assembly.GetType('Dot1xLoggingV2.TraceProperties')
        $modeOffset=[Runtime.InteropServices.Marshal]::OffsetOf($type,'LogFileMode').ToInt32()
        [Runtime.InteropServices.Marshal]::WriteInt32($properties,$modeOffset,0x10000001)
        [Dot1xEtwFixture.Provider]::StartDifferentMode($changed.Name,$properties)
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($properties) }
    $mismatch=''
    try { $null=Invoke-NativeFixtureEnsure ([guid]::NewGuid()) $changed } catch { $mismatch=$_.Exception.ToString() }
    Assert-NativeTrace ($mismatch -match 'settings differ') 'Enable accepted mismatched session settings.'
    [Dot1xLoggingV2.EapHostTrace]::Stop($changed.Id,$changed.Name,$changed.Path)
    Assert-NativeTrace ($null -eq [Dot1xLoggingV2.EapHostTrace]::Query($changed.Id,$changed.Name,$changed.Path)) 'Restore could not stop owned mismatched settings.'
    Write-Output 'PASS owned settings mismatch rejected for enable and recovered by stop'

    # The real fixed provider is reached only after both coexistence checks pass.
    $actual=New-NativeTraceFixture
    $first=[Dot1xLoggingV2.EapHostTrace]::Ensure($actual.Id,$actual.Name,$actual.Path)
    $again=[Dot1xLoggingV2.EapHostTrace]::Ensure($actual.Id,$actual.Name,$actual.Path)
    Assert-NativeTrace ($first.Handle -eq $again.Handle) 'Repeated EapHost enable replaced the session.'
    Assert-NativeTrace ($again.MaximumFileSize -eq 256 -and $again.LogFileMode -eq 0x10400002) 'EapHost trace settings differ from the fixed capture bounds.'
    [Dot1xLoggingV2.EapHostTrace]::Stop($actual.Id,$actual.Name,$actual.Path)
    Assert-NativeTrace ($null -eq [Dot1xLoggingV2.EapHostTrace]::Query($actual.Id,$actual.Name,$actual.Path)) 'EapHost stop did not establish absence.'
    Assert-NativeTrace ($actual.Lease.ValidateTraceFile('EapHost.etl',$false,$true)) 'The finalized EapHost ETL is missing or unsafe.'
    Assert-NativeTrace ((New-Object IO.FileInfo($actual.Path)).Length -gt 0) 'The finalized EapHost ETL is empty.'
    Write-Output 'PASS fixed EapHost provider ensure, repeat, query, stop, and finalized ETL'

    # Keep the state store, directory lease, and ETW path real across helper calls.
    # Only channel/registry adapters use synthetic settings.
    $integrationDirectory=[IO.Path]::Combine($root.Path,'orchestration-state')
    $integrationMachine='native-fixture-machine'
    $script:integrationConfiguration=@{
        'Microsoft-Windows-Wired-AutoConfig/Operational'=[pscustomobject]@{Enabled=$false;MaximumSize=1048576L}
        'Microsoft-Windows-WLAN-AutoConfig/Operational'=[pscustomobject]@{Enabled=$true;MaximumSize=209715200L}
    }
    $script:integrationSchannel=[pscustomobject]@{Present=$true;Value=3L}
    function Invoke-LoggingNative {
        param([string[]]$Arguments)
        if ($Arguments[0] -eq 'el') { return [pscustomobject]@{ExitCode=0;Text=($script:integrationConfiguration.Keys -join "`r`n")} }
        $name=$Arguments[1]
        if (-not $script:integrationConfiguration.ContainsKey($name)) { throw 'Unexpected integration channel.' }
        $setting=$script:integrationConfiguration[$name]
        if ($Arguments[0] -eq 'sl') {
            $setting.Enabled=[bool]::Parse($Arguments[2].Substring(3))
            $setting.MaximumSize=[long]::Parse($Arguments[3].Substring(4))
            return [pscustomobject]@{ExitCode=0;Text=''}
        }
        if ($Arguments[0] -ne 'gl') { throw 'Unexpected integration native action.' }
        $text='<channel xmlns="http://schemas.microsoft.com/win/2004/08/events" name="'+$name+'" enabled="'+$setting.Enabled.ToString().ToLowerInvariant()+'"><logging><maxSize>'+$setting.MaximumSize+'</maxSize></logging></channel>'
        return [pscustomobject]@{ExitCode=0;Text=$text}
    }
    function Get-LoggingSchannel { return $script:integrationSchannel }
    function Set-LoggingSchannel {
        param($Setting)
        $script:integrationSchannel=[pscustomobject]@{Present=$Setting.Present;Value=$Setting.Value}
    }
    $legacy=New-LoggingState $integrationMachine $caller $true
    Assert-NativeTrace ($legacy.Version -eq 1) 'The persisted integration baseline is not v1.'
    $store=New-Object Dot1xLoggingV2.Store($integrationDirectory,$caller,$true)
    try { $store.SaveNew(($legacy|ConvertTo-Json -Depth 6 -Compress)) } finally { $store.Dispose() }
    $baselinePath=[IO.Path]::Combine($integrationDirectory,'state.json')
    $traceRecordPath=[IO.Path]::Combine($integrationDirectory,'eaphost-trace.json')
    $baselineBytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($baselinePath))
    Assert-NativeTrace (-not [IO.File]::Exists($traceRecordPath)) 'A trace record preceded the upgrade Enable.'
    $outputParent=[IO.Path]::Combine($root.Path,'orchestration-report')
    $store=New-Object Dot1xLoggingV2.Store($integrationDirectory,$caller,$false)
    try { Invoke-LoggingSession $store $integrationMachine $caller $false $true $outputParent } finally { $store.Dispose() }
    Assert-NativeTrace ($baselineBytes -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($baselinePath))) 'Enable rewrote the original v1 baseline.'
    $traceBytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($traceRecordPath))
    $store=New-Object Dot1xLoggingV2.Store($integrationDirectory,$caller,$false)
    try { $traceState=ConvertFrom-Json -InputObject $store.ReadTrace() } finally { $store.Dispose() }
    Assert-LoggingTraceState $traceState $integrationMachine $caller
    $first=Invoke-LoggingTraceNative -Action Query -State $traceState
    Assert-NativeTrace ($null -ne $first) 'Default Enable did not start the saved trace.'
    Assert-NativeTrace ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($traceState.TracePath)) -ceq $outputParent) 'The integration trace ignored its output parent.'
    foreach ($setting in $script:integrationConfiguration.Values) { Assert-NativeTrace ($setting.Enabled -and $setting.MaximumSize -ge 104857600L) 'Enable did not prepare the mock channel.' }
    Assert-NativeTrace ($script:integrationConfiguration['Microsoft-Windows-WLAN-AutoConfig/Operational'].MaximumSize -eq 209715200L) 'Enable shrank the larger mock channel.'
    Assert-NativeTrace ($script:integrationSchannel.Value -eq 7) 'Enable did not apply the mock Schannel value.'
    $store=New-Object Dot1xLoggingV2.Store($integrationDirectory,$caller,$false)
    try { Invoke-LoggingSession $store $integrationMachine $caller $false $true $outputParent } finally { $store.Dispose() }
    Assert-NativeTrace ($baselineBytes -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($baselinePath))) 'Repeated Enable rewrote the v1 baseline.'
    Assert-NativeTrace ($traceBytes -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($traceRecordPath))) 'Repeated Enable rewrote the trace intent.'
    $again=Invoke-LoggingTraceNative -Action Query -State $traceState
    Assert-NativeTrace ($null -ne $again -and $first.Handle -eq $again.Handle) 'Repeated helper Enable replaced the native trace.'
    $store=New-Object Dot1xLoggingV2.Store($integrationDirectory,$caller,$false)
    try { Invoke-LoggingSession $store $integrationMachine $caller $true $false '' } finally { $store.Dispose() }
    Assert-NativeTrace ($null -eq (Invoke-LoggingTraceNative -Action Query -State $traceState)) 'Helper Restore left the native trace active.'
    Assert-NativeTrace (-not [IO.File]::Exists($baselinePath) -and -not [IO.File]::Exists($traceRecordPath)) 'Helper Restore retained completed recovery records.'
    foreach ($channel in $legacy.Channels) {
        $restored=$script:integrationConfiguration[$channel.Name]
        Assert-NativeTrace ($restored.Enabled -eq $channel.Enabled -and $restored.MaximumSize -eq $channel.MaximumSize) 'Restore did not recover the original mock channel settings.'
    }
    Assert-NativeTrace ($script:integrationSchannel.Present -eq $legacy.Schannel.Present -and $script:integrationSchannel.Value -eq $legacy.Schannel.Value) 'Restore did not recover the original mock Schannel value.'
    $lease=New-Object Dot1xLoggingV2.DirectoryLease(([IO.Path]::GetDirectoryName($traceState.TracePath)),$caller,$false,$false)
    try { Assert-NativeTrace ($lease.ValidateTraceFile('EapHost.etl',$false,$true)) 'Helper Restore did not finalize a safe ETL.' } finally { $lease.Dispose() }
    Assert-NativeTrace ((New-Object IO.FileInfo($traceState.TracePath)).Length -gt 0) 'The helper integration ETL is empty.'
    Write-Output 'PASS helper integration: v1 upgrade, durable trace intent, repeat identity, restored mock settings, and finalized ETL'
} catch {
    Write-Output ('FAIL native lifecycle: '+$_.Exception.ToString())
    $failure=$_.Exception
    while ($null -ne $failure) {
        if ($failure -is [ComponentModel.Win32Exception]) { Write-Output ('NATIVE_CODE='+$failure.NativeErrorCode+' '+$failure.Message) }
        $failure=$failure.InnerException
    }
    throw
} finally {
    if ($null -ne $integrationDirectory) {
        $recoveryStore=$null
        try {
            $recoveryStore=New-Object Dot1xLoggingV2.Store($integrationDirectory,$caller,$false)
            $json=$recoveryStore.ReadTrace()
            if ($null -ne $json) {
                $recoveryState=ConvertFrom-Json -InputObject $json
                Assert-LoggingTraceState $recoveryState $integrationMachine $caller
                $null=Invoke-LoggingTraceNative -Action Stop -State $recoveryState
            }
        } catch { $clean=$false; Write-Warning ('Owned integration trace cleanup failed: '+$_.Exception.Message) }
        finally { if ($null -ne $recoveryStore) { $recoveryStore.Dispose() } }
    }
    foreach ($item in $sessions) {
        try { [Dot1xLoggingV2.EapHostTrace]::Stop($item.Id,$item.Name,$item.Path) }
        catch { $clean=$false; Write-Warning ('Owned fixture trace cleanup failed: '+$_.Exception.Message) }
    }
    foreach ($provider in $providers) { try { $provider.Dispose() } catch { $clean=$false } }
    foreach ($item in $sessions) { $item.Lease.Dispose() }
    $rootPath=$root.Path; $root.Dispose()
    if ($clean) { [IO.Directory]::Delete($rootPath,$true) }
    else { throw ('Native fixture cleanup is incomplete; retained private output: '+$rootPath) }
}

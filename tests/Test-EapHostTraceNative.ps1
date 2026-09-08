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
    $ensure.Invoke($null,[object[]]@($Provider,$Item.Id,$Item.Name,$Item.Path))
}
function Assert-NativeForeignGuard {
    param([guid]$Provider)
    $message=''
    try { $guard.Invoke($null,[object[]]@($Provider,$null)) }
    catch { $message=$_.Exception.ToString() }
    Assert-NativeTrace ($message -match 'already enabled by another session') 'Provider metadata did not identify the foreign enabled session.'
}
$clean=$true
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
    $properties=$newProperties.Invoke($null,[object[]]@($changed.Id,$changed.Path,$true))
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
    Assert-NativeTrace ($again.MaximumFileSize -eq 256 -and $again.LogFileMode -eq 0x10000002) 'EapHost trace settings differ from the fixed capture bounds.'
    [Dot1xLoggingV2.EapHostTrace]::Stop($actual.Id,$actual.Name,$actual.Path)
    Assert-NativeTrace ($null -eq [Dot1xLoggingV2.EapHostTrace]::Query($actual.Id,$actual.Name,$actual.Path)) 'EapHost stop did not establish absence.'
    Assert-NativeTrace ($actual.Lease.ValidateTraceFile('EapHost.etl',$false,$true)) 'The finalized EapHost ETL is missing or unsafe.'
    Assert-NativeTrace ((New-Object IO.FileInfo($actual.Path)).Length -gt 0) 'The finalized EapHost ETL is empty.'
    Write-Output 'PASS fixed EapHost provider ensure, repeat, query, stop, and finalized ETL'
} finally {
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

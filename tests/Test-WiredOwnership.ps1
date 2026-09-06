<#
.SYNOPSIS
Tests private output and wired XML ownership with synthetic files and workers only.
.DESCRIPTION
No real netsh export, network query, profile read, or configuration change runs.
#>
[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1'),
    [Parameter(Mandatory=$true)][string]$ScratchPath
)
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
. (Join-Path $PSScriptRoot 'Xml-Fixtures.ps1')
. $ScriptPath
$caseRoot = Join-Path $ScratchPath ('wired-fixtures-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -Path $caseRoot -ItemType Directory -ErrorAction Stop
$worker = Join-Path $caseRoot 'fake-worker.ps1'
$workerCode = @'
param([string]$WorkerName,[string]$WorkerContext)
$ErrorActionPreference='Stop'
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($WorkerContext))|ConvertFrom-Json
[IO.File]::WriteAllText((Join-Path $c.WiredTempDirectory 'fixture.xml'),'<LANProfile><fixture>synthetic</fixture></LANProfile>')
[IO.File]::WriteAllText($c.MarkerPath,($c.WiredTempDirectory+'|'+$PID))
if($c.Mode -eq 'Timeout'){Start-Sleep -Seconds 30}
[Console]::WriteLine('{"Status":"Succeeded","Data":{},"Limitations":[]}')
'@
[IO.File]::WriteAllText($worker,$workerCode,[Text.Encoding]::ASCII)
try {
    Test-Case 'private directory has a protected owner-scoped DACL' {
        $lease = New-Dot1xPrivateDirectory -Path (Join-Path $caseRoot 'private-output')
        try {
            $acl = Get-Acl -LiteralPath $lease.Path
            $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $allowed = @($sid,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique
            $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
            Assert-True $acl.AreAccessRulesProtected 'Output DACL inherits unreviewed access.'
            Assert-Equal $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value $sid 'Output owner differs from execution identity.'
            Assert-Equal $rules.Count @($allowed).Count 'Output DACL has unexpected entries.'
            foreach($rule in $rules){
                Assert-True ($allowed -contains $rule.IdentityReference.Value) 'Output DACL grants another principal.'
                Assert-Equal $rule.AccessControlType ([Security.AccessControl.AccessControlType]::Allow) 'Output DACL has an unexpected access type.'
                Assert-Equal $rule.FileSystemRights ([Security.AccessControl.FileSystemRights]::FullControl) 'Output rights differ from the reviewed contract.'
                Assert-True (-not $rule.IsInherited) 'Output DACL entry is inherited.'
            }
        } finally { $lease.DeleteEmptyDirectory(); $lease.Dispose() }
    }
    Test-Case 'private directory helper does not create missing parents by default' {
        $parent = Join-Path $caseRoot 'missing-wired-parent'
        $threw = $false; $lease = $null
        try { $lease = New-Dot1xPrivateDirectory -Path (Join-Path $parent 'transport') }
        catch { $threw = $true }
        finally { if($null -ne $lease){$lease.Dispose()} }
        Assert-True $threw 'The wired-default helper silently created missing parents.'
        Assert-True (-not (Test-Path -LiteralPath $parent)) 'The wired-default helper changed a missing ancestor.'
    }
    Test-Case 'private directory leaf remains exclusive with existing content and ACL preserved' {
        $path = Join-Path $caseRoot 'existing private leaf'
        $lease = New-Dot1xPrivateDirectory -Path $path
        $lease.Dispose()
        $sentinel = Join-Path $path 'keep.txt'
        [IO.File]::WriteAllText($sentinel,'synthetic exclusive-leaf sentinel')
        $beforeAcl = (Get-Acl -LiteralPath $path).Sddl
        $threw = $false; $unexpected = $null
        try { $unexpected = New-Dot1xPrivateDirectory -Path $path -CreateParents }
        catch { $threw = $true }
        finally { if($null -ne $unexpected){$unexpected.Dispose()} }
        Assert-True $threw 'Report parent creation weakened exclusive leaf creation.'
        Assert-Equal ([IO.File]::ReadAllText($sentinel)) 'synthetic exclusive-leaf sentinel' 'An existing private leaf file changed.'
        Assert-Equal (Get-Acl -LiteralPath $path).Sddl $beforeAcl 'An existing private leaf ACL changed.'
        Assert-Equal @(Get-ChildItem -LiteralPath $path -Force).Count 1 'An existing private leaf was modified.'
    }
    foreach($mode in @('Complete','Timeout')) {
        Test-Case ('parent removes synthetic wired XML after worker ' + $mode) {
            $marker = Join-Path $caseRoot ($mode + '-marker.txt')
            $context = [ordered]@{ MarkerPath=$marker; Mode=$mode }
            $probe = Invoke-Dot1xProbe -Name Wired -ScriptPath $worker -Context $context -TimeoutSeconds 3
            Assert-True (Test-Path -LiteralPath $marker -PathType Leaf) 'Worker did not publish the controlled transport identity.'
            $parts = [IO.File]::ReadAllText($marker).Split('|')
            $expected = if($mode -eq 'Complete'){'Succeeded'}else{'TimedOut'}
            Assert-Equal $probe.Status $expected 'Controlled worker outcome was not preserved.'
            Assert-Equal $probe.CleanupConfirmed $true 'Owned job emptiness was not confirmed.'
            Assert-Equal @(Get-Process -Id ([int]$parts[1]) -ErrorAction SilentlyContinue).Count 0 'Owned writer remains alive.'
            Assert-True (-not (Test-Path -LiteralPath $parts[0])) 'Parent left synthetic raw XML transport after confirmed writer exit.'
        }
    }

    # This replacement is script-local and starts no process. Remaining cases use it.
    $script:MockMode = ''; $script:ExportCalls = 0; $script:HeldStream = $null
    $script:MockDirectory = ''; $script:RetainedDirectory = ''
    $script:WiredXml = New-TestProfileXml -Kind Wired
    function Invoke-Dot1xProcess {
        param([string]$FilePath,[string[]]$ArgumentList,[int]$TimeoutSeconds,[int]$OutputLimitChars)
        $result = [pscustomobject]@{Status='Succeeded';ExitCode=0;StdOut='';StdErr='';DurationMs=1;ProcessId=$null;ErrorCode=$null;OutputTruncated=$false;CleanupConfirmed=$true;CleanupErrorCode=$null}
        if($script:MockMode -eq 'ProbeUnconfirmed'){
            $index=[array]::IndexOf($ArgumentList,'-WorkerContext')
            if($index -lt 0){throw 'Unexpected fixture invocation.'}
            $context=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgumentList[$index+1]))|ConvertFrom-Json
            $script:RetainedDirectory=$context.WiredTempDirectory
            [IO.File]::WriteAllText((Join-Path $script:RetainedDirectory 'fixture.xml'),$script:WiredXml)
            $result.Status='TimedOut';$result.CleanupConfirmed=$false;$result.CleanupErrorCode=999
            return $result
        }
        if($script:MockMode -notin @('ExportNormal','ExportLocked','ExportUnconfirmed')){throw 'Unexpected fixture mode.'}
        $script:ExportCalls++
        $file=Join-Path $script:MockDirectory 'fixture.xml'
        [IO.File]::WriteAllText($file,$script:WiredXml)
        if($script:MockMode -eq 'ExportLocked'){$script:HeldStream=New-Object IO.FileStream($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}
        if($script:MockMode -eq 'ExportUnconfirmed'){$result.Status='TimedOut';$result.CleanupConfirmed=$false;$result.CleanupErrorCode=999}
        return $result
    }
    Test-Case 'unconfirmed writer cleanup retains transport and an explicit limitation' {
        $script:MockMode='ProbeUnconfirmed';$script:RetainedDirectory=''
        try {
            $probe=Invoke-Dot1xProbe -Name Wired -ScriptPath $worker -Context ([ordered]@{}) -TimeoutSeconds 2
            Assert-Equal $probe.CleanupConfirmed $false 'Unconfirmed cleanup was presented as confirmed.'
            Assert-True (Test-Path -LiteralPath (Join-Path $script:RetainedDirectory 'fixture.xml')) 'Unconfirmed writer transport was removed.'
            Assert-True (($probe.Limitations -join ' ') -match 'retained') 'Retained sensitive transport was not reported.'
        } finally { if($script:RetainedDirectory -and (Test-Path -LiteralPath $script:RetainedDirectory)){Remove-Item -LiteralPath $script:RetainedDirectory -Recurse -Force} }
    }
    foreach($mode in @('ExportNormal','ExportLocked','ExportUnconfirmed')) {
        Test-Case ('per-interface transport ownership: ' + $mode) {
            $script:MockMode=$mode;$script:ExportCalls=0;$script:HeldStream=$null
            $lease=New-Dot1xPrivateDirectory -Path (Join-Path $caseRoot $mode)
            $script:MockDirectory=$lease.Path
            $context=[pscustomobject]@{WiredTempDirectory=$lease.Path;MaxProfiles=2;ProfileName='';WiredInterfaces=@(
                [pscustomobject]@{InterfaceIndex=10;InterfaceGuid='11111111-1111-1111-1111-111111111111';Alias='fixture-adapter-a'},
                [pscustomobject]@{InterfaceIndex=20;InterfaceGuid='22222222-2222-2222-2222-222222222222';Alias='fixture-adapter-b'}
            )}
            $limits=New-Object 'System.Collections.Generic.List[string]'
            try {
                $data=Get-Dot1xWired -Context $context -Limitations $limits
                if($mode -eq 'ExportNormal'){
                    Assert-Equal $script:ExportCalls 2 'Resettable transport did not preserve both interface capabilities.'
                    Assert-Equal @($data.Profiles).Count 2 'Normal synthetic exports were lost.'
                    Assert-Equal @([IO.Directory]::EnumerateFiles($lease.Path,'*.xml')).Count 0 'Normal per-interface XML was not reset.'
                } else {
                    Assert-Equal $script:ExportCalls 1 'A later adapter reused transport after cleanup failed.'
                    Assert-True ($limits.Count -gt 0) 'Failed transport ownership has no limitation.'
                    Assert-True (Test-Path -LiteralPath (Join-Path $lease.Path 'fixture.xml')) 'Unreset transport was hidden or prematurely removed.'
                    if($mode -eq 'ExportUnconfirmed'){Assert-Equal @($data.Profiles).Count 0 'XML was parsed before exporter exit was confirmed.'}
                    else{Assert-True (@($data.Profiles | Where-Object {$_.InterfaceGuid -eq '22222222-2222-2222-2222-222222222222'}).Count -eq 0) 'Old XML was attributed to the later adapter.'}
                }
            } finally {
                if($null -ne $script:HeldStream){$script:HeldStream.Dispose();$script:HeldStream=$null}
                $lease.RemoveProfileFiles();$lease.DeleteEmptyDirectory();$lease.Dispose()
            }
        }
    }
} finally { Remove-Item -LiteralPath $caseRoot -Recurse -Force -ErrorAction Stop }
Complete-Tests

<#
.SYNOPSIS
Runs a bounded, read-only host collection after explicit review of the source hash.
.DESCRIPTION
This is an endpoint smoke test, not a wired, Wi-Fi, or RADIUS authentication lab test.
The caller must authorize the exact host, execution context, scratch directory, and
source hash. The test captures raw output privately and deletes its own report directory.
No network, service, adapter, profile, certificate-store, policy, or log setting is changed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string]$ScratchPath,
    [Parameter(Mandatory=$true)][string]$ExpectedSourceSha256,
    [switch]$ExpectSystemEapHostUnsupported
)
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
. (Join-Path $PSScriptRoot 'Native-Library.ps1')
$hash = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $ExpectedSourceSha256.ToLowerInvariant()) { throw 'Source changed after review. Obtain approval for the new hash.' }
if (-not (Test-Path -LiteralPath $ScratchPath -PathType Container)) { throw 'Use the approved existing private scratch directory.' }
Write-Output ('RECEIPT source_sha256=' + $hash + ' ps=' + $PSVersionTable.PSVersion.ToString() + ' os=' + [Environment]::OSVersion.Version.ToString())
$reportPath = Join-Path $ScratchPath ('smoke-report-' + [guid]::NewGuid().ToString('N'))
$oldTemp = $env:TEMP; $oldTmp = $env:TMP
try {
    $env:TEMP = $ScratchPath; $env:TMP = $ScratchPath
    Test-Case 'bounded read-only collector produces honest scoped reports' {
        $code = '& ' + (ConvertTo-TestLiteral $ScriptPath) + ' -OutputDirectory ' + (ConvertTo-TestLiteral $reportPath) + ' -MaxEventsPerLog 2 -MaxProfiles 2 -MaxCertificatesPerStore 4 -ProbeTimeoutSeconds 15 -OverallTimeoutSeconds 150'
        $r = Invoke-TestPowerShell -Code $code -WorkingDirectory $ScratchPath -TimeoutSeconds 190
        Assert-True (-not $r.TimedOut) 'Collector exceeded the smoke bound.'
        Assert-Equal $r.ExitCode 0 'Collector did not complete with its documented exit code.'
        $runs = @(Get-ChildItem -LiteralPath $reportPath -Directory)
        Assert-Equal $runs.Count 1 'The smoke destination does not contain exactly one report run.'
        $savedPath = $runs[0].FullName
        foreach ($name in @('evidence.json','report.json','report.txt')) { Assert-True (Test-Path -LiteralPath (Join-Path $savedPath $name) -PathType Leaf) 'A documented host report artifact is missing.' }
        $evidence = [IO.File]::ReadAllText((Join-Path $savedPath 'evidence.json')) | ConvertFrom-Json
        $report = [IO.File]::ReadAllText((Join-Path $savedPath 'report.json')) | ConvertFrom-Json
        Assert-Equal $report.OutputDirectory $savedPath 'The smoke report does not identify its saved directory.'
        Assert-True ($r.Stdout.Contains('Saved reports: ' + $savedPath)) 'The smoke output does not identify its saved directory.'
        $ids = @($report.Findings | ForEach-Object { $_.Id } | Sort-Object -Unique)
        if($ExpectSystemEapHostUnsupported){
            $pair=@($evidence.EventLogs|Where-Object{$_.LogName -eq 'System' -and $_.ProviderFilter -eq 'Microsoft-Windows-EapHost'})
            Assert-Equal $pair.Count 1 'Expected System/EapHost metadata is missing.'
            Assert-Equal $pair[0].Available $true 'Existing System log was reported missing.'
            Assert-Equal $pair[0].QueryStatus 'UnsupportedProviderChannel' 'Unsupported pair was not classified accurately.'
            Assert-Equal $pair[0].ErrorCode 'LogsAndProvidersDontOverlap' 'Fixed provider/channel category was lost.'
            [pscustomobject]@{Stage='SystemEapHost';Available=$pair[0].Available;Enabled=$pair[0].Enabled;QueryStatus=$pair[0].QueryStatus;ErrorCode=$pair[0].ErrorCode}|ConvertTo-Json -Compress
        }

        Assert-True ($ids -contains 'AUTH-NOT-VERIFIED') 'Host report falsely omits the authentication-proof limitation.'
        Assert-True (@($evidence.Probes | Where-Object { $_.Status -eq 'Succeeded' }).Count -gt 0) 'No probe succeeded; this is not a working collector smoke result.'
        $incomplete = @($evidence.Probes | Where-Object { $_.Status -ne 'Succeeded' })
        if ($incomplete.Count -gt 0) { Assert-True ($ids -contains 'COLLECTION-INCOMPLETE') 'Failed, partial, or skipped collection was concealed.' }
        foreach ($profile in @($evidence.Profiles)) {
            foreach ($name in @('Xml','RawXml','Password','Username','KeyMaterial','EapHostUserCredentials')) { Assert-True ($null -eq $profile.PSObject.Properties[$name]) 'A prohibited raw profile field entered a host report.' }
        }
        [pscustomobject]@{
            Mode = 'ReadOnlyHostSmoke'; PhysicalEapLabTest = $false
            Interfaces = @($evidence.Interfaces).Count; Profiles = @($evidence.Profiles).Count
            Certificates = @($evidence.Certificates).Count; Events = @($evidence.Events).Count
            ProbesSucceeded = @($evidence.Probes | Where-Object { $_.Status -eq 'Succeeded' }).Count
            ProbesIncomplete = $incomplete.Count; FindingIds = $ids
        } | ConvertTo-Json -Compress
        foreach ($probe in $evidence.Probes) { Write-Output ('PROBE ' + $probe.Name + ' status=' + $probe.Status) }
    }
} finally {
    $env:TEMP = $oldTemp; $env:TMP = $oldTmp
    if (Test-Path -LiteralPath $reportPath) { Remove-Item -LiteralPath $reportPath -Recurse -Force -ErrorAction Stop }
}
Complete-Tests

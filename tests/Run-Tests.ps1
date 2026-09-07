<#
.SYNOPSIS
Runs dependency-free PowerShell 5.1 synthetic tests. Does not run live collection.
.PARAMETER ScratchPath
An existing, caller-owned private directory for short-lived test artifacts.
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1'),
    [Parameter(Mandatory=$true)][string]$ScratchPath
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Native-Library.ps1')
if (-not (Test-Path -LiteralPath $ScratchPath -PathType Container)) { throw 'Use an existing private scratch directory.' }
$hash = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output ('RECEIPT source_sha256=' + $hash + ' ps=' + $PSVersionTable.PSVersion.ToString() + ' os=' + [Environment]::OSVersion.Version.ToString())
$oldTemp = $env:TEMP; $oldTmp = $env:TMP
$allPassed = $true
try {
    $env:TEMP = $ScratchPath; $env:TMP = $ScratchPath
    foreach ($name in @('Test-Static.ps1','Test-Harness.ps1','Test-Rules.ps1','Test-ErrorCodes.ps1','Test-Xml.ps1','Test-Collection.ps1','Test-Process.ps1','Test-IO.ps1','Test-WiredOwnership.ps1')) {
        $code = '& ' + (ConvertTo-TestLiteral (Join-Path $PSScriptRoot $name)) + ' -ScriptPath ' + (ConvertTo-TestLiteral $ScriptPath)
        if ($name -in @('Test-Process.ps1','Test-IO.ps1','Test-WiredOwnership.ps1')) { $code += ' -ScratchPath ' + (ConvertTo-TestLiteral $ScratchPath) }
        $r = Invoke-TestPowerShell -Code $code -WorkingDirectory $ScratchPath -TimeoutSeconds 90
        foreach ($line in ($r.Stdout -split '[\r\n]+')) {
            if ($line -match '^(PASS |FAIL |\{"Passed":)') { Write-Output $line }
        }
        Write-Output ('SUITE ' + $name + ' exit=' + $r.ExitCode + ' timeout=' + $r.TimedOut)
        if ($r.ExitCode -ne 0 -or $r.TimedOut) { $allPassed = $false }
    }
} finally { $env:TEMP = $oldTemp; $env:TMP = $oldTmp }
if (-not $allPassed) { exit 1 }
exit 0

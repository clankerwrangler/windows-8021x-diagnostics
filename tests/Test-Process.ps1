<#
.SYNOPSIS
Tests the bounded native-command helper with owned, noninteractive test children.
.DESCRIPTION
Does not collect endpoint data or change network, services, profiles, stores, or policy.
#>
[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1'),
    [Parameter(Mandatory=$true)][string]$ScratchPath
)
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
. $ScriptPath
$exe = Join-Path $PSHOME 'powershell.exe'
function New-TestEncodedCommand {
    param([string]$Code)
    return @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Code)))
}
Test-Case 'native zero exit with stderr is still successful' {
    $r = Invoke-Dot1xProcess -FilePath $exe -ArgumentList (New-TestEncodedCommand '[Console]::Out.Write("fixture-out"); [Console]::Error.Write("fixture-error"); exit 0') -TimeoutSeconds 10
    Assert-Equal $r.Status 'Succeeded' 'Zero native exit was not successful.'
    Assert-Equal $r.ExitCode 0 'Native success exit code was lost.'
    Assert-True ($r.StdOut -match 'fixture-out') 'Stdout was not captured.'
    Assert-True ($r.StdErr -match 'fixture-error') 'Stderr was not captured.'
}
Test-Case 'native nonzero exit is reported as failure' {
    $r = Invoke-Dot1xProcess -FilePath $exe -ArgumentList (New-TestEncodedCommand 'exit 7') -TimeoutSeconds 10
    Assert-Equal $r.Status 'Failed' 'Nonzero native exit was not failed.'
    Assert-Equal $r.ExitCode 7 'Native failure exit code was lost.'
}
Test-Case 'missing native executable fails without hanging' {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Dot1xProcess -FilePath (Join-Path $ScratchPath 'does-not-exist.exe') -ArgumentList @() -TimeoutSeconds 2
    $clock.Stop()
    Assert-Equal $r.Status 'Failed' 'Missing executable was not failed.'
    Assert-True ($clock.Elapsed.TotalSeconds -lt 8) 'Missing executable failure was not bounded.'
}
Test-Case 'timeout terminates the owned native child' {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Dot1xProcess -FilePath $exe -ArgumentList (New-TestEncodedCommand '[Console]::WriteLine($PID); [Console]::Out.Flush(); Start-Sleep -Seconds 30') -TimeoutSeconds 1
    $clock.Stop()
    Assert-Equal $r.Status 'TimedOut' 'Native timeout was not reported.'
    Assert-True ($clock.Elapsed.TotalSeconds -lt 10) 'Native timeout exceeded its cleanup bound.'
    Assert-True ($r.ProcessId -gt 0) 'Timeout did not identify its owned process.'
    Assert-Equal @(Get-Process -Id $r.ProcessId -ErrorAction SilentlyContinue).Count 0 'Owned child is still live after timeout.'
}
Test-Case 'native arguments preserve literal metacharacters' {
    $path = Join-Path $ScratchPath ('argument fixture [' + [guid]::NewGuid().ToString('N') + '].ps1')
    $value = 'fixture space [bracket] & ; $ trailing\'
    [IO.File]::WriteAllText($path, 'param([string]$Value) [Console]::Write($Value); exit 0', [Text.Encoding]::ASCII)
    try {
        $r = Invoke-Dot1xProcess -FilePath $exe -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$path,'-Value',$value) -TimeoutSeconds 10
        Assert-Equal $r.Status 'Succeeded' 'Literal argument child did not complete.'
        Assert-Equal $r.StdOut $value 'Argument boundaries or metacharacters changed.'
    } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
}
Test-Case 'native output reports truncation at the caller bound' {
    $r = Invoke-Dot1xProcess -FilePath $exe -ArgumentList (New-TestEncodedCommand '[Console]::Write(("x" * 4096)); exit 0') -TimeoutSeconds 10 -OutputLimitChars 1024
    Assert-Equal $r.Status 'Succeeded' 'Bounded-output child did not complete.'
    Assert-Equal $r.StdOut.Length 1024 'Caller output length bound was not enforced.'
    Assert-Equal $r.OutputTruncated $true 'Output truncation was concealed.'
}
Test-Case 'timeout does not leave an owned descendant alive' {
    $marker = Join-Path $ScratchPath ('owned-child-' + [guid]::NewGuid().ToString('N') + '.txt')
    $literalMarker = "'" + $marker.Replace("'", "''") + "'"
    $childCode = '$ErrorActionPreference=''Stop''; [IO.File]::WriteAllText(' + $literalMarker + ', ($PID.ToString() + '','' + (Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks)); Start-Sleep -Seconds 20'
    $childArgs = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCode))
    $literalExe = "'" + $exe.Replace("'", "''") + "'"
    $parentCode = '$s=New-Object Diagnostics.ProcessStartInfo; $s.FileName=' + $literalExe + '; $s.Arguments=''' + $childArgs + '''; $s.UseShellExecute=$false; $s.CreateNoWindow=$true; $s.RedirectStandardOutput=$true; $s.RedirectStandardError=$true; $p=[Diagnostics.Process]::Start($s); Start-Sleep -Seconds 30'
    try {
        $r = Invoke-Dot1xProcess -FilePath $exe -ArgumentList (New-TestEncodedCommand $parentCode) -TimeoutSeconds 3
        Assert-Equal $r.Status 'TimedOut' 'Descendant test parent did not time out.'
        Assert-True (Test-Path -LiteralPath $marker -PathType Leaf) 'Owned descendant did not publish its test identity before timeout.'
        $parts = [IO.File]::ReadAllText($marker).Split(',')
        $child = Get-Process -Id ([int]$parts[0]) -ErrorAction SilentlyContinue
        $stillOwned = $null -ne $child -and -not $child.HasExited -and $child.StartTime.ToUniversalTime().Ticks -eq [long]$parts[1]
        Assert-True (-not $stillOwned) 'An owned descendant is still live after command timeout.'
    } finally {
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            $parts = [IO.File]::ReadAllText($marker).Split(',')
            $child = Get-Process -Id ([int]$parts[0]) -ErrorAction SilentlyContinue
            if ($null -ne $child -and -not $child.HasExited -and $child.StartTime.ToUniversalTime().Ticks -eq [long]$parts[1]) { $child.Kill(); $null = $child.WaitForExit(5000); $child.Dispose() }
            Remove-Item -LiteralPath $marker -Force
        }
    }
}

Complete-Tests

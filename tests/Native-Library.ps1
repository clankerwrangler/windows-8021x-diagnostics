# Run only owned test processes. Keep stdout/stderr private until assertions sanitize them.
function Invoke-TestPowerShell {
    param([string]$Code, [string]$WorkingDirectory, [int]$TimeoutSeconds = 90)
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $PSHOME 'powershell.exe'
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Code))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.WorkingDirectory = $WorkingDirectory
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    $started = $false
    try {
        $null = $process.Start()
        $started = $true
        $ownedId = $process.Id
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        if ($timedOut) {
            & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $ownedId /T /F 2>&1 | Out-Null
            if (-not $process.WaitForExit(5000)) { throw 'ASSERT: Owned test process did not terminate.' }
        }
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdout.GetAwaiter().GetResult()
            Stderr = $stderr.GetAwaiter().GetResult()
            TimedOut = $timedOut
            ProcessId = $ownedId
        }
    } finally {
        if ($null -ne $process) {
            if ($started -and -not $process.HasExited) {
                & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $process.Id /T /F 2>&1 | Out-Null
                $null = $process.WaitForExit(5000)
            }
            $process.Dispose()
        }
    }
}

function ConvertTo-TestLiteral {
    param([string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

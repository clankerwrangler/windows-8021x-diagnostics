# Shared built-in assertions. No Pester or package dependencies.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
$script:FailedNames = @()

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('ASSERT: ' + $Message) }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    Assert-True ($Actual -eq $Expected) $Message
}

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        $script:Passed++
        Write-Output ('PASS ' + $Name)
    } catch {
        $script:Failed++
        $script:FailedNames += $Name
        $detail = $_.Exception.Message
        if (-not $detail.StartsWith('ASSERT: ')) {
            $hr = '0x{0:X8}' -f ($_.Exception.HResult -band 0xFFFFFFFFL)
            $leaf = [IO.Path]::GetFileName($_.InvocationInfo.ScriptName)
            $detail = $_.Exception.GetType().FullName + '; HResult=' + $hr + '; source=' + $leaf + ':' + $_.InvocationInfo.ScriptLineNumber + '; errorId=' + $_.FullyQualifiedErrorId
        }
        Write-Output ('FAIL ' + $Name + ' (' + $detail + ')')
    }
}

function Complete-Tests {
    [pscustomobject]@{
        Passed = $script:Passed
        Failed = $script:Failed
        FailedNames = $script:FailedNames
    } | ConvertTo-Json -Compress
    if ($script:Failed -gt 0) { exit 1 }
    exit 0
}

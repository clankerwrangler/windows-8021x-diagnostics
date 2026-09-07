<# Tests that the assertion harness rejects vacuous success. #>
[CmdletBinding()]
param([string]$ScriptPath)
. (Join-Path $PSScriptRoot 'Test-Library.ps1')

Test-Case 'empty test body is rejected' {
    $caught = $false
    try { Invoke-TestCaseBody {} } catch { $caught = $_.Exception.Message -like '*executed no assertions*' }
    Assert-True $caught 'An empty test body passed.'
}
Test-Case 'ordinary statements do not count as assertions' {
    $caught = $false
    try { Invoke-TestCaseBody { $null = 1 + 1 } } catch { $caught = $_.Exception.Message -like '*executed no assertions*' }
    Assert-True $caught 'A body with no assertions passed.'
}
Test-Case 'a prior assertion cannot satisfy a later empty body' {
    Assert-True $true 'Initial assertion failed.'
    $caught = $false
    try { Invoke-TestCaseBody {} } catch { $caught = $_.Exception.Message -like '*executed no assertions*' }
    Assert-True $caught 'The assertion count leaked across bodies.'
}
Test-Case 'a real passing assertion satisfies the harness' {
    Invoke-TestCaseBody { Assert-Equal 2 2 'Passing equality failed.' }
}
Test-Case 'a failing assertion propagates' {
    $caught = $false
    try { Invoke-TestCaseBody { Assert-True $false 'Expected failure.' } }
    catch { $caught = $_.Exception.Message -like '*Expected failure*' }
    Assert-True $caught 'A failing assertion was swallowed.'
}
Complete-Tests

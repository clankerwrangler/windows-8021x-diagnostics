<#
.SYNOPSIS
Checks parse compatibility, help, and read-only source guards without collection.
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ScriptPath)
. (Join-Path $PSScriptRoot 'Test-Library.ps1')

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$parseErrors)
$source = [System.IO.File]::ReadAllText($ScriptPath)
Test-Case 'script parses on the executing PowerShell runtime' {
    Assert-Equal @($parseErrors).Count 0 'Main script has parse errors.'
}
Test-Case 'every test script parses' {
    foreach ($file in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File) {
        $testTokens = $null; $testErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$testTokens, [ref]$testErrors)
        Assert-Equal @($testErrors).Count 0 'A test script has parse errors.'
    }
}
Test-Case 'help has a synopsis and describes read-only limitations' {
    $help = Get-Help -Name $ScriptPath -Full
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$help.Synopsis)) 'Synopsis is missing.'
    Assert-True ($source -match '(?i)read.only') 'Read-only scope is missing.'
    Assert-True ($source -match '(?i)(cannot|does not|not).{0,80}(prove|proof|RADIUS)') 'Evidence limitation is missing.'
}
Test-Case 'no executable network or configuration mutation commands' {
    $blocked = '^(Set-Service|Start-Service|Stop-Service|Restart-Service|Suspend-Service|Resume-Service|New-Service|Remove-Service|Set-Net.*|New-Net.*|Remove-Net.*|Disable-Net.*|Enable-Net.*|Restart-Net.*|Rename-Net.*|Import-Certificate|Import-PfxCertificate|Export-PfxCertificate|New-SelfSignedCertificate|Clear-EventLog|Limit-EventLog|Remove-EventLog|New-EventLog|Enable-WSManCredSSP|Disable-WSManCredSSP|Set-ExecutionPolicy|Invoke-WebRequest|Invoke-RestMethod|Test-Connection|Test-NetConnection|Resolve-DnsName|Start-BitsTransfer|Register-ScheduledTask|Set-ScheduledTask|Unregister-ScheduledTask)$'
    $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
    foreach ($command in $commands) {
        $name = $command.GetCommandName()
        if ($null -ne $name) { Assert-True ($name -notmatch $blocked) 'A blocked command appears in executable code.' }
    }
    Assert-True ($source -notmatch '(?i)System\.Net\.(WebClient|HttpWebRequest|HttpClient|Sockets)|\b(TcpClient|UdpClient)\b') 'A network client is present.'
}
Test-Case 'no private-key or profile-secret export commands' {
    $nativeCalls = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -in @('Invoke-Dot1xProcess','netsh','netsh.exe','Export-PfxCertificate') }, $true))
    foreach ($call in $nativeCalls) {
        Assert-True ($call.Extent.Text -notmatch '(?i)key\s*=\s*clear|Export-PfxCertificate') 'A credential export command is present.'
    }
    Assert-True ($source -notmatch '(?i)CredRead|ProtectedData\]::Unprotect') 'A credential decryption API is present.'
}
Test-Case 'NoCheck is not accepted as proof of offline X509Chain build' {
    $chainBuild = ($source -match '(?i)X509Chain') -and ($source -match '(?i)\.Build\s*\(')
    Assert-True (-not $chainBuild) 'Managed X509Chain.Build needs an explicitly verified cache-only replacement before this smoke gate passes.'
}
Complete-Tests

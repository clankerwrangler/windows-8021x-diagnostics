<#
.SYNOPSIS
Tests offline CLI output and exit codes in caller-owned private scratch.
.DESCRIPTION
No live collector is called. The script writes and removes only its own fixture directory.
#>
[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1'),
    [Parameter(Mandatory=$true)][string]$ScratchPath
)
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
. (Join-Path $PSScriptRoot 'Native-Library.ps1')
. (Join-Path $PSScriptRoot 'Xml-Fixtures.ps1')
. $ScriptPath
$caseRoot = Join-Path $ScratchPath ('io-fixtures-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -Path $caseRoot -ItemType Directory -ErrorAction Stop
$inputPath = Join-Path $caseRoot 'input fixture [1].json'
$profile = ConvertFrom-Dot1xProfileXml -XmlText (New-TestProfileXml -Extra '<sharedKey><keyMaterial>fixture-io-secret-DO-NOT-EMIT</keyMaterial></sharedKey>') -Kind Wireless -Name 'fixture-profile'
$fixture = [pscustomobject]@{
    SchemaVersion = 1; CapturedAtUtc = '2026-01-15T12:00:00Z'; Collection = [pscustomobject]@{ Mode = 'Synthetic' }
    Profiles = @($profile); CertificateStores = @([pscustomobject]@{ Store = 'LocalMachine'; Status = 'Succeeded'; Truncated = $false })
    Certificates = @(); Probes = @([pscustomobject]@{ Name = 'SyntheticEvents'; Status = 'Failed'; DurationMs = 1; Limitations = @('Synthetic denied collection.') })
}
[IO.File]::WriteAllText($inputPath, ($fixture | ConvertTo-Json -Depth 20), [Text.Encoding]::UTF8)
function Invoke-TestCli {
    param([string]$Extra = '', [string]$InputFile = $inputPath)
    $code = '& ' + (ConvertTo-TestLiteral $ScriptPath) + ' -EvidencePath ' + (ConvertTo-TestLiteral $InputFile) + ' ' + $Extra
    Invoke-TestPowerShell -Code $code -WorkingDirectory $caseRoot -TimeoutSeconds 30
}
function Get-TestRunDirectories {
    param([string]$Container)
    @(Get-ChildItem -LiteralPath $Container -Directory | Where-Object { $_.Name -like 'Dot1x-Report-*' })
}
function Assert-TestSavedReport {
    param([string]$Directory, [string]$OrdinaryOutput)
    Assert-True ([IO.Path]::IsPathRooted($Directory)) 'The saved report path is not absolute.'
    Assert-Equal @(Get-ChildItem -LiteralPath $Directory -File).Count 3 'Unexpected output artifact count.'
    foreach ($name in @('evidence.json','report.json','report.txt')) {
        Assert-True (Test-Path -LiteralPath (Join-Path $Directory $name) -PathType Leaf) 'A documented output artifact is missing.'
    }
    $report = [IO.File]::ReadAllText((Join-Path $Directory 'report.json')) | ConvertFrom-Json
    Assert-Equal $report.OutputDirectory $Directory 'Saved JSON does not identify its actual run directory.'
    Assert-True (@($report.Findings | Where-Object { $_.Id -eq 'AUTH-NOT-VERIFIED' }).Count -gt 0) 'Serialized report omits the authentication limitation.'
    $savedLine = 'Saved reports: ' + $Directory
    Assert-True ([IO.File]::ReadAllText((Join-Path $Directory 'report.txt')).Contains($savedLine)) 'Saved text does not identify its actual run directory.'
    if ($PSBoundParameters.ContainsKey('OrdinaryOutput')) {
        Assert-True $OrdinaryOutput.Contains($savedLine) 'Ordinary output does not identify the saved run directory.'
    }
}
function Assert-TestPrivateDirectory {
    param([string]$Directory)
    $acl = Get-Acl -LiteralPath $Directory
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed = @($sid,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique
    $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    Assert-True $acl.AreAccessRulesProtected 'A new report directory inherits unreviewed access.'
    Assert-Equal $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value $sid 'A new report directory has the wrong owner.'
    Assert-Equal $rules.Count @($allowed).Count 'A new report directory has unexpected access entries.'
    foreach ($rule in $rules) {
        Assert-True ($allowed -contains $rule.IdentityReference.Value) 'A new report directory grants another principal.'
        Assert-Equal $rule.AccessControlType ([Security.AccessControl.AccessControlType]::Allow) 'A new report directory has an unexpected access type.'
        Assert-Equal $rule.FileSystemRights ([Security.AccessControl.FileSystemRights]::FullControl) 'A new report directory has unexpected rights.'
        Assert-True (-not $rule.IsInherited) 'A new report directory access entry is inherited.'
    }
}
$script:firstRun = ''; $script:testJunction = ''
try {
    Test-Case 'dot-source imports functions without compiling native collectors' {
        $code = '. ' + (ConvertTo-TestLiteral $ScriptPath) + '; if (''Dot1x.Native'' -as [type]) { exit 9 }; if (-not (Get-Command Get-Dot1xDiagnosis -ErrorAction SilentlyContinue)) { exit 8 }; exit 0'
        $r = Invoke-TestPowerShell -Code $code -WorkingDirectory $caseRoot -TimeoutSeconds 15
        Assert-Equal $r.ExitCode 0 'Dot-source did not remain import-only.'
    }
    Test-Case 'CLI help does not collect or write output files' {
        $before = @(Get-ChildItem -LiteralPath $caseRoot -Force).Count
        $code = '& ' + (ConvertTo-TestLiteral $ScriptPath) + ' -?'
        $r = Invoke-TestPowerShell -Code $code -WorkingDirectory $caseRoot -TimeoutSeconds 15
        Assert-Equal $r.ExitCode 0 'Help returned a failure exit code.'
        Assert-True ($r.Stdout -match 'SYNOPSIS|SYNTAX|NAME') 'Help text was not returned.'
        Assert-Equal @(Get-ChildItem -LiteralPath $caseRoot -Force).Count $before 'Help wrote files.'
    }
    Test-Case 'offline warnings remain pipeline-only without a destination' {
        $before = @(Get-ChildItem -LiteralPath $caseRoot -Force).Count
        $r = Invoke-TestCli
        Assert-Equal $r.ExitCode 0 'Completed offline diagnosis did not exit zero.'
        Assert-True ($r.Stdout -match 'AUTH-NOT-VERIFIED') 'Offline output lacks the authentication limitation.'
        Assert-True ($r.Stdout -match 'COLLECTION-INCOMPLETE') 'Partial input lost its incomplete collection finding.'
        Assert-True ($r.Stdout -notmatch 'Saved reports:') 'Pipeline-only text claims to have saved a report.'
        Assert-Equal @(Get-ChildItem -LiteralPath $caseRoot -Force).Count $before 'Pipeline-only output wrote files.'
    }
    Test-Case 'PassThru without a destination returns one unsaved report and no files' {
        $before = @(Get-ChildItem -LiteralPath $caseRoot -Force).Count
        $r = Invoke-TestCli '-PassThru | ConvertTo-Json -Depth 20 -Compress'
        Assert-Equal $r.ExitCode 0 'Pipeline-only PassThru failed.'
        $returned = @($r.Stdout | ConvertFrom-Json)
        Assert-Equal $returned.Count 1 'PassThru emitted more than one pipeline object.'
        Assert-Equal $returned[0].SchemaVersion 1 'PassThru did not return the report object.'
        Assert-True ($null -eq $returned[0].PSObject.Properties['OutputDirectory']) 'Unsaved PassThru report claims a saved path.'
        Assert-Equal @(Get-ChildItem -LiteralPath $caseRoot -Force).Count $before 'Pipeline-only PassThru wrote files.'
    }
    $output = Join-Path $caseRoot 'report output [1]'
    Test-Case 'new literal destination writes a private run and displays its actual path' {
        $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral $output))
        Assert-Equal $r.ExitCode 0 'New output destination failed.'
        $runs = @(Get-TestRunDirectories $output)
        Assert-Equal $runs.Count 1 'The destination does not contain exactly one new run.'
        Assert-Equal @(Get-ChildItem -LiteralPath $output -File).Count 0 'Artifacts were written directly into the destination.'
        $script:firstRun = $runs[0].FullName
        Assert-TestSavedReport -Directory $script:firstRun -OrdinaryOutput $r.Stdout
        Assert-TestPrivateDirectory $output
        Assert-TestPrivateDirectory $script:firstRun
    }
    Test-Case 'profile-to-report pipeline omits profile secret values and raw XML' {
        Assert-True ([bool]$script:firstRun) 'Precondition: the initial run was not saved.'
        foreach ($name in @('evidence.json','report.json','report.txt')) {
            $text = [IO.File]::ReadAllText((Join-Path $script:firstRun $name))
            Assert-True ($text -notmatch 'fixture-io-secret-DO-NOT-EMIT|<sharedKey>|<WLANProfile') 'An output artifact contains omitted profile data.'
        }
    }
    Test-Case 'reusing a destination preserves the first run and creates a distinct complete run' {
        Assert-TestSavedReport -Directory $script:firstRun
        $before = @(Get-ChildItem -LiteralPath $script:firstRun -File | Sort-Object Name | ForEach-Object {
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash + ':' + (Get-Acl -LiteralPath $_.FullName).Sddl
        }) -join '|'
        $beforeAcl = (Get-Acl -LiteralPath $script:firstRun).Sddl
        $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral $output))
        Assert-Equal $r.ExitCode 0 'Reusing a destination failed.'
        $runs = @(Get-TestRunDirectories $output)
        Assert-Equal $runs.Count 2 'A repeated save did not create a second run.'
        $newRun = @($runs | Where-Object { $_.FullName -ne $script:firstRun })
        Assert-Equal $newRun.Count 1 'Repeated saves do not have distinct run paths.'
        Assert-TestSavedReport -Directory $newRun[0].FullName -OrdinaryOutput $r.Stdout
        Assert-TestPrivateDirectory $newRun[0].FullName
        $after = @(Get-ChildItem -LiteralPath $script:firstRun -File | Sort-Object Name | ForEach-Object {
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash + ':' + (Get-Acl -LiteralPath $_.FullName).Sddl
        }) -join '|'
        Assert-Equal $after $before 'The first run contents or file ACLs changed.'
        Assert-Equal (Get-Acl -LiteralPath $script:firstRun).Sddl $beforeAcl 'The first run directory ACL changed.'
    }
    Test-Case 'existing destination preserves unrelated file and directory contents and ACLs' {
        $container = Join-Path $caseRoot 'existing unrelated destination'
        $unrelated = Join-Path $container 'unrelated directory'
        $null = [IO.Directory]::CreateDirectory($unrelated)
        $sentinels = @((Join-Path $container 'unrelated.txt'), (Join-Path $unrelated 'keep.txt'))
        foreach ($path in $sentinels) { [IO.File]::WriteAllText($path,'synthetic unrelated content') }
        $beforeAcls = @{}
        foreach ($path in @($container,$unrelated) + $sentinels) { $beforeAcls[$path] = (Get-Acl -LiteralPath $path).Sddl }
        $beforeHashes = @{}
        foreach ($path in $sentinels) { $beforeHashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
        Assert-True (-not (Get-Acl -LiteralPath $container).AreAccessRulesProtected) 'Precondition: the fixture must have a distinguishable inherited ACL.'
        $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral $container))
        Assert-Equal $r.ExitCode 0 'An existing destination with unrelated items failed.'
        foreach ($path in $beforeAcls.Keys) { Assert-Equal (Get-Acl -LiteralPath $path).Sddl $beforeAcls[$path] 'An existing item ACL changed.' }
        foreach ($path in $beforeHashes.Keys) { Assert-Equal (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash $beforeHashes[$path] 'An unrelated file changed.' }
        Assert-Equal @(Get-ChildItem -LiteralPath $unrelated -Force).Count 1 'The unrelated directory was changed.'
        $runs = @(Get-TestRunDirectories $container)
        Assert-Equal $runs.Count 1 'The existing destination did not receive one run.'
        Assert-TestSavedReport -Directory $runs[0].FullName -OrdinaryOutput $r.Stdout
        Assert-TestPrivateDirectory $runs[0].FullName
    }
    Test-Case 'PassThru identifies the same run as saved JSON and text without a second object' {
        $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral $output) + ' -PassThru | ConvertTo-Json -Depth 20 -Compress')
        Assert-Equal $r.ExitCode 0 'Saved PassThru failed.'
        $returned = @($r.Stdout | ConvertFrom-Json)
        Assert-Equal $returned.Count 1 'Saved PassThru emitted a separate path or text object.'
        Assert-Equal $returned[0].SchemaVersion 1 'Saved PassThru is not the report object.'
        Assert-Equal (Split-Path -Path $returned[0].OutputDirectory -Parent) $output 'PassThru points outside the requested destination.'
        Assert-TestSavedReport -Directory $returned[0].OutputDirectory
        Assert-Equal @(Get-TestRunDirectories $output).Count 3 'PassThru overwrote an earlier run.'
    }
    Test-Case 'a file used as destination is rejected without overwrite' {
        $before = (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash
        $beforeAcl = (Get-Acl -LiteralPath $inputPath).Sddl
        $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral $inputPath))
        Assert-Equal $r.ExitCode 1 'A destination file was not rejected.'
        Assert-Equal (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash $before 'The destination file was overwritten.'
        Assert-Equal (Get-Acl -LiteralPath $inputPath).Sddl $beforeAcl 'The destination file ACL changed.'
    }
    Test-Case 'missing nested destination parents are created privately' {
        $top = Join-Path $caseRoot 'missing-parent'
        $middle = Join-Path $top 'nested [1]'
        $container = Join-Path $middle 'reports'
        $existingAcl = (Get-Acl -LiteralPath $caseRoot).Sddl
        Assert-True (-not (Test-Path -LiteralPath $top)) 'Precondition: a missing ancestor already exists.'
        $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral $container))
        Assert-Equal $r.ExitCode 0 'Missing nested parents were not created.'
        $runs = @(Get-TestRunDirectories $container)
        Assert-Equal $runs.Count 1 'The nested destination did not receive one run.'
        foreach ($path in @($top,$middle,$container,$runs[0].FullName)) { Assert-TestPrivateDirectory $path }
        Assert-TestSavedReport -Directory $runs[0].FullName -OrdinaryOutput $r.Stdout
        Assert-Equal (Get-Acl -LiteralPath $caseRoot).Sddl $existingAcl 'An existing ancestor ACL changed.'
    }
    Test-Case 'relative bracket destination is literal and does not select a wildcard sibling' {
        $wildcardSibling = Join-Path $caseRoot 'relative report 2'
        $null = [IO.Directory]::CreateDirectory($wildcardSibling)
        $sentinel = Join-Path $wildcardSibling 'keep.txt'; [IO.File]::WriteAllText($sentinel,'synthetic wildcard sentinel')
        $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral '.\relative report [2]'))
        Assert-Equal $r.ExitCode 0 'A relative literal destination failed.'
        $runs = @(Get-TestRunDirectories (Join-Path $caseRoot 'relative report [2]'))
        Assert-Equal $runs.Count 1 'A relative report was not created in the literal caller directory.'
        Assert-TestSavedReport -Directory $runs[0].FullName -OrdinaryOutput $r.Stdout
        Assert-Equal @(Get-ChildItem -LiteralPath $wildcardSibling -Force).Count 1 'Wildcard expansion changed a sibling directory.'
        Assert-Equal ([IO.File]::ReadAllText($sentinel)) 'synthetic wildcard sentinel' 'The wildcard sibling sentinel changed.'
    }
    Test-Case 'relative output follows PowerShell location rather than process current directory' {
        $processDir = Join-Path $caseRoot 'process-current-directory'
        $shellDir = Join-Path $caseRoot 'powershell-current-location'
        $null = New-Item -Path $processDir -ItemType Directory
        $null = New-Item -Path $shellDir -ItemType Directory
        $code = '[Environment]::CurrentDirectory=' + (ConvertTo-TestLiteral $processDir) + '; Set-Location -LiteralPath ' + (ConvertTo-TestLiteral $shellDir) + '; & ' + (ConvertTo-TestLiteral $ScriptPath) + ' -EvidencePath ' + (ConvertTo-TestLiteral $inputPath) + ' -OutputDirectory ' + (ConvertTo-TestLiteral 'relative-location-report')
        $r = Invoke-TestPowerShell -Code $code -WorkingDirectory $caseRoot -TimeoutSeconds 30
        Assert-Equal $r.ExitCode 0 'Relative output failed with distinct process and PowerShell locations.'
        $runs = @(Get-TestRunDirectories (Join-Path $shellDir 'relative-location-report'))
        Assert-Equal $runs.Count 1 'Relative output ignored the PowerShell location.'
        Assert-TestSavedReport -Directory $runs[0].FullName -OrdinaryOutput $r.Stdout
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $processDir 'relative-location-report'))) 'Output used the unrelated process current directory.'
    }
    Test-Case 'destination accepts a trailing separator' {
        $out = (Join-Path $caseRoot 'trailing-separator-report') + '\'
        $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral $out))
        Assert-Equal $r.ExitCode 0 'A trailing separator prevented output.'
        $runs = @(Get-TestRunDirectories $out)
        Assert-Equal $runs.Count 1 'The trailing-separator destination did not receive one run.'
        Assert-TestSavedReport -Directory $runs[0].FullName -OrdinaryOutput $r.Stdout
    }
    Test-Case 'a reparse ancestor is rejected without changing its synthetic target' {
        $target = Join-Path $caseRoot 'owned reparse target'
        $null = [IO.Directory]::CreateDirectory($target)
        $sentinel = Join-Path $target 'keep.txt'; [IO.File]::WriteAllText($sentinel,'synthetic reparse sentinel')
        $beforeAcl = (Get-Acl -LiteralPath $target).Sddl
        $script:testJunction = Join-Path $caseRoot 'owned junction'
        $null = New-Item -ItemType Junction -Path $script:testJunction -Value $target -ErrorAction Stop
        try {
            Assert-True (([IO.File]::GetAttributes($script:testJunction) -band [IO.FileAttributes]::ReparsePoint) -ne 0) 'Precondition: no owned reparse point was created.'
            $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral (Join-Path $script:testJunction 'missing nested destination')))
            Assert-Equal $r.ExitCode 1 'A reparse ancestor was followed.'
            Assert-Equal @(Get-ChildItem -LiteralPath $target -Force).Count 1 'Output was written through a reparse ancestor.'
            Assert-Equal ([IO.File]::ReadAllText($sentinel)) 'synthetic reparse sentinel' 'The reparse target sentinel changed.'
            Assert-Equal (Get-Acl -LiteralPath $target).Sddl $beforeAcl 'The reparse target ACL changed.'
        } finally { [IO.Directory]::Delete($script:testJunction); $script:testJunction = '' }
    }
    Test-Case 'a non-filesystem destination fails without creating reports' {
        $before = @(Get-ChildItem -LiteralPath $caseRoot -Force).Count
        $r = Invoke-TestCli ('-OutputDirectory ' + (ConvertTo-TestLiteral 'Variable:\dot1x-synthetic-report'))
        Assert-Equal $r.ExitCode 1 'A non-filesystem destination was accepted.'
        Assert-Equal @(Get-ChildItem -LiteralPath $caseRoot -Force).Count $before 'The invalid provider destination wrote files.'
    }
    Test-Case 'CreateNew report writes reject a controlled file collision without overwrite' {
        # Inject only a private lease with a synthetic existing file; run the real writer.
        $factory = (Get-Command New-Dot1xPrivateDirectory).ScriptBlock
        $script:collisionDirectory = ''
        function New-Dot1xPrivateDirectory {
            param([string]$Path,[switch]$CreateParents)
            $lease = & $factory -Path $Path -CreateParents:$CreateParents
            $script:collisionDirectory = $lease.Path
            [IO.File]::WriteAllText((Join-Path $lease.Path 'evidence.json'),'synthetic collision sentinel')
            return $lease
        }
        $report = [pscustomobject]@{SchemaVersion=1;CapturedAtUtc=$fixture.CapturedAtUtc;Findings=@();Probes=@()}
        $threw = $false
        try { $null = Write-Dot1xReport -Report $report -Evidence $fixture -OutputDirectory (Join-Path $caseRoot 'collision destination') }
        catch { $threw = $true }
        Assert-True $threw 'An existing report file was overwritten instead of rejected.'
        Assert-True ([bool]$script:collisionDirectory) 'Precondition: the controlled private directory was not created.'
        Assert-Equal ([IO.File]::ReadAllText((Join-Path $script:collisionDirectory 'evidence.json'))) 'synthetic collision sentinel' 'CreateNew did not preserve the existing file.'
        Assert-Equal @(Get-ChildItem -LiteralPath $script:collisionDirectory -Force).Count 1 'The writer continued after its first artifact collision.'
    }
    Test-Case 'invalid JSON has a native failure exit and no output directory' {
        $invalid = Join-Path $caseRoot 'invalid.json'; [IO.File]::WriteAllText($invalid,'{')
        $out = Join-Path $caseRoot 'invalid-output'
        $r = Invoke-TestCli -Extra ('-OutputDirectory ' + (ConvertTo-TestLiteral $out)) -InputFile $invalid
        Assert-Equal $r.ExitCode 1 'Invalid input did not fail.'
        Assert-True (-not (Test-Path -LiteralPath $out)) 'Invalid input wrote a report directory.'
    }
    Test-Case 'unsupported evidence schema has a native failure exit' {
        $invalid = Join-Path $caseRoot 'unsupported.json'; [IO.File]::WriteAllText($invalid,'{"SchemaVersion":2}')
        Assert-Equal (Invoke-TestCli -InputFile $invalid).ExitCode 1 'Unsupported schema did not fail.'
    }
    Test-Case 'directory used as evidence has a native failure exit' {
        Assert-Equal (Invoke-TestCli -InputFile $caseRoot).ExitCode 1 'Evidence directory was not rejected.'
    }
    Test-Case 'invalid numeric parameter is rejected before collection' {
        Assert-True ((Invoke-TestCli -Extra '-LookbackHours 0').ExitCode -ne 0) 'Invalid parameter unexpectedly succeeded.'
    }
} finally {
    if ($script:testJunction -and [IO.Directory]::Exists($script:testJunction)) { [IO.Directory]::Delete($script:testJunction) }
    Remove-Item -LiteralPath $caseRoot -Recurse -Force -ErrorAction Stop
}
Complete-Tests

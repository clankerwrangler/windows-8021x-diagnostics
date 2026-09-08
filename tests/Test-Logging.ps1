<#
.SYNOPSIS
Tests logging preparation with synthetic native/registry responses and private scratch files.
.DESCRIPTION
Uses only wevtutil el for the read-only native boundary regression; logging mutations and
Schannel access are mocked. Filesystem tests use owned fixtures.
#>
[CmdletBinding()]
param(
    [string]$ScriptPath,
    [Parameter(Mandatory=$true)][string]$ScratchPath
)
if (-not $ScriptPath) { $ScriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-8021xDiagnostics.ps1' }
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
$helperPath = Join-Path (Split-Path $ScriptPath -Parent) 'Set-8021xLogging.ps1'
. $helperPath
$script:realLoggingNative = ${function:Invoke-LoggingNative}

function Assert-Throws {
    param([scriptblock]$Body, [string]$Pattern = '.')
    $message = ''
    try { & $Body } catch { $message = $_.Exception.Message }
    Assert-True ($message -match $Pattern) ('Expected failure matching: ' + $Pattern + '; actual: ' + $message)
}
function New-TestLoggingStore {
    $store = [pscustomobject]@{ Json=$null; Saves=0; Deletes=0; FailSave=$false; FailDelete=$false }
    $store | Add-Member ScriptMethod Read { return $this.Json }
    $store | Add-Member ScriptMethod SaveNew {
        param($text)
        if ($this.FailSave) { throw 'Synthetic state disk failure' }
        if ($null -ne $this.Json) { throw 'Baseline overwrite' }
        $this.Json=$text; $this.Saves++
    }
    $store | Add-Member ScriptMethod DeleteBaseline {
        if ($this.FailDelete) { throw 'Synthetic cleanup failure' }
        $this.Json=$null; $this.Deletes++
    }
    return $store
}
function Reset-TestLogging {
    $script:installed = @(Get-LoggingCoreChannels) + @(
        'Microsoft-Windows-Dhcp-Client/Admin', 'Microsoft-Windows-DNS-Client/Operational',
        'Microsoft-Windows-NetworkProfile/Operational', 'Microsoft-Windows-GroupPolicy/Operational',
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin',
        'Microsoft-Windows-CertificateServicesClient-AutoEnrollment/Operational',
        'Microsoft-Windows-OneX/Operational', 'Microsoft-Windows-EapMethods-RasChap/Operational',
        'Microsoft-Windows-EapMethods-RasTls/Operational', 'Microsoft-Windows-EapMethods-Sim/Operational',
        'Microsoft-Windows-EapMethods-Ttls/Operational', 'Microsoft-Windows-Dhcpv6-Client/Admin',
        'Microsoft-Windows-Dhcpv6-Client/Operational',
        'Microsoft-Windows-EapHost/Debug', 'Microsoft-Windows-Dhcp-Client/Analytic', 'Security')
    $script:configuration = @{}
    foreach ($name in $script:installed) { $script:configuration[$name] = [pscustomobject]@{ Enabled=$false; MaximumSize=1048576L } }
    $script:configuration['Microsoft-Windows-WLAN-AutoConfig/Operational'].Enabled = $true
    $script:configuration['Microsoft-Windows-WLAN-AutoConfig/Operational'].MaximumSize = 209715200L
    $script:schannel = [pscustomobject]@{ Present=$false; Value=$null }
    $script:nativeCalls = New-Object 'System.Collections.Generic.List[object]'
    $script:schannelWrites = New-Object 'System.Collections.Generic.List[object]'
    $script:nativeFailures = @{}
    $script:nativeFailureText = 'Synthetic native denied or unavailable'
    $script:failSchannel = $false
    $script:store = New-TestLoggingStore
}
# Only this adapter is replaced: enumeration, XML parsing, exit handling, channel
# allowlisting, baseline serialization, and enable/restore orchestration stay real.
function Invoke-LoggingNative {
    param([string[]]$Arguments)
    $script:nativeCalls.Add(@($Arguments))
    $action = $Arguments[0]
    $key = $action
    if ($Arguments.Count -gt 1) { $key += ':' + $Arguments[1] }
    if ($script:nativeFailures.ContainsKey($key)) { return [pscustomobject]@{ ExitCode=$script:nativeFailures[$key]; Text=$script:nativeFailureText } }
    if ($action -eq 'el') { return [pscustomobject]@{ ExitCode=0; Text=($script:installed -join "`r`n") } }
    $name = $Arguments[1]
    if ($script:installed -notcontains $name) { return [pscustomobject]@{ ExitCode=15007; Text='Synthetic missing channel' } }
    $setting = $script:configuration[$name]
    if ($action -eq 'sl') {
        if ($null -eq $script:store.Json) { throw 'A logging mutation preceded a durable baseline.' }
        $setting.Enabled = [bool]::Parse($Arguments[2].Substring(3))
        $setting.MaximumSize = [long]::Parse($Arguments[3].Substring(4))
        return [pscustomobject]@{ ExitCode=0; Text='' }
    }
    if ($action -ne 'gl') { throw 'Unexpected native action' }
    $text = '<channel xmlns="http://schemas.microsoft.com/win/2004/08/events" name="' + $name + '" enabled="' + $setting.Enabled.ToString().ToLowerInvariant() + '"><logging><maxSize>' + $setting.MaximumSize + '</maxSize></logging></channel>'
    [pscustomobject]@{ ExitCode=0; Text=$text }
}
function Get-LoggingSchannel { return $script:schannel }
function Set-LoggingSchannel {
    param($Setting)
    if ($script:failSchannel) { throw 'Synthetic registry denied' }
    if ($null -eq $script:store.Json) { throw 'A registry mutation preceded a durable baseline.' }
    $script:schannelWrites.Add($Setting)
    $script:schannel = [pscustomobject]@{ Present=$Setting.Present; Value=$Setting.Value }
}
function Invoke-TestLogging {
    param([bool]$Restoring=$false, [bool]$Schannel=$false)
    Invoke-LoggingSession $script:store 'fixture-machine' 'fixture-caller' $Restoring $Schannel
}
function Get-TestMutations { @($script:nativeCalls | Where-Object { $_[0] -eq 'sl' }) }

Test-Case 'helper parses, imports without execution, and documents both modes' {
    $tokens=$null; $errors=$null
    $ast = [Management.Automation.Language.Parser]::ParseFile($helperPath,[ref]$tokens,[ref]$errors)
    Assert-Equal @($errors).Count 0 'Helper parse errors.'
    Assert-True ([bool](Get-Command Invoke-LoggingSession)) 'Import did not expose the orchestration function.'
    Assert-True (-not ('Dot1xLogging.Store' -as [type])) 'Dot-source compiled platform code.'
    Assert-True ((Get-Help $helperPath -Full).Synopsis -match 'client') 'Help omits client scope.'
    $commands = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] },$true))
    foreach ($command in $commands) {
        Assert-True ($command.GetCommandName() -notmatch '^(Restart-Computer|Restart-Service|Set-Service|Clear-EventLog|Set-Net.*|netsh|auditpol)$') 'Unexpected non-logging mutation command.'
    }
}
Test-Case 'defaults are the exact collector channels plus narrow client Admin and Operational families' {
    Reset-TestLogging
    $core = @(Get-LoggingCoreChannels)
    Assert-Equal $core.Count 5 'Core list changed.'
    foreach ($family in @('WLAN-AutoConfig','Wired-AutoConfig','EapHost','CAPI2','NTLM')) {
        Assert-True ($core -contains ('Microsoft-Windows-' + $family + '/Operational')) 'A collector channel is missing.'
    }
    foreach ($name in $script:installed[0..17]) { Assert-True (Test-LoggingChannel $name) 'Expected client channel was excluded.' }
    foreach ($name in @('Security','System','Microsoft-Windows-NPS/Operational','Microsoft-Windows-OneX/Debug','Microsoft-Windows-EapMethods-Unrelated/Operational','Microsoft-Windows-EapMethods-RasTls/Analytic','Microsoft-Windows-EapHost/Debug','Microsoft-Windows-EapHost/Analytic','Microsoft-Windows-Dhcp-Client/Analytic','Microsoft-Windows-CertificateServicesClient-X/Debug','Microsoft-Windows-CertificateServicesClient-X/Operational/extra','Microsoft-Windows-NTLM/Operational /e:false','Other-Microsoft-Windows-DNS-Client/Operational')) {
        Assert-True (-not (Test-LoggingChannel $name)) 'A channel outside the allowlist was accepted.'
    }
    Invoke-TestLogging
    Assert-Equal @(Get-TestMutations).Count 18 'Unexpected enabled channel count.'
    Assert-Equal $script:schannelWrites.Count 0 'Default enable changed Schannel.'
    Assert-Equal $script:configuration[$core[0]].MaximumSize 209715200L 'Enable shrank a large log.'
    Assert-Equal $script:configuration[$core[1]].MaximumSize 104857600L 'Enable did not enlarge a small log.'
}
Test-Case 'missing installed logs are skipped without native setting queries' {
    Reset-TestLogging
    $script:installed = @('Microsoft-Windows-CAPI2/Operational')
    Invoke-TestLogging
    Assert-Equal @(Get-TestMutations).Count 1 'Missing logs were not skipped.'
    Assert-Equal ($script:store.Json | ConvertFrom-Json).Channels.Count 1 'Baseline includes missing logs.'
}
Test-Case 'native non-aligned log sizes remain exact in the original baseline' {
    Reset-TestLogging
    $name = 'Microsoft-Windows-CAPI2/Operational'
    $script:configuration[$name].MaximumSize = 1052672L
    Invoke-TestLogging
    $saved = $script:store.Json | ConvertFrom-Json
    Assert-LoggingState $saved 'fixture-machine' 'fixture-caller'
    $original = @($saved.Channels | Where-Object { $_.Name -eq $name })
    Assert-Equal $original.Count 1 'The native-size channel is missing from the baseline.'
    Assert-Equal $original[0].MaximumSize 1052672L 'Snapshot or serialization rounded the original native size.'
    Assert-Equal $script:configuration[$name].MaximumSize 104857600L 'Enable did not enlarge the native-size log.'
    Invoke-TestLogging -Restoring $true
    Assert-Equal $script:configuration[$name].MaximumSize 1052672L 'Restore rounded the original native size.'
    Assert-Equal $script:configuration[$name].Enabled $false 'Restore lost the original disabled state.'
    Assert-Equal $script:store.Deletes 1 'Exact native-size restoration did not complete.'
}
Test-Case 'repeated enable preserves the first baseline and never shrinks newer larger sizes' {
    Reset-TestLogging
    Invoke-TestLogging
    $original = $script:store.Json
    $name = 'Microsoft-Windows-Wired-AutoConfig/Operational'
    $script:configuration[$name].MaximumSize = 314572800L
    Invoke-TestLogging
    Assert-Equal $script:store.Json $original 'Repeated enable overwrote the baseline.'
    Assert-Equal $script:store.Saves 1 'Repeated enable saved a new baseline.'
    Assert-Equal $script:configuration[$name].MaximumSize 314572800L 'Repeated enable shrank a log.'
    Assert-Throws { Invoke-TestLogging -Schannel $true } 'Run -Restore'
    Assert-Equal $script:schannelWrites.Count 0 'Schannel was changed without a matching baseline.'
}
Test-Case 'snapshot and durable save failures prevent all logging changes' {
    Reset-TestLogging
    $script:nativeFailures['gl:Microsoft-Windows-CAPI2/Operational'] = 5
    Assert-Throws { Invoke-TestLogging } 'exit=5'
    Assert-Equal $script:store.Saves 0 'Incomplete snapshot was saved.'
    Assert-Equal @(Get-TestMutations).Count 0 'Snapshot failure changed logging.'
    Reset-TestLogging; $script:store.FailSave = $true
    Assert-Throws { Invoke-TestLogging } 'disk failure'
    Assert-Equal @(Get-TestMutations).Count 0 'Save failure changed logging.'
}
Test-Case 'partial native enable failure is visible and preserves recoverable original states' {
    Reset-TestLogging
    $name = 'Microsoft-Windows-CAPI2/Operational'
    $script:nativeFailures['sl:' + $name] = 5
    Assert-Throws { Invoke-TestLogging } 'incomplete[\s\S]*exit=5'
    Assert-Equal $script:store.Saves 1 'Original baseline was not saved.'
    Assert-Equal @(Get-TestMutations).Count 18 'A failure prevented other channels from being attempted.'
    Assert-Equal ($script:store.Json | ConvertFrom-Json).Channels[0].Enabled $false 'Baseline captured a mutated state.'
    $script:nativeFailures.Clear()
    Invoke-TestLogging -Restoring $true
    Assert-Equal $script:configuration[$name].Enabled $false 'Restore missed the original disabled state.'
    Assert-Equal $script:store.Deletes 1 'Successful restore did not remove the baseline.'
}
Test-Case 'partial restore and cleanup failures retain baseline and permit idempotent retry' {
    Reset-TestLogging; Invoke-TestLogging
    $original = $script:store.Json
    $name = 'Microsoft-Windows-CAPI2/Operational'
    $script:nativeFailures['sl:' + $name] = 15007
    Assert-Throws { Invoke-TestLogging -Restoring $true } 'incomplete[\s\S]*exit=15007'
    Assert-Equal $script:store.Json $original 'Partial restore removed the baseline.'
    $script:nativeFailures.Clear(); $script:store.FailDelete = $true
    Assert-Throws { Invoke-TestLogging -Restoring $true } 'cleanup failure'
    Assert-Equal $script:store.Json $original 'Cleanup failure lost the baseline.'
    $script:store.FailDelete = $false
    Invoke-TestLogging -Restoring $true
    foreach ($row in ($original | ConvertFrom-Json).Channels) {
        Assert-Equal $script:configuration[$row.Name].Enabled $row.Enabled 'Original enabled state was not restored.'
        Assert-Equal $script:configuration[$row.Name].MaximumSize $row.MaximumSize 'Original size was not restored.'
    }
    $before = @(Get-TestMutations).Count
    Invoke-TestLogging -Restoring $true
    Assert-Equal @(Get-TestMutations).Count $before 'Repeated completed restore changed settings.'
}
Test-Case 'Schannel absence, zero, and high-bit DWORD values restore exactly' {
    foreach ($value in @($null,0L,3L,4294967295L)) {
        Reset-TestLogging
        $script:schannel = [pscustomobject]@{ Present=($null -ne $value); Value=$value }
        Invoke-TestLogging -Schannel $true
        Assert-Equal $script:schannel.Value 7L 'Optional Schannel verbosity was not enabled.'
        $baseline = $script:store.Json
        Invoke-TestLogging
        Assert-Equal $script:store.Json $baseline 'Repeated enable lost the Schannel baseline.'
        Invoke-TestLogging -Restoring $true
        Assert-Equal $script:schannel.Present ($null -ne $value) 'Schannel presence was not restored.'
        Assert-True ($script:schannel.Value -eq $value) 'Schannel DWORD was not restored exactly.'
    }
}
Test-Case 'Schannel errors preserve the baseline through enable and restore' {
    Reset-TestLogging; $script:failSchannel = $true
    Assert-Throws { Invoke-TestLogging -Schannel $true } 'registry denied'
    Assert-True ($null -ne $script:store.Json) 'Schannel failure lost the baseline.'
    Assert-Throws { Invoke-TestLogging -Restoring $true } 'registry denied'
    Assert-Equal $script:store.Deletes 0 'Failed Schannel restore removed the baseline.'
    $script:failSchannel = $false; Invoke-TestLogging -Restoring $true
    Assert-Equal $script:store.Deletes 1 'Schannel retry failed to complete restoration.'
}
Test-Case 'malformed, foreign, and command-bearing baselines never reach native mutations' {
    Reset-TestLogging
    $valid = New-LoggingState 'fixture-machine' 'fixture-caller' $false | ConvertTo-Json -Depth 6 -Compress
    $invalid = @('{', '{}', $valid.Replace('fixture-machine','other-machine'), $valid.Replace('fixture-caller','other-caller'),
        $valid.Replace('"Enabled":false','"Enabled":"false"'), $valid.Replace('"MaximumSize":1048576','"MaximumSize":-1'),
        $valid.Replace('Microsoft-Windows-CAPI2/Operational','Security'), $valid.Replace('Microsoft-Windows-CAPI2/Operational','Microsoft-Windows-CAPI2/Operational /e:false'),
        $valid.Replace('"Version":1','"Version":2'), $valid.Replace('"Version":1','"Command":"anything","Version":1'),
        $valid.Replace('"Schannel":null','"Schannel":{"Present":true,"Value":4294967296}'),
        $valid.Replace('"Schannel":null','"Schannel":{"Present":false,"Value":7}'))
    foreach ($json in $invalid) {
        $script:store.Json = $json
        Assert-Throws { Invoke-TestLogging -Restoring $true }
        Assert-Equal @(Get-TestMutations).Count 0 'Untrusted state reached a logging mutation.'
        Assert-Equal $script:store.Deletes 0 'Untrusted state was deleted.'
    }
}
Test-Case 'enumeration native errors are not treated as missing optional logs' {
    Reset-TestLogging; $script:nativeFailures['el'] = 5
    Assert-Throws { Invoke-TestLogging } 'exit=5'
    Assert-Equal $script:store.Saves 0 'Failed enumeration produced a baseline.'
    Assert-Equal @(Get-TestMutations).Count 0 'Failed enumeration changed settings.'
    $script:nativeFailureText = 'x' * 4096
    $message = ''
    try { Invoke-TestLogging } catch { $message = $_.Exception.Message }
    Assert-True ($message.Length -lt 1200 -and $message -match '\[truncated\]') 'Native failure text is unbounded.'
}

Test-Case 'real native boundary returns the actual wevtutil exit code without changing logging' {
    $global:LASTEXITCODE = 77
    $result = & $script:realLoggingNative @('el')
    Assert-Equal $result.ExitCode 0 'Successful native enumeration lost its exit code.'
    Assert-True (-not [string]::IsNullOrWhiteSpace($result.Text)) 'Native enumeration returned no channels.'
}

# Real state-store tests stay inside the supplied scratch directory. No native
# logger or registry adapter is restored for these tests.
$caseRoot = Join-Path $ScratchPath ('logging-fixtures-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($caseRoot)
$caller = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
try {
    Test-Case 'state store compiles and preserves private durable baseline across reopening and retries' {
        Initialize-LoggingStore
        $path = Join-Path $caseRoot 'private'
        $lease = New-Object Dot1xLogging.Store($path,$caller,$true)
        try {
            Assert-True ($null -eq $lease.Read()) 'Fresh store has a baseline.'
            $lease.SaveNew('{"fixture":1}')
            Assert-Throws { $lease.SaveNew('{"fixture":2}') } 'must not be overwritten'
            Assert-Throws { $other = New-Object Dot1xLogging.Store($path,$caller,$true); try { $other.Read() } finally { $other.Dispose() } } 'open failed'
            $acl = (New-Object IO.DirectoryInfo($path)).GetAccessControl()
            Assert-True $acl.AreAccessRulesProtected 'Directory is not protected.'
            Assert-Equal $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value $caller 'Wrong directory owner.'
        } finally { $lease.Dispose() }
        $lease = New-Object Dot1xLogging.Store($path,$caller,$true)
        try { Assert-Equal $lease.Read() '{"fixture":1}' 'Baseline did not survive reopening.'; $lease.DeleteBaseline() }
        finally { $lease.Dispose() }
        Assert-True (-not [IO.File]::Exists((Join-Path $path 'state.json'))) 'Completed restore left the baseline.'
    }
    Test-Case 'state store rejects unsafe existing ACL without rewriting it' {
        $path = Join-Path $caseRoot 'unsafe'
        $null = [IO.Directory]::CreateDirectory($path)
        $before = (Get-Acl -LiteralPath $path).Sddl
        Assert-Throws { $lease = New-Object Dot1xLogging.Store($path,$caller,$true); $lease.Dispose() } 'unsafe'
        Assert-Equal (Get-Acl -LiteralPath $path).Sddl $before 'Unsafe directory ACL was silently replaced.'
    }
    Test-Case 'state store rejects foreign owner, inherited state ACL, and oversized state' {
        $path = Join-Path $caseRoot 'validation'
        $lease = New-Object Dot1xLogging.Store($path,$caller,$true)
        try { $lease.SaveNew('{"fixture":1}') } finally { $lease.Dispose() }
        Assert-Throws { $other = New-Object Dot1xLogging.Store($path,'S-1-5-21-1-2-3-1001',$true); $other.Dispose() } 'unsafe'
        $file = Join-Path $path 'state.json'
        $acl = Get-Acl -LiteralPath $file; $original = $acl.Sddl
        $acl.SetAccessRuleProtection($false,$true); Set-Acl -LiteralPath $file -AclObject $acl
        $lease = New-Object Dot1xLogging.Store($path,$caller,$true)
        try { Assert-Throws { $lease.Read() } 'unsafe' } finally { $lease.Dispose() }
        $acl.SetSecurityDescriptorSddlForm($original); Set-Acl -LiteralPath $file -AclObject $acl
        [IO.File]::WriteAllText($file,('x' * 65537))
        $lease = New-Object Dot1xLogging.Store($path,$caller,$true)
        try { Assert-Throws { $lease.Read() } 'size is invalid' } finally { $lease.Dispose() }
    }
    Test-Case 'state store rejects reparse paths and hard-linked baselines' {
        $target = Join-Path $caseRoot 'target'
        $null = [IO.Directory]::CreateDirectory($target)
        $junction = Join-Path $caseRoot 'junction'
        $null = New-Item -Path $junction -ItemType Junction -Target $target -ErrorAction Stop
        try { Assert-Throws { $lease = New-Object Dot1xLogging.Store((Join-Path $junction 'state'),$caller,$true); $lease.Dispose() } 'reparse point' }
        finally { [IO.Directory]::Delete($junction) }
        Assert-Equal @([IO.Directory]::EnumerateFileSystemEntries($target)).Count 0 'Reparse target was changed.'
        $path = Join-Path $caseRoot 'hardlink'
        $lease = New-Object Dot1xLogging.Store($path,$caller,$true)
        try { $lease.SaveNew('{"fixture":1}') } finally { $lease.Dispose() }
        $file = Join-Path $path 'state.json'
        $null = New-Item -Path (Join-Path $caseRoot 'alias.json') -ItemType HardLink -Target $file -ErrorAction Stop
        $lease = New-Object Dot1xLogging.Store($path,$caller,$true)
        try { Assert-Throws { $lease.Read() } 'hard link' } finally { $lease.Dispose() }
        Assert-Equal ([IO.File]::ReadAllText($file)) '{"fixture":1}' 'Hard-linked baseline was modified.'
    }
} finally { [IO.Directory]::Delete($caseRoot,$true) }
Complete-Tests

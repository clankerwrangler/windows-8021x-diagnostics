#requires -version 5.1
<#
.SYNOPSIS
Collects bounded, read-only Windows wired and wireless 802.1X evidence.
.DESCRIPTION
Requires Windows PowerShell 5.1 and components that ship with Windows 10/11.
Read-only collection. Reports can include private network details.
Dot-source this file to load the offline rules functions.
.PARAMETER EvidencePath
Read a bounded synthetic evidence JSON file instead of collecting host data.
.PARAMETER OutputDirectory
Save evidence.json, report.json, and report.txt in a unique private run folder
under this reusable destination. Missing directories are created; existing files
and directory ACLs are not changed. The actual run folder is included in text
and PassThru output. A live run with no destination saves under Desktop\Dot1x-Report.
Offline -EvidencePath without a destination still prints to the pipeline only.
.PARAMETER IncludeEventMessages
Include up to 2048 characters of each event message. Live collection includes
messages by default. Messages can contain identities.
.PARAMETER OmitEventMessages
Omit rendered event messages on a live run. Profile names, server names,
certificate identifiers, addresses, and saved paths can still identify users or networks.
.PARAMETER InterfaceAlias
Limit interface-related collection and findings to this exact adapter alias.
.PARAMETER ProfileName
Limit profile findings and profile collection to this exact profile name.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$EvidencePath,
    [string]$InterfaceAlias,
    [string]$ProfileName,
    [ValidateRange(1,168)][int]$LookbackHours = 24,
    [ValidateRange(1,500)][int]$MaxEventsPerLog = 250,
    [ValidateRange(2,120)][int]$ProbeTimeoutSeconds = 20,
    [ValidateRange(10,600)][int]$OverallTimeoutSeconds = 180,
    [ValidateRange(1,128)][int]$MaxProfiles = 32,
    [ValidateRange(1,500)][int]$MaxCertificatesPerStore = 100,
    [switch]$IncludeEventMessages,
    [switch]$OmitEventMessages,
    [switch]$PassThru,
    [Parameter(DontShow=$true)][string]$WorkerName,
    [Parameter(DontShow=$true)][string]$WorkerContext
)

function Get-Dot1xValue {
    param($Object, [string]$Name, $Default = $null)
    if ($null -ne $Object) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($Name)) { return $Object[$Name] }
        } else {
            $p = $Object.PSObject.Properties[$Name]
            if ($null -ne $p) { return $p.Value }
        }
    }
    return $Default
}

function ConvertTo-Dot1xGuid {
    param($Value)
    $g = [guid]::Empty
    if ([guid]::TryParse([string]$Value, [ref]$g)) { return $g.ToString('D') }
    return ''
}

function ConvertTo-Dot1xUInt32 {
    param($Value)
    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    try {
        if ($text -match '^0x[0-9A-Fa-f]{1,8}$') {
            return [Convert]::ToUInt32($text.Substring(2), 16)
        }
        $unsigned = [uint32]0
        if ([uint32]::TryParse($text, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$unsigned)) {
            return $unsigned
        }
        $signed = 0
        if ([int]::TryParse($text, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$signed)) {
            return [BitConverter]::ToUInt32([BitConverter]::GetBytes($signed), 0)
        }
    } catch { }
    return $null
}

function Get-Dot1xOnexReasonLabel {
    param([uint32]$Code)
    switch (('{0:X8}' -f $Code)) {
        '00050001' { return 'ONEX_UNABLE_TO_IDENTIFY_USER: no usable credential set was identified' }
        '00050003' { return 'ONEX_UI_DISABLED: required user input could not be obtained' }
        '00050004' { return 'ONEX_UI_FAILURE: required user input failed' }
        '00050005' { return 'ONEX_EAP_FAILURE_RECEIVED: the EAP module returned a failure' }
        '00050006' { return 'ONEX_AUTHENTICATOR_NO_LONGER_PRESENT: the authenticator disappeared' }
        '00050007' { return 'ONEX_NO_RESPONSE_TO_IDENTITY: no response to the identity response' }
        '00050008' { return 'ONEX_PROFILE_VERSION_NOT_SUPPORTED: profile version is unsupported' }
        '0005000A' { return 'ONEX_PROFILE_DISALLOWED_EAP_TYPE: the EAP type is not allowed' }
        '0005000B' { return 'ONEX_PROFILE_INVALID_EAP_TYPE_OR_FLAG: EAP type or flags are invalid' }
        '0005000F' { return 'ONEX_PROFILE_INVALID_AUTH_MODE: authentication mode is invalid' }
        '00050010' { return 'ONEX_PROFILE_INVALID_EAP_CONNECTION_PROPERTIES: EAP connection properties are invalid' }
        '00050014' { return 'ONEX_UI_NOT_PERMITTED: user input was not permitted' }
        default { return $null }
    }
}

function Get-Dot1xHresultLabel {
    param([uint32]$Code)
    # Constant references and namespace limits: docs/error-codes.md.
    # PowerShell 5.1 sign-extends 0x80000000+ hex literals to Int32, so match on hex text.
    switch (('{0:X8}' -f $Code)) {
        '800B0101' { return 'CERT_E_EXPIRED: a certificate is expired or not yet valid' }
        '800B0109' { return 'CERT_E_UNTRUSTEDROOT: the chain ended in an untrusted root' }
        '800B010A' { return 'CERT_E_CHAINING: a chain could not be built to a trusted root' }
        '800B010C' { return 'CERT_E_REVOKED: a certificate in the chain is revoked' }
        '800B010E' { return 'CERT_E_REVOCATION_FAILURE: revocation checking failed' }
        '800B010F' { return 'CERT_E_CN_NO_MATCH: the certificate name did not match the expected name' }
        '800B0110' { return 'CERT_E_WRONG_USAGE: the certificate is not valid for this use' }
        '800B0114' { return 'CERT_E_INVALID_NAME: a certificate name is excluded or outside the permitted name constraints' }
        '80092012' { return 'CRYPT_E_NO_REVOCATION_CHECK: no revocation check was performed' }
        '80092013' { return 'CRYPT_E_REVOCATION_OFFLINE: revocation check timed out or the responder was unreachable' }
        '8009030C' { return 'SEC_E_LOGON_DENIED: the logon was denied' }
        '8009030E' { return 'SEC_E_NO_CREDENTIALS: no credentials were available' }
        '8009030D' { return 'SEC_E_UNKNOWN_CREDENTIALS: the credentials were not recognized' }
        '80090317' { return 'SEC_E_CONTEXT_EXPIRED: the security context has expired' }
        '80090325' { return 'SEC_E_UNTRUSTED_ROOT: the certificate chain has an untrusted issuing authority' }
        '80090327' { return 'SEC_E_CERT_UNKNOWN: an unspecified certificate-processing error occurred' }
        '80090326' { return 'SEC_E_ILLEGAL_MESSAGE: TLS received an illegal message' }
        '80090328' { return 'SEC_E_CERT_EXPIRED: the peer certificate is expired' }
        '80090331' { return 'SEC_E_ALGORITHM_MISMATCH: TLS algorithm mismatch' }
        '80090016' { return 'NTE_BAD_KEYSET: the private key was not available' }
        '80420014' { return 'EAP_E_EAPHOST_IDENTITY_UNKNOWN: authentication failed after the peer identity was submitted' }
        '80420100' { return 'EAP_E_USER_CERT_NOT_FOUND: the required user certificate was not found' }
        default { return $null }
    }
}

function Get-Dot1xRasErrorLabel {
    param([uint32]$Code)
    if ($Code -eq 691) { return 'ERROR_AUTHENTICATION_FAILURE: the user name or password was not accepted' }
    return $null
}

function Get-Dot1xEventCodeDetails {
    param($Event)
    $fields = Get-Dot1xValue $Event 'Fields' @{}
    $provider = [string](Get-Dot1xValue $Event 'ProviderName')
    $id = Get-Dot1xValue $Event 'Id'
    $recognizedFailure = ($provider -eq 'Microsoft-Windows-WLAN-AutoConfig' -and $id -eq 12013) -or
        ($provider -eq 'Microsoft-Windows-Wired-AutoConfig' -and $id -eq 15514)
    foreach ($name in @('ReasonCode','ErrorCode','ResultCode','EapErrorCode','FailureReasonCode','EapReasonCode')) {
        $raw = Get-Dot1xValue $fields $name
        if ($null -eq $raw -or [string]::IsNullOrWhiteSpace([string]$raw)) { continue }
        $code = ConvertTo-Dot1xUInt32 $raw
        $hex = $null; $label = $null; $candidateNamespace = $null
        $status = 'NotNumeric'
        if ($null -ne $code) {
            $hex = '0x{0:X8}' -f $code
            $status = 'Unmapped'
            if ($recognizedFailure) {
                if ($name -eq 'ReasonCode') {
                    $label = Get-Dot1xOnexReasonLabel $code
                    if ($label) { $candidateNamespace = 'ONEX' }
                } elseif ($name -in @('ErrorCode','ResultCode','EapErrorCode')) {
                    $label = Get-Dot1xHresultLabel $code
                    if ($label) { $candidateNamespace = 'HRESULT' }
                    else {
                        $label = Get-Dot1xRasErrorLabel $code
                        if ($label) { $candidateNamespace = 'RAS' }
                    }
                }
            }
            if ($label) { $status = 'UnverifiedNumericMatch' }
        }
        # A constant match is not an event-field contract. No provider/version/field
        # contract is verified yet; keep Namespace unknown even when a label exists.
        [pscustomobject][ordered]@{
            ProviderName=$provider; EventId=$id; EventVersion=(Get-Dot1xValue $Event 'Version')
            Field=$name; RawValue=[string]$raw; HexValue=$hex; Namespace='Unknown'
            MappingStatus=$status; CandidateNamespace=$candidateNamespace; CandidateLabel=$label
        }
    }
}

function Get-Dot1xAuthFailureSummary {
    param($Event, [string]$Provider, $Id)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    $parts.Add("$Provider event $Id reports a historical 802.1X failure.")
    foreach ($detail in @(Get-Dot1xEventCodeDetails $Event)) {
        if ($detail.MappingStatus -eq 'UnverifiedNumericMatch') {
            $parts.Add(('{0} {1}; numeric match in {2}: {3} (field namespace unverified).' -f
                $detail.Field,$detail.HexValue,$detail.CandidateNamespace,$detail.CandidateLabel))
        } elseif ($detail.HexValue) {
            $parts.Add(('{0} {1} is retained as an unmapped numeric code.' -f $detail.Field,$detail.HexValue))
        } else { $parts.Add(('{0}={1}' -f $detail.Field,$detail.RawValue)) }
    }
    return ($parts -join ' ')
}

function Add-Dot1xFinding {
    param([System.Collections.Generic.List[object]]$List, [string]$Id,
          [string]$Severity, [string]$Confidence, [string]$Category,
          [string]$Summary, [string[]]$Evidence, [string[]]$Remediation,
          [string[]]$Limitations, $AuthenticationContext = $null)
    $List.Add([pscustomobject][ordered]@{
        Id=$Id; Severity=$Severity; Confidence=$Confidence; Category=$Category
        Summary=$Summary; Evidence=@($Evidence); Remediation=@($Remediation)
        Limitations=@($Limitations); AuthenticationContext=$AuthenticationContext
    })
}

function Get-Dot1xDiagnosis {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Evidence)
    $findings = New-Object 'System.Collections.Generic.List[object]'
    $profiles = @(Get-Dot1xValue $Evidence 'Profiles' @())
    $interfaces = @(Get-Dot1xValue $Evidence 'Interfaces' @())
    $services = @(Get-Dot1xValue $Evidence 'Services' @())
    $events = @(Get-Dot1xValue $Evidence 'Events' @())
    $certificates = @(Get-Dot1xValue $Evidence 'Certificates' @())
    $stores = @(Get-Dot1xValue $Evidence 'CertificateStores' @())
    $probes = @(Get-Dot1xValue $Evidence 'Probes' @())
    $collection = Get-Dot1xValue $Evidence 'Collection'
    $now = [datetime]::MinValue
    $timeKnown = [datetime]::TryParse([string](Get-Dot1xValue $Evidence 'CapturedAtUtc'), [ref]$now)
    if ($timeKnown) { $now = $now.ToUniversalTime() }
    $incomplete = @($probes | Where-Object { (Get-Dot1xValue $_ 'Status') -ne 'Succeeded' })
    if ($incomplete.Count -gt 0) {
        Add-Dot1xFinding $findings 'COLLECTION-INCOMPLETE' 'Warning' 'High' 'Collection' `
            'Some evidence is unavailable or incomplete.' `
            @($incomplete | ForEach-Object { '{0}: {1}' -f (Get-Dot1xValue $_ 'Name'), (Get-Dot1xValue $_ 'Status') }) `
            @('Check the failed probe details. For access-denied results, collect in the affected user context and elevate that account where possible.') `
            @()
    }
    if ($probes.Count -eq 0 -and $profiles.Count -eq 0 -and $interfaces.Count -eq 0) {
        Add-Dot1xFinding $findings 'EVIDENCE-EMPTY' 'Information' 'High' 'Collection' `
            'No interface or profile evidence is available.' @('Evidence arrays are missing or empty.') `
            @('Run the collector on the affected Windows endpoint.') @()
    }
    $targetAlias = [string](Get-Dot1xValue $collection 'InterfaceAlias')
    $targetProfile = [string](Get-Dot1xValue $collection 'ProfileName')
    if ($targetAlias) {
        $interfaces = @($interfaces | Where-Object { (Get-Dot1xValue $_ 'Alias') -eq $targetAlias })
        $targetGuids = @($interfaces | ForEach-Object { ConvertTo-Dot1xGuid (Get-Dot1xValue $_ 'InterfaceGuid') })
        $profiles = @($profiles | Where-Object { $targetGuids -contains (ConvertTo-Dot1xGuid (Get-Dot1xValue $_ 'InterfaceGuid')) })
        $events = @($events | Where-Object { (Get-Dot1xValue $_ 'ProviderName') -notmatch 'AutoConfig$' -or $targetGuids -contains (ConvertTo-Dot1xGuid (Get-Dot1xValue $_ 'InterfaceGuid')) })
        if ($interfaces.Count -eq 0) {
            Add-Dot1xFinding $findings 'TARGET-NOT-FOUND' 'Information' 'High' 'Scope' `
                'The requested interface alias is not present in the collected interface evidence.' @('No interface-specific failure was inferred.') `
                @('Check the exact interface alias and probe coverage in the affected endpoint context.') @('Missing interface data is not proof that the adapter is absent.')
        }
    }
    if ($targetProfile) {
        $profiles = @($profiles | Where-Object { (Get-Dot1xValue $_ 'Name') -eq $targetProfile })
        $events = @($events | Where-Object { (Get-Dot1xValue $_ 'ProviderName') -notmatch 'AutoConfig$' -or (Get-Dot1xValue (Get-Dot1xValue $_ 'Fields') 'ProfileName') -eq $targetProfile })
    }
    $lookback = 0
    [void][int]::TryParse([string](Get-Dot1xValue $collection 'LookbackHours'), [ref]$lookback)
    if ($timeKnown) {
        $events = @($events | Where-Object {
            $eventTime = [datetime]::MinValue
            [datetime]::TryParse([string](Get-Dot1xValue $_ 'TimeCreatedUtc'), [ref]$eventTime) -and $eventTime.ToUniversalTime() -le $now -and ($lookback -le 0 -or $eventTime.ToUniversalTime() -ge $now.AddHours(-$lookback))
        })
    }
    $targetWireless = $targetAlias -and @($interfaces | Where-Object { (Get-Dot1xValue $_ 'PhysicalMediaType') -match '802\.11|Wireless' }).Count -gt 0
    $targetWired = $targetAlias -and @($interfaces | Where-Object {
        (Get-Dot1xValue $_ 'PhysicalMediaType') -notmatch '802\.11|Wireless' -and ((Get-Dot1xValue $_ 'PhysicalMediaType') -in @('802.3','14') -or (Get-Dot1xValue $_ 'MediaType') -eq '802.3')
    }).Count -gt 0
    if ($targetAlias) {
        foreach ($interface in $interfaces) {
            $link = [string](Get-Dot1xValue $interface 'Status')
            if ($link -in @('Disabled','Disconnected','NotPresent')) {
                $severity = 'Warning'; if ($link -eq 'Disconnected') { $severity = 'Information' }
                Add-Dot1xFinding $findings 'TARGET-INTERFACE-NOT-UP' $severity 'High' 'Link state' `
                    "The targeted interface reports local state $link." @("Interface=$targetAlias; status=$link") `
                    @('Review the intended adapter, cable, dock, radio, and AP/link availability with the endpoint owner before an approved change.') `
                    @('This is a local link fact, not a RADIUS, certificate, or password diagnosis. A disconnected or intentionally disabled interface can be expected.')
            }
        }
    }
    if ($targetProfile -and $profiles.Count -eq 0) {
        $requiredProfileProbes = @('Wireless','Wired')
        if ($targetWireless) { $requiredProfileProbes = @('Wireless') }
        elseif ($targetWired) { $requiredProfileProbes = @('Wired') }
        $profileCoverageComplete = $true
        foreach ($probeName in $requiredProfileProbes) {
            $completed = @($probes | Where-Object { (Get-Dot1xValue $_ 'Name') -eq $probeName -and (Get-Dot1xValue $_ 'Status') -eq 'Succeeded' -and @(Get-Dot1xValue $_ 'Limitations' @()).Count -eq 0 })
            if ($completed.Count -eq 0) { $profileCoverageComplete = $false }
        }
        $summary = 'The requested profile was not observed, but profile visibility is incomplete.'
        $confidence = 'Low'
        if ($profileCoverageComplete) { $summary = 'The requested profile was not found within the inspected interface and execution-user scope.'; $confidence = 'Medium' }
        Add-Dot1xFinding $findings 'PROFILE-NOT-OBSERVED' 'Information' $confidence 'Profile' `
            $summary @("Requested profile=$targetProfile; required probes=$($requiredProfileProbes -join ', '); complete=$profileCoverageComplete") `
            @('Check the exact profile/interface name, affected user context, and profile assignment with the GPO/MDM or local profile owner.') `
            @('A failed, skipped, or truncated query does not prove absence. Profiles belonging to other users or unapplied management assignments are not established by this snapshot.')
    }
    $enterpriseProfiles = @($profiles | Where-Object { (Get-Dot1xValue $_ 'OneXEnabled') -eq $true })
    $wiredRequired = @($enterpriseProfiles | Where-Object { (Get-Dot1xValue $_ 'Kind') -eq 'Wired' }).Count -gt 0
    $wirelessRequired = @($enterpriseProfiles | Where-Object { (Get-Dot1xValue $_ 'Kind') -eq 'Wireless' }).Count -gt 0
    foreach ($s in $services) {
        $name = [string](Get-Dot1xValue $s 'Name')
        $status = [string](Get-Dot1xValue $s 'Status')
        $start = [string](Get-Dot1xValue $s 'StartMode')
        if (($name -eq 'dot3svc' -and ($wiredRequired -or $targetWired)) -or ($name -eq 'WlanSvc' -and ($wirelessRequired -or $targetWireless))) {
            if ($status -and $status -ne 'Running') {
                $id = 'SERVICE-WLAN-NOT-RUNNING'
                if ($name -eq 'dot3svc') { $id = 'SERVICE-WIRED-NOT-RUNNING' }
                $serviceSeverity = 'Warning'; $serviceConfidence = 'High'
                $serviceSummary = "$name is not running and a collected profile requires 802.1X."
                if (($name -eq 'dot3svc' -and -not $wiredRequired) -or ($name -eq 'WlanSvc' -and -not $wirelessRequired)) {
                    $serviceSeverity = 'Information'; $serviceConfidence = 'Medium'
                    $serviceSummary = "$name is not running on the structurally matched targeted medium; relevance to the attempted 802.1X connection is indicated, not proven."
                }
                Add-Dot1xFinding $findings $id $serviceSeverity $serviceConfidence 'Services' `
                    $serviceSummary @("Status=$status; start mode=$start; targeted interface=$targetAlias") `
                    @('Confirm that the target connection requires AutoConfig, then check the service start mode, dependencies, and service events.') `
                    @('Stopped AutoConfig can itself prevent profile enumeration. Nonenterprise wired operation might not need dot3svc. A stored profile might not be the attempted connection. This does not identify a RADIUS cause.')
            }
        }
        if ($name -eq 'EapHost' -and $start -eq 'Disabled' -and $enterpriseProfiles.Count -gt 0) {
            Add-Dot1xFinding $findings 'EAPHOST-DISABLED' 'Warning' 'High' 'Services' `
                'EapHost is disabled while an 802.1X profile is present.' @("Status=$status; start mode=$start") `
                @('Check why the effective EapHost service start mode is Disabled.') `
                @('A stopped demand-start EapHost service alone is normal and is not diagnosed as a fault.')
        }
    }
    foreach ($p in $enterpriseProfiles) {
        $label = '{0} profile {1}' -f (Get-Dot1xValue $p 'Kind'), (Get-Dot1xValue $p 'Name')
        $validation = Get-Dot1xValue $p 'ServerValidationEnabled'
        if ($null -ne $validation -and $validation -eq $false) {
            Add-Dot1xFinding $findings 'PROFILE-SERVER-VALIDATION-DISABLED' 'Warning' 'High' 'Profile' `
                "$label explicitly disables server certificate validation." @('The profile contains an explicit disabled validation setting.') `
                @('Configure the intended server names and trust anchors in the deployed profile, with server validation enabled.') `
                @('This is a security configuration concern, not proof of the observed connection failure.')
        }
        $eapTypes = @(Get-Dot1xValue $p 'EapTypes' @())
        if ($eapTypes -contains 13) {
            $authMode = [string](Get-Dot1xValue $p 'AuthMode')
            $neededStores = @('CurrentUser','LocalMachine')
            if ($authMode -eq 'machine') { $neededStores = @('LocalMachine') }
            elseif ($authMode -eq 'user') { $neededStores = @('CurrentUser') }
            $complete = $true
            foreach ($store in $neededStores) {
                $coverage = @($stores | Where-Object { (Get-Dot1xValue $_ 'Store') -eq $store -and (Get-Dot1xValue $_ 'Status') -eq 'Succeeded' -and (Get-Dot1xValue $_ 'Truncated') -ne $true })
                if ($coverage.Count -eq 0) { $complete = $false }
            }
            $eligible = @($certificates | Where-Object {
                $store = Get-Dot1xValue $_ 'Store'
                $ekus = @(Get-Dot1xValue $_ 'EkuOids' @())
                $ekuEligible = Get-Dot1xValue $_ 'ClientAuthEkuEligible'
                if ($null -eq $ekuEligible) { $ekuEligible = ($ekus.Count -eq 0 -or $ekus -contains '1.3.6.1.5.5.7.3.2' -or $ekus -contains '2.5.29.37.0') }
                $neededStores -contains $store -and (Get-Dot1xValue $_ 'HasPrivateKey') -eq $true -and $ekuEligible -eq $true
            })
            $valid = @($eligible | Where-Object {
                $before = [datetime]::MinValue; $after = [datetime]::MinValue
                $datesKnown = [datetime]::TryParse([string](Get-Dot1xValue $_ 'NotBeforeUtc'), [ref]$before) -and [datetime]::TryParse([string](Get-Dot1xValue $_ 'NotAfterUtc'), [ref]$after)
                $datesKnown -and $timeKnown -and $before.ToUniversalTime() -le $now -and $after.ToUniversalTime() -gt $now
            })
            $dateCoverage = @($eligible | Where-Object {
                $d = [datetime]::MinValue
                -not ([datetime]::TryParse([string](Get-Dot1xValue $_ 'NotBeforeUtc'), [ref]$d) -and [datetime]::TryParse([string](Get-Dot1xValue $_ 'NotAfterUtc'), [ref]$d))
            }).Count -eq 0
            $scopedCertificates = @($certificates | Where-Object { $neededStores -contains (Get-Dot1xValue $_ 'Store') })
            $missingKeys = @($scopedCertificates | Where-Object { (Get-Dot1xValue $_ 'HasPrivateKey') -eq $false }).Count
            $wrongEku = @($scopedCertificates | Where-Object {
                $oids = @(Get-Dot1xValue $_ 'EkuOids' @())
                $oids.Count -gt 0 -and $oids -notcontains '1.3.6.1.5.5.7.3.2' -and $oids -notcontains '2.5.29.37.0'
            }).Count
            $expired = @($eligible | Where-Object {
                $d = [datetime]::MinValue
                $timeKnown -and [datetime]::TryParse([string](Get-Dot1xValue $_ 'NotAfterUtc'),[ref]$d) -and $d.ToUniversalTime() -le $now
            }).Count
            $future = @($eligible | Where-Object {
                $d = [datetime]::MinValue
                $timeKnown -and [datetime]::TryParse([string](Get-Dot1xValue $_ 'NotBeforeUtc'),[ref]$d) -and $d.ToUniversalTime() -gt $now
            }).Count
            if ($complete -and $timeKnown -and $dateCoverage -and $valid.Count -eq 0) {
                Add-Dot1xFinding $findings 'CERT-NO-SUITABLE-CANDIDATE' 'Warning' 'Medium' 'Certificate' `
                    "$label contains EAP-TLS, but no structurally eligible, time-valid client certificate was found in the inspected stores." `
                    @("AuthMode=$authMode; stores=$($neededStores -join ', '); private-key/EKU candidates=$($eligible.Count)", "Scoped inventory counts: expired structural candidates=$expired; future-dated structural candidates=$future; missing associated keys=$missingKeys; explicit EKUs excluding client authentication=$wrongEku") `
                    @('Review enrollment, renewal, certificate selection filters, and the intended user or machine authentication context with the certificate administrator.', 'For the intended network certificate only: renew if expired; check the clock and issuance dates if future-dated; review approved enrollment/key association if the key is missing; review the template if its EKU excludes client authentication.') `
                    @('Unrelated certificates in a personal store are not defects. These counts describe inspected inventory, not the certificate selected by the supplicant.', 'CurrentUser belongs to the collector identity, not necessarily the affected user. TEAP/PEAP inner-method alternatives and server policy can change certificate requirements. No key access, server mapping, or authentication was tested.')
            } elseif ($valid.Count -gt 0) {
                Add-Dot1xFinding $findings 'CERT-CANDIDATES-PRESENT' 'Information' 'Medium' 'Certificate' `
                    "$label has structurally eligible client certificate candidates." `
                    @($valid | ForEach-Object {
                        $chain = Get-Dot1xValue $_ 'Chain'
                        '{0}:{1}; cached chain={2}; errors={3}; status={4}' -f (Get-Dot1xValue $_ 'Store'),(Get-Dot1xValue $_ 'Thumbprint'),(Get-Dot1xValue $chain 'Assessment' 'Unknown'),(Get-Dot1xValue $chain 'TrustErrorMask' 'Unknown'),(@(Get-Dot1xValue $chain 'Status' @()) -join ', ')
                    }) `
                    @('Match candidates to profile filters, issuer requirements, server account mapping, and the actual authentication context.', 'If a scoped candidate has cached chain errors, ask the PKI owner which chain element failed. Unknown/offline revocation is not proof of revocation; partial chain can mean missing cached issuers, and a chain time error can concern an issuer.') `
                    @('No EKU means unrestricted EKU; any-purpose also permits client authentication structurally. HasPrivateKey proves presence only. Offline chain results and candidates do not prove server acceptance or key usability.')
                $nearExpiry = @($valid | Where-Object { ([datetime](Get-Dot1xValue $_ 'NotAfterUtc')).ToUniversalTime() -le $now.AddDays(30) })
                if ($nearExpiry.Count -eq $valid.Count) {
                    Add-Dot1xFinding $findings 'CERT-CANDIDATES-EXPIRING' 'Warning' 'Medium' 'Certificate' `
                        "All inspected time-valid candidates for $label expire within 30 days." `
                        @($nearExpiry | ForEach-Object { '{0}: {1}' -f (Get-Dot1xValue $_ 'Thumbprint'), (Get-Dot1xValue $_ 'NotAfterUtc') }) `
                        @('Arrange renewal through the certificate policy owner before expiration.') @('The actual selected certificate is not established.')
                }
            }
        }
    }
    $authEvents = New-Object 'System.Collections.Generic.List[object]'
    foreach ($e in $events) {
        $provider = [string](Get-Dot1xValue $e 'ProviderName')
        $id = Get-Dot1xValue $e 'Id'
        $outcome = $null
        if ($provider -eq 'Microsoft-Windows-WLAN-AutoConfig') {
            if ($id -eq 12012) { $outcome = 'Success' }
            elseif ($id -eq 12013) { $outcome = 'Failure' }
        }
        if ($provider -eq 'Microsoft-Windows-Wired-AutoConfig') {
            # Installed signed provider metadata identifies these auth outcomes.
            if ($id -eq 15505) { $outcome = 'Success' }
            elseif ($id -eq 15514) { $outcome = 'Failure' }
        }
        if ($null -ne $outcome) {
            $authEvents.Add([pscustomobject]@{ Event=$e; Outcome=$outcome })
            if ($outcome -eq 'Failure') {
                $summary = Get-Dot1xAuthFailureSummary -Event $e -Provider $provider -Id $id
                Add-Dot1xFinding $findings 'AUTH-HISTORICAL-FAILURE' 'Warning' 'High' 'Authentication history' `
                    $summary `
                    @("Provider=$provider; event=$id; record=$(Get-Dot1xValue $e 'RecordId'); UTC=$(Get-Dot1xValue $e 'TimeCreatedUtc'); interface=$(Get-Dot1xValue $e 'InterfaceGuid')", ('Fields: ' + ((Get-Dot1xValue $e 'Fields' @{}) | ConvertTo-Json -Compress -Depth 5))) `
                    @('Confirm that this timestamp and interface match the reported attempt. Use the event details and matching RADIUS/NPS logs to choose the next check.') `
                    @('A later successful attempt can supersede this failure. Numeric code matches are reference labels, not a confirmed cause.')
                $findings[$findings.Count - 1] | Add-Member -NotePropertyName CodeDetails -NotePropertyValue @(Get-Dot1xEventCodeDetails $e)
            }
        }
    }
    $supportEvents = @($events | Where-Object {
        $provider = [string](Get-Dot1xValue $_ 'ProviderName'); $level = Get-Dot1xValue $_ 'Level'
        $null -ne $level -and $level -ge 1 -and $level -le 3 -and @('Microsoft-Windows-EapHost','Schannel','Microsoft-Windows-CAPI2') -contains $provider
    })
    if ($supportEvents.Count -gt 0) {
        Add-Dot1xFinding $findings 'TLS-EAP-SUPPORTING-HISTORY' 'Information' 'Low' 'Authentication history' `
            'Historical EAP or certificate/TLS warnings are available for correlation.' `
            @($supportEvents | Select-Object -First 20 | ForEach-Object { '{0}, event {1}, record {2}, UTC {3}' -f (Get-Dot1xValue $_ 'ProviderName'), (Get-Dot1xValue $_ 'Id'), (Get-Dot1xValue $_ 'RecordId'), (Get-Dot1xValue $_ 'TimeCreatedUtc') }) `
            @('Match these events to the actual connection attempt before interpreting their provider-specific error codes.') `
            @('Schannel and CAPI2 also serve unrelated applications. These events alone do not establish an 802.1X cause. EAP TLS does not always emit Schannel events.')
    }
    $ntlmEvents = @($events | Where-Object { (Get-Dot1xValue $_ 'ProviderName') -eq 'Microsoft-Windows-NTLM' -and (Get-Dot1xValue $_ 'Id') -in @(4013,4014) })
    if ($ntlmEvents.Count -gt 0) {
        Add-Dot1xFinding $findings 'NTLM-CREDENTIAL-GUARD-CONTEXT' 'Information' 'Low' 'Authentication history' `
            'NTLM history contains a blocked legacy authentication or credential-key operation.' `
            @($ntlmEvents | Select-Object -First 20 | ForEach-Object { 'Microsoft-Windows-NTLM event {0}, UTC {1}' -f (Get-Dot1xValue $_ 'Id'),(Get-Dot1xValue $_ 'TimeCreatedUtc') }) `
            @('Correlate the event with the affected EAP attempt and single sign-on policy. Prefer a supported certificate-based design through the policy owner rather than disabling Credential Guard.') `
            @('These events can involve unrelated applications. Credential Guard can block MSCHAPv2 single sign-on without proving that manually supplied credential authentication fails. No security feature was queried for secrets or modified.')
    }
    foreach ($wireless in @(Get-Dot1xValue $Evidence 'Wireless' @())) {
        $code = Get-Dot1xValue $wireless 'ConnectionQueryCode'
        if ($null -ne $code -and $code -ne 0) {
            Add-Dot1xFinding $findings 'WLAN-CURRENT-STATE-UNAVAILABLE' 'Information' 'High' 'Wireless state' `
                'The native WLAN current-connection query was unavailable.' @("Native result code=$code") `
                @('Review access and the current connection from the affected user context. Windows 11 location permission can restrict this API; ask the affected user or policy owner to review it if appropriate.') `
                @('No permission was changed. An unavailable query does not prove disconnection or authentication failure.')
        }
    }
    $ipConfigurations = @(Get-Dot1xValue $Evidence 'IpConfiguration' @())
    foreach ($interface in $interfaces) {
        if ((Get-Dot1xValue $interface 'Status') -ne 'Up') { continue }
        $index = Get-Dot1xValue $interface 'InterfaceIndex'
        $alias = [string](Get-Dot1xValue $interface 'Alias')
        $ipRows = @($ipConfigurations | Where-Object { (Get-Dot1xValue $_ 'InterfaceIndex') -eq $index })
        if ($ipRows.Count -eq 0) { continue }
        $ip = $ipRows[0]
        $addresses = @((Get-Dot1xValue $ip 'IPv4Addresses' @())) + @((Get-Dot1xValue $ip 'IPv6Addresses' @()))
        $usable = @($addresses | Where-Object {
            $text = if ($_ -is [string]) { $_ } else { Get-Dot1xValue $_ 'IPAddress' }
            $addressState = Get-Dot1xValue $_ 'AddressState'
            $addr = $null
            $parsed = [System.Net.IPAddress]::TryParse([string]$text, [ref]$addr)
            $parsed -and -not [System.Net.IPAddress]::IsLoopback($addr) -and -not $addr.IsIPv6LinkLocal -and $text -notmatch '^(169\.254\.|0\.|::$)' -and $addressState -notin @('Invalid','Tentative','Duplicate')
        })
        $guid = ConvertTo-Dot1xGuid (Get-Dot1xValue $interface 'InterfaceGuid')
        $matchingHistory = @($authEvents | Where-Object { $guid -and (ConvertTo-Dot1xGuid (Get-Dot1xValue $_.Event 'InterfaceGuid')) -eq $guid } | Sort-Object { Get-Dot1xValue $_.Event 'TimeCreatedUtc' } -Descending)
        $authContext = 'No matching authentication outcome was observed.'
        $history = $null
        if ($matchingHistory.Count -gt 0) {
            $last = $matchingHistory[0]
            $history = [pscustomobject][ordered]@{
                Outcome=$last.Outcome; IsHistorical=$true
                TimeCreatedUtc=(Get-Dot1xValue $last.Event 'TimeCreatedUtc')
                InterfaceGuid=(Get-Dot1xValue $last.Event 'InterfaceGuid')
                ProfileName=(Get-Dot1xValue (Get-Dot1xValue $last.Event 'Fields') 'ProfileName')
                ProviderName=(Get-Dot1xValue $last.Event 'ProviderName')
                EventId=(Get-Dot1xValue $last.Event 'Id'); RecordId=(Get-Dot1xValue $last.Event 'RecordId')
            }
            $authContext = 'Latest matching historical authentication outcome: {0}, UTC {1}.' -f $history.Outcome, $history.TimeCreatedUtc
        }
        if ($usable.Count -eq 0) {
            Add-Dot1xFinding $findings 'IP-NO-USABLE-ADDRESS' 'Warning' 'High' 'IP configuration' `
                "$alias is up, but its collected addresses contain no usable non-link-local IPv4 or IPv6 address." `
                @("InterfaceIndex=$index", $authContext) `
                @('Review DHCP, static addressing, intended VLAN, and any IPv6-only design. If authentication succeeded for this attempt, investigate post-authentication addressing separately.') `
                @('Link-local-only operation can be intentional. No addressing or connectivity test was performed.') -AuthenticationContext $history
        } elseif (@(Get-Dot1xValue $ip 'DnsServers' @()).Count -eq 0) {
            Add-Dot1xFinding $findings 'DNS-NO-SERVERS' 'Warning' 'High' 'DNS configuration' `
                "$alias has a usable address but no collected DNS server configuration." @("InterfaceIndex=$index", $authContext) `
                @('Review the intended DNS configuration and DHCP options after confirming the authentication stage.') `
                @('This is configuration evidence, not a DNS resolution test. Cached names, alternate resolvers, and local-only designs are not assessed.') -AuthenticationContext $history
        }
    }
    return $findings.ToArray()
}

function ConvertFrom-Dot1xProfileXml {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$XmlText, [string]$Kind,
          [string]$InterfaceGuid, [string]$Name, [string]$ConfigurationSource = 'Unknown')
    if ($XmlText.Length -gt 1048576) { throw 'Profile XML exceeds the 1 MiB parsing bound.' }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 1048576
    $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($XmlText)), $settings)
    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    try { $doc.Load($reader) } finally { $reader.Dispose() }
    function Read-NodeText([string]$xpath) {
        $node = $doc.SelectSingleNode($xpath)
        if ($null -ne $node) { return [string]$node.InnerText }
        return $null
    }
    function Read-Bool([string]$text) {
        if ($text -eq 'true' -or $text -eq '1') { return $true }
        if ($text -eq 'false' -or $text -eq '0') { return $false }
        return $null
    }
    if (-not $Name) { $Name = Read-NodeText '/*/*[local-name()="name"]' }
    $hostPath = '//*[local-name()="EapHostConfig" and namespace-uri()="http://www.microsoft.com/provisioning/EapHostConfig"]'
    $configPath = $hostPath + '/*[local-name()="Config" and namespace-uri()="http://www.microsoft.com/provisioning/EapHostConfig"]'
    $baseEapPath = $configPath + '//*[local-name()="Eap" and namespace-uri()="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"]'
    $methodTypes = $hostPath + '/*[local-name()="EapMethod" and namespace-uri()="http://www.microsoft.com/provisioning/EapHostConfig"]/*[local-name()="Type" and namespace-uri()="http://www.microsoft.com/provisioning/EapCommon"]'
    $eap = @($doc.SelectNodes($methodTypes + ' | ' + $baseEapPath + '/*[local-name()="Type" and namespace-uri()="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"]') | ForEach-Object {
        $number = 0
        if ([int]::TryParse($_.InnerText, [ref]$number)) { $number }
    } | Select-Object -Unique)
    $methods = @($doc.SelectNodes($baseEapPath) | ForEach-Object {
        $typeNode = $_.SelectSingleNode('./*[local-name()="Type" and namespace-uri()="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"]')
        $number = 0
        if ($null -ne $typeNode -and [int]::TryParse($typeNode.InnerText, [ref]$number)) {
            $depth = 0; $parentNode = $_.ParentNode
            while ($null -ne $parentNode) { if ($parentNode.LocalName -eq 'Eap') { $depth++ }; $parentNode = $parentNode.ParentNode }
            [pscustomobject]@{ Type=$number; TunnelDepth=$depth }
        }
    })
    $oneX = Read-Bool (Read-NodeText '//*[local-name()="useOneX"]')
    if ($null -eq $oneX) {
        $oneX = Read-Bool (Read-NodeText '//*[local-name()="OneXEnabled"]')
        if ($null -eq $oneX -and $null -ne $doc.SelectSingleNode('//*[local-name()="OneX"]')) { $oneX = $true }
    }
    $validationNodes = @($doc.SelectNodes($configPath + '//*[(local-name()="PerformServerValidation" or local-name()="DisableServerValidation" or local-name()="ServerValidationEnabled") and starts-with(namespace-uri(),"http://www.microsoft.com/provisioning/")]'))
    $validation = $null
    foreach ($n in $validationNodes) {
        $v = Read-Bool $n.InnerText
        if ($null -ne $v) {
            if ($n.LocalName -eq 'DisableServerValidation') { $v = -not $v }
            if ($v -eq $false) { $validation = $false; break }
            $validation = $true
        }
    }
    [pscustomobject][ordered]@{
        Kind=$Kind; InterfaceGuid=(ConvertTo-Dot1xGuid $InterfaceGuid); Name=$Name
        ConfigurationSource=$ConfigurationSource; OneXEnabled=$oneX
        AuthMode=(Read-NodeText '//*[local-name()="authMode"]')
        Authentication=(Read-NodeText '//*[local-name()="authentication"]')
        Encryption=(Read-NodeText '//*[local-name()="encryption"]')
        EapTypes=$eap; EapMethods=$methods; ServerValidationEnabled=$validation
        ServerValidationScope='Aggregate of explicit settings in EapHost Config. False means at least one method disables validation; it is not an effective setting for every method.'
        ServerNames=@($doc.SelectNodes('//*[local-name()="ServerNames"]') | ForEach-Object { $_.InnerText.Substring(0,[Math]::Min(1024,$_.InnerText.Length)) })
        TrustedRootThumbprints=@($doc.SelectNodes('//*[local-name()="TrustedRootCA" or local-name()="TrustedRootCAHash" or local-name()="TrustedRootCAHashes"]') | ForEach-Object { $_.InnerText })
        DisableUserPromptForServerValidation=(Read-Bool (Read-NodeText '//*[local-name()="DisableUserPromptForServerValidation"]'))
        SimpleCertificateSelection=(Read-Bool (Read-NodeText '//*[local-name()="SimpleCertSelection"]'))
        OneXTimers=[pscustomobject]@{ HeldPeriod=(Read-NodeText '//*[local-name()="heldPeriod"]'); AuthPeriod=(Read-NodeText '//*[local-name()="authPeriod"]'); StartPeriod=(Read-NodeText '//*[local-name()="startPeriod"]'); MaxStart=(Read-NodeText '//*[local-name()="maxStart"]'); MaxAuthFailures=(Read-NodeText '//*[local-name()="maxAuthFailures"]'); BlockPeriod=(Read-NodeText '//*[local-name()="blockPeriod"]') }
        InnerAuthenticationMethods=@($doc.SelectNodes('//*[local-name()="InnerAuthentication" or local-name()="Phase2Authentication"]/*') | ForEach-Object { $_.LocalName } | Select-Object -Unique)
        CacheUserData=(Read-Bool (Read-NodeText '//*[local-name()="cacheUserData"]'))
        UseWinLogonCredentials=@($doc.SelectNodes($configPath + '//*[local-name()="UseWinLogonCredentials" and starts-with(namespace-uri(),"http://www.microsoft.com/provisioning/")]') | ForEach-Object { [pscustomobject]@{ Value=(Read-Bool $_.InnerText); Namespace=$_.NamespaceURI } })
        TrustedRootPinSemantics='Configured method-specific root hashes are retained, not matched. TEAP can use SHA-256; do not equate every value with X509Certificate2.Thumbprint or an issuer-selection hash.'
        SingleSignOnType=(Read-NodeText '//*[local-name()="singleSignOn"]/*[local-name()="type"]')
        Limitations=@('Only selected configuration fields are retained. No key material, EAP user data, identities, passwords, or raw XML is emitted. Certificate filters and vendor-specific EAP settings can require policy-owner review.')
    }
}

function Initialize-Dot1xNative {
    if ('Dot1x.Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace Dot1x {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct WlanInterface {
        public Guid Id;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string Description;
        public int State;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct WlanProfile {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string Name;
        public uint Flags;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Ssid {
        public uint Length;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=32)] public byte[] Bytes;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Association {
        public Ssid Ssid; public int BssType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=6)] public byte[] Bssid;
        public int PhyType; public uint PhyIndex; public uint SignalQuality;
        public uint RxRate; public uint TxRate;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Security {
        [MarshalAs(UnmanagedType.Bool)] public bool Enabled;
        [MarshalAs(UnmanagedType.Bool)] public bool OneXEnabled;
        public uint AuthenticationAlgorithm; public uint CipherAlgorithm;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct Connection {
        public int State; public int Mode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string ProfileName;
        public Association Association; public Security Security;
    }
    public class InterfaceData {
        public string InterfaceGuid; public string Description; public string State;
        public string CurrentProfileName; public bool? SecurityEnabled; public bool? OneXEnabled;
        public uint? AuthenticationAlgorithm; public uint? CipherAlgorithm; public uint? SignalQuality;
        public uint ConnectionQueryCode;
    }
    public class ProfileData {
        public string InterfaceGuid; public string Name; public string Xml; public uint Flags;
    }
    public class WlanResult {
        public List<InterfaceData> Interfaces=new List<InterfaceData>();
        public List<ProfileData> Profiles=new List<ProfileData>();
        public List<string> Limitations=new List<string>();
        public bool Truncated;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Usage {
        public uint Count; public IntPtr Identifiers;
    }
    [StructLayout(LayoutKind.Sequential)] public struct UsageMatch {
        public uint Type; public Usage Usage;
    }
    [StructLayout(LayoutKind.Sequential)] public struct ChainParameters {
        public uint Size; public UsageMatch RequestedUsage; public UsageMatch RequestedIssuancePolicy;
        public uint UrlRetrievalTimeout; public uint CheckRevocationFreshnessTime;
        public uint RevocationFreshnessTime; public IntPtr CacheResync;
        public IntPtr StrongSignParameters; public uint StrongSignFlags;
    }
    public class ChainResult {
        public string Assessment; public string TrustErrorMask; public string TrustInformationMask;
        public uint NativeError; public string[] Status;
        public string Flags="CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE | CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY";
        public string Limitation="Cached Windows chain assessment only. AIA and revocation URL retrieval are cache-only. Missing cached issuers or revocation data cause unknown results. No server certificate, RADIUS trust, policy mapping, private-key usability, or live revocation check is tested.";
    }
    public static class Native {
        [DllImport("wlanapi.dll")] static extern uint WlanOpenHandle(uint version, IntPtr reserved, out uint negotiated, out IntPtr handle);
        [DllImport("wlanapi.dll")] static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);
        [DllImport("wlanapi.dll")] static extern uint WlanEnumInterfaces(IntPtr handle, IntPtr reserved, out IntPtr list);
        [DllImport("wlanapi.dll")] static extern uint WlanGetProfileList(IntPtr handle, ref Guid id, IntPtr reserved, out IntPtr list);
        [DllImport("wlanapi.dll", CharSet=CharSet.Unicode)] static extern uint WlanGetProfile(IntPtr handle, ref Guid id, string name, IntPtr reserved, out IntPtr xml, ref uint flags, out uint access);
        [DllImport("wlanapi.dll")] static extern uint WlanQueryInterface(IntPtr handle, ref Guid id, int opcode, IntPtr reserved, out uint size, out IntPtr data, out int opcodeType);
        [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr memory);
        [DllImport("crypt32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool CertGetCertificateChain(IntPtr engine, IntPtr certificate, IntPtr time, IntPtr additionalStore, ref ChainParameters parameters, uint flags, IntPtr reserved, out IntPtr chain);
        [DllImport("crypt32.dll")] static extern void CertFreeCertificateChain(IntPtr chain);
        static string StateName(int state) {
            string[] names={"NotReady","Connected","AdHocNetworkFormed","Disconnecting","Disconnected","Associating","Discovering","Authenticating"};
            return state>=0 && state<names.Length ? names[state] : "Unknown("+state+")";
        }
        public static WlanResult ReadWireless(int maxProfiles, string[] allowedGuids, string requestedProfile) {
            WlanResult result=new WlanResult(); IntPtr handle=IntPtr.Zero; uint version;
            uint rc=WlanOpenHandle(2,IntPtr.Zero,out version,out handle);
            if(rc!=0) { result.Limitations.Add("WlanOpenHandle code="+rc); return result; }
            IntPtr list=IntPtr.Zero;
            try {
                rc=WlanEnumInterfaces(handle,IntPtr.Zero,out list);
                if(rc!=0) { result.Limitations.Add("WlanEnumInterfaces code="+rc); return result; }
                int count=Marshal.ReadInt32(list); int stride=Marshal.SizeOf(typeof(WlanInterface));
                if(count>128) { result.Truncated=true; count=128; }
                for(int i=0;i<count;i++) {
                    WlanInterface wi=(WlanInterface)Marshal.PtrToStructure(IntPtr.Add(list,8+i*stride),typeof(WlanInterface));
                    if(allowedGuids!=null && Array.FindIndex(allowedGuids,delegate(string s){return String.Equals(s,wi.Id.ToString("D"),StringComparison.OrdinalIgnoreCase);})<0) continue;
                    InterfaceData data=new InterfaceData(); data.InterfaceGuid=wi.Id.ToString("D"); data.Description=wi.Description; data.State=StateName(wi.State);
                    if(wi.State==1 || wi.State==2) {
                        IntPtr connection=IntPtr.Zero; uint bytes; int opcodeType;
                        try {
                            rc=WlanQueryInterface(handle,ref wi.Id,7,IntPtr.Zero,out bytes,out connection,out opcodeType);
                            data.ConnectionQueryCode=rc;
                            if(rc==0 && bytes>=Marshal.SizeOf(typeof(Connection))) {
                                Connection c=(Connection)Marshal.PtrToStructure(connection,typeof(Connection));
                                data.CurrentProfileName=c.ProfileName; data.SecurityEnabled=c.Security.Enabled;
                                data.OneXEnabled=c.Security.OneXEnabled; data.AuthenticationAlgorithm=c.Security.AuthenticationAlgorithm;
                                data.CipherAlgorithm=c.Security.CipherAlgorithm; data.SignalQuality=c.Association.SignalQuality;
                            } else if(rc!=0) { result.Limitations.Add("WlanQueryInterface code="+rc+"; permission or disconnected state can limit visibility. Windows 11 location permission can affect this API."); }
                        } finally { if(connection!=IntPtr.Zero) WlanFreeMemory(connection); }
                    }
                    result.Interfaces.Add(data);
                    IntPtr profiles=IntPtr.Zero;
                    try {
                        rc=WlanGetProfileList(handle,ref wi.Id,IntPtr.Zero,out profiles);
                        if(rc!=0) { result.Limitations.Add("WlanGetProfileList code="+rc); continue; }
                        int pc=Marshal.ReadInt32(profiles); int ps=Marshal.SizeOf(typeof(WlanProfile));
                        for(int p=0;p<pc;p++) {
                            if(p>=128) { result.Truncated=true; break; }
                            WlanProfile wp=(WlanProfile)Marshal.PtrToStructure(IntPtr.Add(profiles,8+p*ps),typeof(WlanProfile));
                            if(!String.IsNullOrEmpty(requestedProfile) && !String.Equals(wp.Name,requestedProfile,StringComparison.OrdinalIgnoreCase)) continue;
                            if(result.Profiles.Count>=maxProfiles) { result.Truncated=true; break; }
                            IntPtr xml=IntPtr.Zero; uint flags=0; uint access;
                            try {
                                // Flags are zero: never request WLAN_PROFILE_GET_PLAINTEXT_KEY.
                                rc=WlanGetProfile(handle,ref wi.Id,wp.Name,IntPtr.Zero,out xml,ref flags,out access);
                                if(rc!=0) { result.Limitations.Add("WlanGetProfile code="+rc); continue; }
                                ProfileData pd=new ProfileData(); pd.InterfaceGuid=wi.Id.ToString("D"); pd.Name=wp.Name; pd.Flags=wp.Flags; pd.Xml=Marshal.PtrToStringUni(xml);
                                result.Profiles.Add(pd);
                            } finally { if(xml!=IntPtr.Zero) WlanFreeMemory(xml); }
                        }
                    } finally { if(profiles!=IntPtr.Zero) WlanFreeMemory(profiles); }
                }
            } finally { if(list!=IntPtr.Zero) WlanFreeMemory(list); WlanCloseHandle(handle,IntPtr.Zero); }
            return result;
        }
        public static ChainResult ReadChain(IntPtr certificate, bool machineStore) {
            ChainResult result=new ChainResult(); ChainParameters p=new ChainParameters();
            p.Size=(uint)Marshal.SizeOf(typeof(ChainParameters)); p.UrlRetrievalTimeout=1;
            IntPtr chain=IntPtr.Zero;
            try {
                // Both issuer URL retrieval and revocation retrieval are cache-only.
                bool ok=CertGetCertificateChain(machineStore ? new IntPtr(1) : IntPtr.Zero, certificate,IntPtr.Zero,IntPtr.Zero,ref p,0xC0000104U,IntPtr.Zero,out chain);
                if(!ok || chain==IntPtr.Zero) { result.Assessment="Unavailable"; result.NativeError=(uint)Marshal.GetLastWin32Error(); result.Status=new string[]{"Native chain API failed"}; return result; }
                uint errors=unchecked((uint)Marshal.ReadInt32(chain,4)); uint info=unchecked((uint)Marshal.ReadInt32(chain,8));
                result.TrustErrorMask="0x"+errors.ToString("X8"); result.TrustInformationMask="0x"+info.ToString("X8");
                List<string> status=new List<string>();
                uint[] bits={1U,2U,4U,8U,16U,32U,64U,128U,256U,512U,1024U,65536U,1048576U,16777216U,33554432U,67108864U};
                string[] names={"NotTimeValid","NotTimeNested","Revoked","InvalidSignature","InvalidUsage","UntrustedRoot","RevocationStatusUnknown","Cyclic","InvalidExtension","InvalidPolicy","InvalidBasicConstraints","PartialChain","WeakSignature","OfflineRevocation","NoIssuanceChainPolicy","ExplicitDistrust"};
                for(int i=0;i<bits.Length;i++) if((errors & bits[i])!=0) status.Add(names[i]);
                result.Status=status.ToArray();
                result.Assessment=errors==0 ? "NoErrorsInCachedAssessment" : ((errors & ~0x01000040U)==0 ? "RevocationUnknownOffline" : "CachedChainErrors");
                return result;
            } finally { if(chain!=IntPtr.Zero) CertFreeCertificateChain(chain); }
        }
    }
}
'@ -ErrorAction Stop
}

function Invoke-Dot1xWorker {
    param([string]$Name, $Context)
    $limits = New-Object 'System.Collections.Generic.List[string]'
    $data = [ordered]@{}
    switch ($Name) {
        'Services' {
            $rows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($serviceName in @('WlanSvc','dot3svc','EapHost','Dhcp','Dnscache','NlaSvc')) {
                try {
                    $s = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -OperationTimeoutSec 5 -ErrorAction Stop
                    if ($null -ne $s) { $rows.Add([pscustomobject]@{ Name=$s.Name; Status=$s.State; StartMode=$s.StartMode; ExitCode=$s.ExitCode }) }
                    else { $limits.Add("Service $serviceName is not installed.") }
                } catch { $limits.Add("Service $serviceName unavailable: $($_.Exception.GetType().Name).") }
            }
            $data.Services = $rows.ToArray()
        }
        'Interfaces' {
            $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object -First 128)
            if ($Context.InterfaceAlias) { $adapters = @($adapters | Where-Object { $_.Name -eq $Context.InterfaceAlias }) }
            $data.Interfaces = @($adapters | ForEach-Object {
                [pscustomobject]@{
                    InterfaceIndex=$_.ifIndex; InterfaceGuid=(ConvertTo-Dot1xGuid $_.InterfaceGuid)
                    Alias=$_.Name; Description=$_.InterfaceDescription; Status=[string]$_.Status
                    MediaType=[string]$_.MediaType; PhysicalMediaType=[string]$_.PhysicalMediaType
                    HardwareInterface=$_.HardwareInterface; Virtual=$_.Virtual; LinkSpeed=[string]$_.LinkSpeed
                    DriverProvider=$_.DriverProvider; DriverVersion=$_.DriverVersionString
                    DriverDate=[string]$_.DriverDate
                }
            })
            if ($Context.InterfaceAlias -and $adapters.Count -eq 0) { $limits.Add('The requested interface alias was not found; no interface scope was inferred.') }
            $ipRows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($a in $adapters) {
                try {
                    $addresses = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -ErrorAction Stop)
                    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ErrorAction Stop)
                    $routes = @(Get-NetRoute -InterfaceIndex $a.ifIndex -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } | Select-Object -First 32)
                    $ipRows.Add([pscustomobject]@{
                        InterfaceIndex=$a.ifIndex
                        IPv4Addresses=@($addresses | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -First 32 | ForEach-Object { [pscustomobject]@{ IPAddress=$_.IPAddress; PrefixLength=$_.PrefixLength; AddressState=[string]$_.AddressState; PrefixOrigin=[string]$_.PrefixOrigin } })
                        IPv6Addresses=@($addresses | Where-Object { $_.AddressFamily -eq 'IPv6' } | Select-Object -First 32 | ForEach-Object { [pscustomobject]@{ IPAddress=$_.IPAddress; PrefixLength=$_.PrefixLength; AddressState=[string]$_.AddressState; PrefixOrigin=[string]$_.PrefixOrigin } })
                        IPv4DefaultGateway=@($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | ForEach-Object { $_.NextHop })
                        IPv6DefaultGateway=@($routes | Where-Object { $_.DestinationPrefix -eq '::/0' } | ForEach-Object { $_.NextHop })
                        DnsServers=@($dns | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique -First 32)
                    })
                } catch { $limits.Add("IP configuration for interface index $($a.ifIndex) is incomplete: $($_.Exception.GetType().Name).") }
            }
            $data.IpConfiguration = $ipRows.ToArray()
        }
        'Wireless' {
            Initialize-Dot1xNative
            $allowed = $null
            if ($Context.InterfaceAlias) { $allowed = [string[]]@($Context.AllowedGuids) }
            $native = [Dot1x.Native]::ReadWireless([int]$Context.MaxProfiles,$allowed,[string]$Context.ProfileName)
            $data.Wireless = @($native.Interfaces)
            $rows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($p in $native.Profiles) {
                try {
                    $origin = 'Local or MDM; ownership not distinguished'
                    if (($p.Flags -band 1) -ne 0) { $origin = 'GroupPolicy' }
                    elseif (($p.Flags -band 2) -ne 0) { $origin = 'CurrentUser' }
                    $rows.Add((ConvertFrom-Dot1xProfileXml -XmlText $p.Xml -Kind Wireless -InterfaceGuid $p.InterfaceGuid -Name $p.Name -ConfigurationSource $origin))
                } catch { $limits.Add("A wireless profile could not be summarized: $($_.Exception.GetType().Name).") }
            }
            $data.Profiles = $rows.ToArray()
            foreach ($l in $native.Limitations) { $limits.Add($l) }
            if ($native.Truncated) { $limits.Add('Wireless interfaces or profiles reached a configured bound; collection is incomplete.') }
        }
        'CertificatesCurrentUser' { $data = Get-Dot1xCertificates -StoreName CurrentUser -MaxCount $Context.MaxCertificatesPerStore -Limitations $limits }
        'CertificatesLocalMachine' { $data = Get-Dot1xCertificates -StoreName LocalMachine -MaxCount $Context.MaxCertificatesPerStore -Limitations $limits }
        'Events' { $data = Get-Dot1xEvents -Context $Context -Limitations $limits }
        'Wired' { $data = Get-Dot1xWired -Context $Context -Limitations $limits }
        default { throw 'Unknown worker name.' }
    }
    $status = 'Succeeded'
    if ($limits.Count -gt 0) { $status = 'Partial' }
    [pscustomobject]@{ Status=$status; Data=$data; Limitations=$limits.ToArray() }
}

function Get-Dot1xCertificates {
    param([string]$StoreName, [int]$MaxCount, [System.Collections.Generic.List[string]]$Limitations)
    Initialize-Dot1xNative
    $location = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreName
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My',$location)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $truncated = $false
    $status = 'Succeeded'
    try {
        $flags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
        $store.Open($flags)
        $certs = @($store.Certificates)
        $truncated = $certs.Count -gt $MaxCount
        foreach ($cert in @($certs | Sort-Object NotAfter -Descending | Select-Object -First $MaxCount)) {
            try {
                $ekus = @()
                foreach ($extension in $cert.Extensions) {
                    if ($extension.Oid.Value -eq '2.5.29.37') {
                        $decoded = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($extension,$extension.Critical)
                        $ekus = @($decoded.EnhancedKeyUsages | ForEach-Object { $_.Value })
                    }
                }
                $chain = [Dot1x.Native]::ReadChain($cert.Handle,($StoreName -eq 'LocalMachine'))
                $rows.Add([pscustomobject]@{
                    Store=$StoreName; Thumbprint=$cert.Thumbprint
                    NotBeforeUtc=$cert.NotBefore.ToUniversalTime().ToString('o'); NotAfterUtc=$cert.NotAfter.ToUniversalTime().ToString('o')
                    EkuOids=$ekus; HasPrivateKey=$cert.HasPrivateKey
                    ClientAuthEkuEligible=($ekus.Count -eq 0 -or $ekus -contains '1.3.6.1.5.5.7.3.2' -or $ekus -contains '2.5.29.37.0')
                    Chain=$chain
                    Limitations=@('Subjects, SANs, and raw certificates are omitted. HasPrivateKey is metadata, not an access or signing test. Profile filters, strong mapping, and server trust are not evaluated.')
                })
            } catch { $status = 'Partial'; $Limitations.Add("A certificate in $StoreName could not be assessed: $($_.Exception.GetType().Name).") }
        }
        if ($truncated) { $Limitations.Add("$StoreName personal store exceeded the certificate bound; newest-expiring certificates were selected.") }
    } catch { $status = 'Failed'; $Limitations.Add("$StoreName personal store is unavailable: $($_.Exception.GetType().Name).") }
    finally { $store.Close() }
    [ordered]@{ Certificates=$rows.ToArray(); CertificateStores=@([pscustomobject]@{ Store=$StoreName; Status=$status; Truncated=$truncated; CollectedCount=$rows.Count }) }
}



function Initialize-Dot1xResources {
    if ('Dot1x.Resources' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Dot1x {
    [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential)] internal struct StartupInfo {
        public int Size; public IntPtr Reserved, Desktop, Title;
        public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;
        public ushort Show,ReservedBytes; public IntPtr ReservedData,StdIn,StdOut,StdErr;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct StartupInfoEx { public StartupInfo Startup; public IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] internal struct ProcessInformation { public IntPtr Process,Thread; public uint ProcessId,ThreadId; }
    [StructLayout(LayoutKind.Sequential)] internal struct BasicJobLimits {
        public long ProcessTime,JobTime; public uint Flags; public UIntPtr MinimumWorkingSet,MaximumWorkingSet;
        public uint ActiveProcessLimit; public UIntPtr Affinity; public uint Priority,Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct IoCounters { public ulong ReadOperations,WriteOperations,OtherOperations,ReadBytes,WriteBytes,OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] internal struct ExtendedJobLimits { public BasicJobLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory; }
    [StructLayout(LayoutKind.Sequential)] internal struct BasicJobAccounting { public long UserTime,KernelTime,PeriodUserTime,PeriodKernelTime; public uint PageFaults,TotalProcesses,ActiveProcesses,TerminatedProcesses; }
    [StructLayout(LayoutKind.Sequential)] internal struct AttributeTag { public uint Attributes,Tag; }
    [StructLayout(LayoutKind.Sequential)] internal struct Disposition { [MarshalAs(UnmanagedType.Bool)] public bool Delete; }
    internal static class ResourceApi {
        [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] internal static extern IntPtr CreateJobObjectW(IntPtr security,string name);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool SetInformationJobObject(IntPtr job,int info,ref ExtendedJobLimits limits,uint size);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryInformationJobObject(IntPtr job,int info,out BasicJobAccounting accounting,uint size,IntPtr returned);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool TerminateJobObject(IntPtr job,uint exit);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool TerminateProcess(IntPtr process,uint exit);
        [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool GetExitCodeProcess(IntPtr process,out uint exit);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SecurityAttributes security,uint size);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool InitializeProcThreadAttributeList(IntPtr attributes,int count,uint flags,ref IntPtr bytes);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool UpdateProcThreadAttribute(IntPtr attributes,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
        [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(IntPtr attributes);
        [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool CreateProcessW(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint flags,IntPtr environment,string cwd,ref StartupInfoEx startup,out ProcessInformation process);
        [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] internal static extern IntPtr CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="CreateFileW")] internal static extern IntPtr CreateInheritedFile(string name,uint access,uint share,ref SecurityAttributes security,uint disposition,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool CreateDirectoryW(string name,ref SecurityAttributes security);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool GetFileInformationByHandleEx(IntPtr file,int info,out AttributeTag tag,uint size);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool SetFileInformationByHandle(IntPtr file,int info,ref Disposition disposition,uint size);
        internal static void Check(bool ok,string operation) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error(),operation+" failed"); }
        internal static bool Valid(IntPtr h) { return h!=IntPtr.Zero && h!=new IntPtr(-1); }
        internal static void Close(ref IntPtr h) { if(Valid(h)) CloseHandle(h); h=IntPtr.Zero; }
    }
    public sealed class PrivateDirectoryLease : IDisposable {
        public string Path { get; private set; }
        readonly List<IntPtr> handles=new List<IntPtr>();
        bool disposed;
        internal PrivateDirectoryLease(string path,byte[] descriptor,bool createParents) {
            string full=System.IO.Path.GetFullPath(path);
            string root=System.IO.Path.GetPathRoot(full);
            char[] separators={System.IO.Path.DirectorySeparatorChar,System.IO.Path.AltDirectorySeparatorChar};
            Path=full.TrimEnd(separators);
            if(String.Equals(Path,root.TrimEnd(separators),StringComparison.OrdinalIgnoreCase)) throw new IOException("A private directory cannot replace a filesystem root.");
            string parent=System.IO.Path.GetDirectoryName(Path);
            if(String.IsNullOrEmpty(parent)) throw new IOException("A private directory cannot replace a filesystem root.");
            List<string> ancestors=new List<string>();
            for(DirectoryInfo d=new DirectoryInfo(parent);d!=null;d=d.Parent) ancestors.Add(d.FullName);
            ancestors.Reverse();
            try {
                GCHandle pinned=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
                try {
                    SecurityAttributes sa=new SecurityAttributes(); sa.Length=Marshal.SizeOf(typeof(SecurityAttributes)); sa.Descriptor=pinned.AddrOfPinnedObject();
                    foreach(string ancestor in ancestors) {
                        try { handles.Add(OpenDirectory(ancestor,false)); }
                        catch(Win32Exception e) {
                            if(!createParents || (e.NativeErrorCode!=2 && e.NativeErrorCode!=3) ||
                               String.Equals(ancestor.TrimEnd(separators),root.TrimEnd(separators),StringComparison.OrdinalIgnoreCase)) throw;
                            // Only reports may create missing parents. Existing directories keep their ACLs.
                            if(!ResourceApi.CreateDirectoryW(ancestor,ref sa)) {
                                int error=Marshal.GetLastWin32Error();
                                if(error!=183) throw new Win32Exception(error,"Private report parent creation failed");
                            }
                            // A concurrent creator may have won; validate and hold that path as usual.
                            handles.Add(OpenDirectory(ancestor,false));
                        }
                    }
                    // CreateDirectory fails if the leaf exists; no existing ACL is changed.
                    ResourceApi.Check(ResourceApi.CreateDirectoryW(Path,ref sa),"Exclusive private directory creation");
                } finally { pinned.Free(); }
                handles.Add(OpenDirectory(Path,true));
            } catch { Dispose(); throw; }
        }
        static IntPtr OpenDirectory(string path,bool leaf) {
            // Holding every ancestor without write/delete sharing prevents path replacement.
            IntPtr h=ResourceApi.CreateFileW(path,leaf ? 0x00030080U : 0x00020080U,1,IntPtr.Zero,3,0x02200000U,IntPtr.Zero);
            if(!ResourceApi.Valid(h)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Private directory path lease failed");
            try {
                AttributeTag tag;
                ResourceApi.Check(ResourceApi.GetFileInformationByHandleEx(h,9,out tag,8),"Directory attributes");
                if((tag.Attributes & 0x10U)==0 || (tag.Attributes & 0x400U)!=0) throw new IOException("A private directory path contains a non-directory or reparse point.");
                return h;
            } catch { ResourceApi.Close(ref h); throw; }
        }
        public void RemoveProfileFiles() {
            if(disposed) throw new ObjectDisposedException("PrivateDirectoryLease");
            int count=0;
            foreach(string file in Directory.EnumerateFiles(Path,"*.xml",SearchOption.TopDirectoryOnly)) {
                if(++count>1024) throw new IOException("Private profile cleanup bound exceeded.");
                File.Delete(file);
            }
        }
        public void DeleteEmptyDirectory() {
            if(disposed || handles.Count==0) throw new ObjectDisposedException("PrivateDirectoryLease");
            Disposition disposition=new Disposition(); disposition.Delete=true;
            // Delete the exact owned directory by handle, not a potentially replaced path.
            ResourceApi.Check(ResourceApi.SetFileInformationByHandle(handles[handles.Count-1],4,ref disposition,4),"Owned temporary directory cleanup");
        }
        ~PrivateDirectoryLease() { Dispose(); }
        public void Dispose() {
            if(disposed) return;
            for(int i=handles.Count-1;i>=0;i--) { IntPtr h=handles[i]; ResourceApi.Close(ref h); }
            handles.Clear(); disposed=true; GC.SuppressFinalize(this);
        }
    }
    public sealed class ProcessCapture {
        public string Status="Failed",StdOut="",StdErr="";
        public int? ExitCode,ProcessId,ErrorCode;
        public long DurationMs;
        public bool OutputTruncated,CleanupConfirmed;
        public int? CleanupErrorCode;
    }
    public static class Resources {
        public static PrivateDirectoryLease CreatePrivateDirectory(string path,byte[] descriptor,bool createParents=false) { return new PrivateDirectoryLease(path,descriptor,createParents); }
        static bool WaitForEmptyJob(IntPtr job,int milliseconds,ProcessCapture result) {
            Stopwatch wait=Stopwatch.StartNew();
            do {
                BasicJobAccounting accounting;
                if(!ResourceApi.QueryInformationJobObject(job,1,out accounting,(uint)Marshal.SizeOf(typeof(BasicJobAccounting)),IntPtr.Zero)) {
                    result.CleanupErrorCode=Marshal.GetLastWin32Error(); return false;
                }
                if(accounting.ActiveProcesses==0) return true;
                Thread.Sleep(10);
            } while(wait.ElapsedMilliseconds<milliseconds);
            result.CleanupErrorCode=258; return false;
        }
        static void Pipe(out IntPtr read,out IntPtr write,ref SecurityAttributes sa) {
            ResourceApi.Check(ResourceApi.CreatePipe(out read,out write,ref sa,4096),"Anonymous pipe creation");
            ResourceApi.Check(ResourceApi.SetHandleInformation(read,1,0),"Pipe inheritance control");
        }
        static StreamReader Reader(ref IntPtr raw) {
            SafeFileHandle handle=new SafeFileHandle(raw,true);
            raw=IntPtr.Zero; // Ownership transfers before any further fallible constructor.
            FileStream stream=null;
            try {
                stream=new FileStream(handle,FileAccess.Read,4096,false);
                return new StreamReader(stream,new UTF8Encoding(false,false),true,4096);
            } catch {
                if(stream!=null) stream.Dispose(); else handle.Dispose();
                throw;
            }
        }
        static bool Drain(StreamReader reader,char[] buffer,ref Task<int> task,ref bool ended,StringBuilder output,int limit,ProcessCapture result) {
            if(ended || !task.IsCompleted) return false;
            int count=task.GetAwaiter().GetResult();
            if(count==0) { ended=true; return true; }
            int keep=Math.Min(count,Math.Max(0,limit-output.Length));
            if(keep>0) output.Append(buffer,0,keep);
            if(keep<count) result.OutputTruncated=true;
            // Continue draining after the cap without retaining discarded text.
            task=reader.ReadAsync(buffer,0,buffer.Length);
            return true;
        }
        public static ProcessCapture Run(string application,string commandLine,int timeoutMs,int outputLimit) {
            ProcessCapture result=new ProcessCapture(); Stopwatch clock=Stopwatch.StartNew();
            IntPtr job=IntPtr.Zero,outRead=IntPtr.Zero,outWrite=IntPtr.Zero,errRead=IntPtr.Zero,errWrite=IntPtr.Zero,input=IntPtr.Zero,attributes=IntPtr.Zero,handleList=IntPtr.Zero;
            ProcessInformation pi=new ProcessInformation(); bool attributesReady=false,assigned=false;
            StreamReader stdout=null,stderr=null;
            StringBuilder output=new StringBuilder(Math.Min(4096,outputLimit)),error=new StringBuilder(4096);
            try {
                job=ResourceApi.CreateJobObjectW(IntPtr.Zero,null);
                if(!ResourceApi.Valid(job)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Owned job creation failed");
                ExtendedJobLimits limits=new ExtendedJobLimits(); limits.Basic.Flags=0x2000U;
                ResourceApi.Check(ResourceApi.SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(ExtendedJobLimits))),"Kill-on-close job policy");
                SecurityAttributes sa=new SecurityAttributes(); sa.Length=Marshal.SizeOf(typeof(SecurityAttributes)); sa.Inherit=1;
                Pipe(out outRead,out outWrite,ref sa); Pipe(out errRead,out errWrite,ref sa);
                input=ResourceApi.CreateInheritedFile("NUL",0x80000000U,3,ref sa,3,0,IntPtr.Zero);
                if(!ResourceApi.Valid(input)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Null stdin creation failed");
                IntPtr size=IntPtr.Zero; ResourceApi.InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);
                if(size.ToInt64()<=0 || size.ToInt64()>65536) throw new IOException("Invalid process attribute size.");
                attributes=Marshal.AllocHGlobal(size);
                ResourceApi.Check(ResourceApi.InitializeProcThreadAttributeList(attributes,1,0,ref size),"Process attribute initialization"); attributesReady=true;
                handleList=Marshal.AllocHGlobal(3*IntPtr.Size);
                Marshal.WriteIntPtr(handleList,0,input); Marshal.WriteIntPtr(handleList,IntPtr.Size,outWrite); Marshal.WriteIntPtr(handleList,2*IntPtr.Size,errWrite);
                ResourceApi.Check(ResourceApi.UpdateProcThreadAttribute(attributes,0,new IntPtr(0x20002),handleList,new IntPtr(3*IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"Explicit inherited handle list");
                StartupInfoEx si=new StartupInfoEx(); si.Startup.Size=Marshal.SizeOf(typeof(StartupInfoEx)); si.Startup.Flags=0x100U;
                si.Startup.StdIn=input; si.Startup.StdOut=outWrite; si.Startup.StdErr=errWrite; si.Attributes=attributes;
                // Suspend before job assignment so no descendant can start outside our job.
                ResourceApi.Check(ResourceApi.CreateProcessW(application,new StringBuilder(commandLine),IntPtr.Zero,IntPtr.Zero,true,0x08080004U,IntPtr.Zero,null,ref si,out pi),"Suspended process creation");
                result.ProcessId=unchecked((int)pi.ProcessId);
                ResourceApi.Check(ResourceApi.AssignProcessToJobObject(job,pi.Process),"Owned job assignment"); assigned=true;
                if(ResourceApi.ResumeThread(pi.Thread)==0xFFFFFFFFU) throw new Win32Exception(Marshal.GetLastWin32Error(),"Process resume failed");
                ResourceApi.Close(ref pi.Thread); ResourceApi.Close(ref outWrite); ResourceApi.Close(ref errWrite); ResourceApi.Close(ref input);
                stdout=Reader(ref outRead);
                stderr=Reader(ref errRead);
                char[] outBuffer=new char[4096],errBuffer=new char[4096];
                Task<int> outTask=stdout.ReadAsync(outBuffer,0,outBuffer.Length),errTask=stderr.ReadAsync(errBuffer,0,errBuffer.Length);
                bool outEnded=false,errEnded=false,mainEnded=false; long drainDeadline=0;
                for(;;) {
                    bool progress=Drain(stdout,outBuffer,ref outTask,ref outEnded,output,outputLimit,result);
                    progress=Drain(stderr,errBuffer,ref errTask,ref errEnded,error,16384,result) || progress;
                    if(!mainEnded && ResourceApi.WaitForSingleObject(pi.Process,0)==0) {
                        uint exit; ResourceApi.Check(ResourceApi.GetExitCodeProcess(pi.Process,out exit),"Native exit code");
                        result.ExitCode=unchecked((int)exit); result.Status=exit==0 ? "Succeeded" : "Failed";
                        mainEnded=true; ResourceApi.Check(ResourceApi.TerminateJobObject(job,0),"Remaining owned child cleanup"); drainDeadline=clock.ElapsedMilliseconds+2000;
                    }
                    if(!mainEnded && clock.ElapsedMilliseconds>=timeoutMs) {
                        result.Status="TimedOut"; mainEnded=true;
                        ResourceApi.Check(ResourceApi.TerminateJobObject(job,1),"Owned job timeout cleanup");
                        ResourceApi.WaitForSingleObject(pi.Process,2000); drainDeadline=clock.ElapsedMilliseconds+2000;
                    }
                    if(mainEnded && outEnded && errEnded) break;
                    if(mainEnded && clock.ElapsedMilliseconds>=drainDeadline) { result.OutputTruncated=true; break; }
                    if(!progress) Thread.Sleep(5);
                }
            } catch(Win32Exception e) { result.ErrorCode=e.NativeErrorCode; if(result.Status!="TimedOut") result.Status="Failed"; }
              catch(Exception e) { result.ErrorCode=e.HResult; if(result.Status!="TimedOut") result.Status="Failed"; }
            finally {
                if(ResourceApi.Valid(pi.Process)) {
                    if(assigned) {
                        ResourceApi.TerminateJobObject(job,1);
                        result.CleanupConfirmed=WaitForEmptyJob(job,2000,result);
                    } else {
                        // An unassigned child has never been resumed and cannot have descendants.
                        ResourceApi.TerminateProcess(pi.Process,1);
                        result.CleanupConfirmed=ResourceApi.WaitForSingleObject(pi.Process,2000)==0;
                        if(!result.CleanupConfirmed) result.CleanupErrorCode=258;
                    }
                } else { result.CleanupConfirmed=true; }
                // Retain the job through the empty-job check; close is a final kill request.
                ResourceApi.Close(ref job); ResourceApi.Close(ref pi.Thread); ResourceApi.Close(ref pi.Process);
                ResourceApi.Close(ref outWrite); ResourceApi.Close(ref errWrite); ResourceApi.Close(ref input);
                if(stdout!=null) stdout.Dispose(); if(stderr!=null) stderr.Dispose();
                ResourceApi.Close(ref outRead); ResourceApi.Close(ref errRead);
                if(attributesReady) ResourceApi.DeleteProcThreadAttributeList(attributes);
                if(attributes!=IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                if(handleList!=IntPtr.Zero) Marshal.FreeHGlobal(handleList);
                clock.Stop(); result.DurationMs=clock.ElapsedMilliseconds;
            }
            result.StdOut=output.ToString(); result.StdErr=error.ToString(); return result;
        }
    }
}
'@ -ErrorAction Stop
}

function New-Dot1xPrivateDirectory {
    param([string]$Path, [switch]$CreateParents)
    Initialize-Dot1xResources
    if (-not $Path) { $Path = [IO.Path]::Combine([IO.Path]::GetTempPath(),('dot1x-' + [guid]::NewGuid().ToString('N'))) }
    [System.Management.Automation.ProviderInfo]$provider = $null
    [System.Management.Automation.PSDriveInfo]$drive = $null
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem') { throw 'A report or temporary directory must use the FileSystem provider.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { $sid = $identity.User } finally { $identity.Dispose() }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true,$false); $security.SetOwner($sid)
    $sids = @($sid.Value,'S-1-5-18','S-1-5-32-544' | Select-Object -Unique)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($value in $sids) {
        $principal = New-Object Security.Principal.SecurityIdentifier($value)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    $lease = [Dot1x.Resources]::CreatePrivateDirectory($fullPath,$security.GetSecurityDescriptorBinaryForm(),[bool]$CreateParents)
    try {
        $actual = (New-Object IO.DirectoryInfo($fullPath)).GetAccessControl([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner)
        $rules = @($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if (-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or $rules.Count -ne $sids.Count) { throw 'Private directory ownership or DACL could not be verified.' }
        foreach ($rule in $rules) {
            if ($sids -notcontains $rule.IdentityReference.Value -or $rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'Private directory access could not be verified.' }
        }
        if (@([IO.Directory]::EnumerateFileSystemEntries($fullPath) | Select-Object -First 1).Count -gt 0) { throw 'The newly created private directory is not empty.' }
        return $lease
    } catch {
        try { $lease.DeleteEmptyDirectory() } catch { }
        $lease.Dispose(); throw
    }
}

function Remove-Dot1xPrivateDirectory {
    param($Lease, [System.Collections.Generic.List[string]]$Limitations)
    if ($null -eq $Lease) { return }
    try { $Lease.RemoveProfileFiles(); $Lease.DeleteEmptyDirectory() }
    catch { $Limitations.Add("Private wired transport cleanup is incomplete at $($Lease.Path). Treat remaining files as sensitive; remove them after diagnostic processes have ended. Error=$($_.Exception.GetType().Name).") }
    finally { $Lease.Dispose() }
}

function Get-Dot1xWired {
    param($Context, [System.Collections.Generic.List[string]]$Limitations)
    if (-not $Context.WiredTempDirectory -or -not [IO.Directory]::Exists($Context.WiredTempDirectory)) { throw 'The parent did not prepare private wired transport.' }
    $interfaces = New-Object 'System.Collections.Generic.List[object]'
    $profiles = New-Object 'System.Collections.Generic.List[object]'
    $targets = @($Context.WiredInterfaces)
    if ($targets.Count -eq 0) { $Limitations.Add('No eligible Ethernet interface metadata was available; bounded per-interface wired export was not attempted.') }
    if ($targets.Count -gt [int]$Context.MaxProfiles) { $Limitations.Add('Wired interface/profile count exceeds the configured bound; collection is incomplete.') }
    foreach ($target in @($targets | Select-Object -First $Context.MaxProfiles)) {
        $status = 'Failed'; $exitCode = $null; $exportedCount = 0; $resetSucceeded = $true; $exporterCleanupConfirmed = $true
        try {
            $exporterCleanupConfirmed = $false
            $native = Invoke-Dot1xProcess -FilePath ([IO.Path]::Combine($env:SystemRoot,'System32\netsh.exe')) `
                -ArgumentList @('lan','export','profile',('folder=' + $Context.WiredTempDirectory),('interface=' + $target.Alias)) -TimeoutSeconds 8 -OutputLimitChars 65536
            $status = $native.Status; $exitCode = $native.ExitCode
            $exporterCleanupConfirmed = $native.CleanupConfirmed -eq $true
            if (-not $exporterCleanupConfirmed) { $status = 'CleanupUnconfirmed'; throw 'Exporter writer cleanup was not confirmed; defer all XML handling to the parent.' }
            if ($status -ne 'Succeeded') { $Limitations.Add("Wired profile export for interface index $($target.InterfaceIndex): $status, exit=$exitCode. No localized command output is interpreted or published.") }
            $xmlFiles = @([IO.Directory]::EnumerateFiles($Context.WiredTempDirectory,'*.xml') | Select-Object -First ([int]$Context.MaxProfiles + 1))
            $exportedCount = $xmlFiles.Count
            if ($status -eq 'Succeeded' -and $exportedCount -eq 0) {
                $status = 'NoExportedProfile'
                $Limitations.Add("Wired export completed without a profile file for interface index $($target.InterfaceIndex). This is distinct from failed export, but is not proof that no policy exists; service state and provider behavior can limit visibility.")
            }
            foreach ($path in $xmlFiles) {
                if ($profiles.Count -ge [int]$Context.MaxProfiles) { $Limitations.Add('The wired profile bound was reached; additional exports were not retained.'); break }
                $file = New-Object IO.FileInfo($path)
                if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -gt 1048576) { $Limitations.Add('A wired XML export was a reparse point or exceeded 1 MiB; it was not parsed.'); continue }
                try {
                    $profile = ConvertFrom-Dot1xProfileXml -XmlText ([IO.File]::ReadAllText($path)) -Kind Wired -InterfaceGuid $target.InterfaceGuid -ConfigurationSource 'Effective wired profile exported by netsh; GPO/MDM ownership is not distinguished'
                    if (-not $profile.Name) {
                        $profile.Name = $target.Alias
                        $profile | Add-Member -NotePropertyName NameSource -NotePropertyValue 'Interface alias; LANProfile does not provide a profile name'
                    }
                    if (-not $Context.ProfileName -or $profile.Name -eq $Context.ProfileName) { $profiles.Add($profile) }
                } catch { $Limitations.Add("A wired profile could not be summarized: $($_.Exception.GetType().Name). Raw XML is not published.") }
            }
        } catch { $Limitations.Add("Wired profile query failed for interface index $($target.InterfaceIndex): $($_.Exception.GetType().Name).") }
        finally {
            # Do not inspect or reset XML while a nested exporter might still write it.
            if (-not $exporterCleanupConfirmed) {
                $resetSucceeded = $false
                $Limitations.Add('Nested exporter cleanup is unconfirmed. XML was not inspected or reset; the outer parent owns final cleanup after its whole job is empty.')
            } else { try {
                $remainingFiles = @([IO.Directory]::EnumerateFiles($Context.WiredTempDirectory,'*.xml') | Select-Object -First 1025)
                if ($remainingFiles.Count -gt 1024) { $resetSucceeded = $false; $Limitations.Add('The private XML reset bound was exceeded.') }
                foreach ($path in @($remainingFiles | Select-Object -First 1024)) {
                    try { [IO.File]::Delete($path) }
                    catch { $resetSucceeded = $false; $Limitations.Add('A private wired XML file requires parent cleanup.') }
                }
            } catch { $resetSucceeded = $false; $Limitations.Add('Private wired transport could not be reset.') } }
        }
        $interfaces.Add([pscustomobject]@{
            InterfaceGuid=$target.InterfaceGuid; Alias=$target.Alias; State='Unknown'
            ProfileQueryStatus=$status; NativeExitCode=$exitCode; ExportedProfileCount=$exportedCount
            Limitations=@('Profile export does not prove current authorization. No key=clear or EAP user-data export is requested. Raw XML is private temporary transport, not a report artifact.')
        })
        if (-not $resetSucceeded) { $Limitations.Add('Further wired interfaces were not queried because transport reset failed. Prior XML was not attributed to another interface.'); break }
    }
    [ordered]@{ Wired=$interfaces.ToArray(); Profiles=$profiles.ToArray() }
}

function Get-Dot1xEvents {
    param($Context, [System.Collections.Generic.List[string]]$Limitations)
    $logName = [string]$Context.LogName
    $providerName = [string]$Context.ProviderName
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $metadata = [ordered]@{ LogName=$logName; ProviderFilter=$providerName; Available=$false; Enabled=$null; QueryStatus='Unavailable'; EventCount=0; Truncated=$false; ErrorCode=$null }
    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        $metadata.Available = $true; $metadata.Enabled = $log.IsEnabled
        if (-not $log.IsEnabled) { $Limitations.Add("$logName is disabled. Retained history might be incomplete; logging was not enabled.") }
        $filter = @{ LogName=$logName; StartTime=([datetime]$Context.StartTimeUtc).ToLocalTime(); EndTime=([datetime]$Context.EndTimeUtc).ToLocalTime() }
        if ($providerName) { $filter.ProviderName = $providerName }
        $records = @()
        try {
            $records = @(Get-WinEvent -FilterHashtable $filter -MaxEvents ([int]$Context.MaxEventsPerLog + 1) -ErrorAction Stop)
            $metadata.QueryStatus = 'Succeeded'
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $metadata.QueryStatus = 'NoEvents' }
            elseif ($providerName -and (($_.FullyQualifiedErrorId -split ',', 2)[0] -ceq 'LogsAndProvidersDontOverlap')) {
                $metadata.QueryStatus = 'UnsupportedProviderChannel'
                $metadata.ErrorCode = 'LogsAndProvidersDontOverlap'
                $Limitations.Add("Provider '$providerName' does not publish to channel '$logName' on this installation. This unsupported provider/channel pairing is not a no-events result.")
            }
            else { throw }
        }
        $metadata.Truncated = $records.Count -gt [int]$Context.MaxEventsPerLog
        if ($metadata.Truncated) { $Limitations.Add("$logName reached the event bound; only the newest matching events are retained.") }
        $allowedFields = @('InterfaceGuid','InterfaceId','InterfaceName','ProfileName','ConnectionId','ReasonCode','ErrorCode','ResultCode','FailureReasonCode','EapErrorCode','EapReasonCode','EapType','InnerEapType','AuthMode','AuthenticationAlgorithm','AuthenticationType','OneXEnabled','Status','ErrorStatus','PolicyError','CertificateHash','CertHash')
        foreach ($record in @($records | Select-Object -First $Context.MaxEventsPerLog)) {
            try {
                $xml = [string]$record.ToXml()
                if ($xml.Length -gt 1048576) { throw 'Event XML exceeds the parsing bound.' }
                $settings = New-Object System.Xml.XmlReaderSettings
                $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null; $settings.MaxCharactersInDocument = 1048576
                $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($xml)), $settings)
                $doc = New-Object System.Xml.XmlDocument; $doc.XmlResolver = $null
                try { $doc.Load($reader) } finally { $reader.Dispose() }
                $fields = [ordered]@{}
                foreach ($node in @($doc.SelectNodes('//*[local-name()="EventData"]/* | //*[local-name()="UserData"]//*[not(*)]') | Select-Object -First 128)) {
                    $name = $node.GetAttribute('Name')
                    if (-not $name) { $name = $node.LocalName }
                    if ($allowedFields -contains $name) {
                        $value = [string]$node.InnerText
                        $fields[$name] = $value.Substring(0,[Math]::Min(256,$value.Length))
                    }
                }
                $guid = ConvertTo-Dot1xGuid (Get-Dot1xValue $fields 'InterfaceGuid')
                if (-not $guid) { $guid = ConvertTo-Dot1xGuid (Get-Dot1xValue $fields 'InterfaceId') }
                $isAutoConfig = $record.ProviderName -in @('Microsoft-Windows-WLAN-AutoConfig','Microsoft-Windows-Wired-AutoConfig')
                if ($isAutoConfig -and $Context.InterfaceAlias -and @($Context.AllowedGuids) -notcontains $guid) { continue }
                if ($isAutoConfig -and $Context.ProfileName -and (Get-Dot1xValue $fields 'ProfileName') -ne $Context.ProfileName) { continue }
                $message = $null
                if ($Context.IncludeEventMessages) {
                    try { $text = [string]$record.Message; $message = $text.Substring(0,[Math]::Min(2048,$text.Length)) }
                    catch { $Limitations.Add('An event message could not be formatted; structured fields remain available.') }
                }
                $rows.Add([pscustomobject][ordered]@{
                    LogName=$logName; ProviderName=$record.ProviderName; Id=$record.Id; Version=$record.Version; Level=$record.Level
                    TimeCreatedUtc=$record.TimeCreated.ToUniversalTime().ToString('o'); RecordId=$record.RecordId
                    InterfaceGuid=$guid; Fields=$fields; Message=$message
                })
            } catch { $Limitations.Add("An event could not be summarized: $($_.Exception.GetType().Name).") }
            finally { $record.Dispose() }
        }
        $metadata.EventCount = $rows.Count
        if (($Context.InterfaceAlias -or $Context.ProfileName) -and $logName -match 'AutoConfig') { $Limitations.Add('Targeted AutoConfig history excludes records without matching structured interface/profile identifiers. Other providers remain uncorrelated supporting evidence.') }
    } catch {
        $metadata.QueryStatus = 'Unavailable'; $metadata.ErrorCode = $_.Exception.HResult
        $Limitations.Add("$logName is unavailable or inaccessible: $($_.Exception.GetType().Name). Missing logs were not created or enabled.")
    }
    [ordered]@{ Events=$rows.ToArray(); EventLogs=@([pscustomobject]$metadata) }
}

function ConvertTo-Dot1xProcessArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value -notmatch '[\s"]' -and $Value.Length -gt 0) { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-Dot1xProcess {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$FilePath, [string[]]$ArgumentList=@(),
          [ValidateRange(1,120)][int]$TimeoutSeconds=20,
          [ValidateRange(1024,16777216)][int]$OutputLimitChars=8388608)
    Initialize-Dot1xResources
    $commandLine = (ConvertTo-Dot1xProcessArgument $FilePath) + ' ' + (@($ArgumentList | ForEach-Object { ConvertTo-Dot1xProcessArgument $_ }) -join ' ')
    [Dot1x.Resources]::Run($FilePath,$commandLine,$TimeoutSeconds*1000,$OutputLimitChars)
}

function Invoke-Dot1xProbe {
    param([string]$Name, [string]$ScriptPath, $Context, [int]$TimeoutSeconds)
    $lease = $null; $cleanupConfirmed = $true; $cleanupErrorCode = $null
    $cleanupLimits = New-Object 'System.Collections.Generic.List[string]'
    $status = 'Failed'; $data = $null; $limits = @(); $duration = 0; $errorCode = $null
    try {
        $workerContext = [ordered]@{}
        foreach ($key in $Context.Keys) { $workerContext[$key] = $Context[$key] }
        if ($Name -eq 'Wired') { $lease = New-Dot1xPrivateDirectory; $workerContext.WiredTempDirectory = $lease.Path }
        $workerJson = $workerContext | ConvertTo-Json -Depth 8 -Compress
        $encodedContext = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($workerJson))
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $cleanupConfirmed = $false
        $result = Invoke-Dot1xProcess -FilePath $exe -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-File',$ScriptPath,'-WorkerName',$Name,'-WorkerContext',$encodedContext) -TimeoutSeconds $TimeoutSeconds
        $status = $result.Status; $duration = $result.DurationMs; $errorCode = $result.ErrorCode
        $cleanupConfirmed = $result.CleanupConfirmed -eq $true; $cleanupErrorCode = $result.CleanupErrorCode
        if ($status -eq 'Succeeded' -and -not $result.OutputTruncated) {
            try {
                $payload = $result.StdOut | ConvertFrom-Json -ErrorAction Stop
                $status = [string]$payload.Status; $data = $payload.Data; $limits = @($payload.Limitations)
                if ($status -notin @('Succeeded','Partial','Failed')) { throw 'Invalid worker status.' }
            } catch { $status = 'Failed'; $limits = @('The isolated worker returned invalid structured output. No raw process output is retained.') }
        } else {
            $limits = @("Bounded worker status=$status; exit=$($result.ExitCode); error=$($result.ErrorCode). Raw process output is not published.")
            if ($result.OutputTruncated) { $status = 'Failed'; $limits += 'Worker output exceeded its capture bound or did not finish draining.' }
        }
    } catch { $status = 'Failed'; $errorCode = $_.Exception.HResult; $limits += "Probe preparation or execution is unavailable: $($_.Exception.GetType().Name)." }
    finally {
        if ($cleanupConfirmed) {
            Remove-Dot1xPrivateDirectory -Lease $lease -Limitations $cleanupLimits
        } elseif ($null -ne $lease) {
            $cleanupLimits.Add("Owned process cleanup was not confirmed. Sensitive wired transport is retained at $($lease.Path); do not remove it until owned writers have ended. Cleanup error=$cleanupErrorCode.")
            $lease.Dispose()
        }
        if (-not $cleanupConfirmed -and $null -eq $lease) { $cleanupLimits.Add("Owned descendant cleanup was not confirmed; cleanup error=$cleanupErrorCode.") }
    }
    if ($cleanupLimits.Count -gt 0) { $limits += $cleanupLimits.ToArray(); if ($status -eq 'Succeeded') { $status = 'Partial' } }
    [pscustomobject]@{ Name=$Name; Status=$status; DurationMs=$duration; ErrorCode=$errorCode; CleanupConfirmed=$cleanupConfirmed; CleanupErrorCode=$cleanupErrorCode; Limitations=$limits; Data=$data }
}

function Get-Dot1xEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ScriptPath,
          [string]$InterfaceAlias, [string]$ProfileName,
          [int]$LookbackHours=24, [int]$MaxEventsPerLog=250, [int]$ProbeTimeoutSeconds=20,
          [int]$OverallTimeoutSeconds=180, [int]$MaxProfiles=32,
          [int]$MaxCertificatesPerStore=100, [switch]$IncludeEventMessages)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Live collection requires Windows. Use -EvidencePath or the offline rules function elsewhere.' }
    $captured = [datetime]::UtcNow
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { $admin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { $identity.Dispose() }
    $evidence = [ordered]@{
        SchemaVersion=1; CapturedAtUtc=$captured.ToString('o')
        Collection=[ordered]@{
            Mode='Live'; Platform=[Environment]::OSVersion.VersionString; PowerShellVersion=$PSVersionTable.PSVersion.ToString(); IsAdministrator=$admin
            IdentityScope='CurrentUser is the process execution identity, not necessarily the affected interactive user. LocalMachine is this endpoint.'
            InterfaceAlias=$InterfaceAlias; ProfileName=$ProfileName; LookbackHours=$LookbackHours; MaxEventsPerLog=$MaxEventsPerLog
            ProbeTimeoutSeconds=$ProbeTimeoutSeconds; OverallTimeoutSeconds=$OverallTimeoutSeconds
            MaxProfiles=$MaxProfiles; MaxCertificatesPerStore=$MaxCertificatesPerStore; IncludeEventMessages=[bool]$IncludeEventMessages
            Limitations=@('Reports are sensitive. Profile names, server names, certificate identifiers, addresses, and optional event messages can identify an organization or person. There is no universal automatic redaction guarantee.',
                'Collection does not transmit diagnostic network traffic, modify configuration, enable logs, reconnect, renew DHCP, or run remediation. Windows cmdlets and read-only APIs can have ordinary OS bookkeeping effects.',
                'Each worker has a timeout, capped incremental output capture, and an owned job that is terminated before parent cleanup. Collection has an overall scheduling deadline. Local API/compiler startup and shutdown can add time. No remaining workers are launched after the deadline.',
                'Report and wired temporary directories grant access only to the execution identity, SYSTEM, and Administrators. Existing directory ACLs are not changed. The parent removes temporary XML only after the owned job reports no active processes; force-ending the parent or power loss can leave sensitive private files.',
                'Historical logs and current configuration are not a synchronized authentication trace. The local clock, log retention, permissions, and execution identity limit correlation.',
                'No server certificate was observed on the wire. Cached client certificate chains do not verify a RADIUS server chain or current revocation status.')
        }
        Services=@(); Interfaces=@(); IpConfiguration=@(); Wireless=@(); Wired=@(); Profiles=@()
        Certificates=@(); CertificateStores=@(); Events=@(); EventLogs=@(); Probes=@()
    }
    $context = [ordered]@{
        InterfaceAlias=$InterfaceAlias; ProfileName=$ProfileName; MaxProfiles=$MaxProfiles; MaxCertificatesPerStore=$MaxCertificatesPerStore
        MaxEventsPerLog=$MaxEventsPerLog; StartTimeUtc=$captured.AddHours(-$LookbackHours).ToString('o'); EndTimeUtc=$captured.ToString('o')
        IncludeEventMessages=[bool]$IncludeEventMessages; AllowedGuids=@(); WiredInterfaces=@(); LogName=''; ProviderName=''
    }
    $plan = @(
        @{ Name='Interfaces' }, @{ Name='Services' }, @{ Name='Wireless' }, @{ Name='Wired' },
        @{ Name='CertificatesCurrentUser' }, @{ Name='CertificatesLocalMachine' },
        @{ Name='Events'; Log='Microsoft-Windows-WLAN-AutoConfig/Operational'; Provider='' },
        @{ Name='Events'; Log='Microsoft-Windows-Wired-AutoConfig/Operational'; Provider='' },
        @{ Name='Events'; Log='Microsoft-Windows-EapHost/Operational'; Provider='' },
        @{ Name='Events'; Log='System'; Provider='Microsoft-Windows-EapHost' },
        @{ Name='Events'; Log='System'; Provider='Schannel' },
        @{ Name='Events'; Log='Microsoft-Windows-CAPI2/Operational'; Provider='' },
        @{ Name='Events'; Log='Microsoft-Windows-NTLM/Operational'; Provider='Microsoft-Windows-NTLM' }
    )
    $timer = [Diagnostics.Stopwatch]::StartNew()
    foreach ($item in $plan) {
        $remaining = [int][Math]::Floor($OverallTimeoutSeconds - $timer.Elapsed.TotalSeconds)
        $probeLabel = $item.Name
        if ($item.Name -eq 'Events') { $probeLabel = 'Events:' + $item.Log + ':' + $item.Provider; $context.LogName=$item.Log; $context.ProviderName=$item.Provider }
        if ($remaining -lt 1) {
            $evidence.Probes += [pscustomobject]@{ Name=$probeLabel; Status='Skipped'; DurationMs=0; ErrorCode=$null; Limitations=@('Overall collection deadline reached before this probe.') }
            continue
        }
        $probe = Invoke-Dot1xProbe -Name $item.Name -ScriptPath $ScriptPath -Context $context -TimeoutSeconds ([Math]::Min($ProbeTimeoutSeconds,$remaining))
        $evidence.Probes += [pscustomobject]@{ Name=$probeLabel; Status=$probe.Status; DurationMs=$probe.DurationMs; ErrorCode=$probe.ErrorCode; CleanupConfirmed=$probe.CleanupConfirmed; CleanupErrorCode=$probe.CleanupErrorCode; Limitations=@($probe.Limitations) }
        if ($null -ne $probe.Data) {
            foreach ($property in $probe.Data.PSObject.Properties) {
                if ($property.Name -in @('Services','Interfaces','IpConfiguration','Wireless','Wired','Profiles','Certificates','CertificateStores','Events','EventLogs')) {
                    $evidence[$property.Name] += @($property.Value)
                }
            }
        }
        if ($item.Name -eq 'Interfaces') {
            $context.AllowedGuids = @($evidence.Interfaces | ForEach-Object { $_.InterfaceGuid })
            $context.WiredInterfaces = @($evidence.Interfaces | Where-Object {
                $_.PhysicalMediaType -notmatch '802\.11|Wireless' -and ($_.PhysicalMediaType -eq '802.3' -or $_.PhysicalMediaType -eq '14' -or $_.MediaType -eq '802.3')
            } | ForEach-Object { [pscustomobject]@{ InterfaceGuid=$_.InterfaceGuid; InterfaceIndex=$_.InterfaceIndex; Alias=$_.Alias } })
        }
    }
    $timer.Stop(); $evidence.Collection.DurationMs = $timer.ElapsedMilliseconds
    return [pscustomobject]$evidence
}

function Format-Dot1xReport {
    param([Parameter(Mandatory=$true)]$Report)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Windows wired and wireless 802.1X endpoint diagnostics')
    $lines.Add('Sensitive report: review before sharing. Collection is minimized, not universally redacted.')
    $lines.Add('Captured UTC: ' + [string](Get-Dot1xValue $Report 'CapturedAtUtc'))
    $savedDirectory = [string](Get-Dot1xValue $Report 'OutputDirectory')
    if ($savedDirectory) { $lines.Add('Saved reports: ' + $savedDirectory) }
    $lines.Add('No remediation, network probes, or authentication attempts were performed.')
    $lines.Add('This snapshot does not test current authentication or establish RADIUS/NPS decisions.')
    $lines.Add('')
    foreach ($finding in @(Get-Dot1xValue $Report 'Findings' @())) {
        $lines.Add(('[{0}; confidence={1}] {2}: {3}' -f $finding.Severity,$finding.Confidence,$finding.Id,$finding.Summary))
        foreach ($item in @($finding.Evidence)) { $lines.Add('  Evidence: ' + $item) }
        foreach ($item in @($finding.Remediation)) { $lines.Add('  Next step (not executed): ' + $item) }
        foreach ($item in @($finding.Limitations)) { $lines.Add('  Limitation: ' + $item) }
        $lines.Add('')
    }
    $lines.Add('Collection limitations:')
    foreach ($item in @(Get-Dot1xValue (Get-Dot1xValue $Report 'Collection') 'Limitations' @())) { $lines.Add('  ' + $item) }
    foreach ($probe in @(Get-Dot1xValue $Report 'Probes' @())) {
        $lines.Add(('  Probe {0}: {1}, {2} ms' -f $probe.Name,$probe.Status,$probe.DurationMs))
        foreach ($item in @($probe.Limitations)) { $lines.Add('    ' + $item) }
    }
    return ($lines -join [Environment]::NewLine)
}

function Write-Dot1xReport {
    param([Parameter(Mandatory=$true)]$Report, [Parameter(Mandatory=$true)]$Evidence,
          [Parameter(Mandatory=$true)][string]$OutputDirectory)
    $runName = 'Dot1x-Report-' + [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss.fffZ',[Globalization.CultureInfo]::InvariantCulture) + '-' + [guid]::NewGuid().ToString('N')
    $runPath = Join-Path -Path $OutputDirectory -ChildPath $runName -ErrorAction Stop
    $lease = New-Dot1xPrivateDirectory -Path $runPath -CreateParents
    try {
        $Report | Add-Member -NotePropertyName OutputDirectory -NotePropertyValue $lease.Path -Force
        $outputs = [ordered]@{
            'evidence.json'=($Evidence | ConvertTo-Json -Depth 20)
            'report.json'=($Report | ConvertTo-Json -Depth 20)
            'report.txt'=(Format-Dot1xReport -Report $Report)
        }
        foreach ($item in $outputs.GetEnumerator()) { if ($item.Value.Length -gt 16777216) { throw 'A report exceeds the 16 MiB character bound.' } }
        $encoding = New-Object Text.UTF8Encoding($false)
        foreach ($item in $outputs.GetEnumerator()) {
            $path = [IO.Path]::Combine($lease.Path,$item.Key)
            $stream = New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $bytes = $encoding.GetBytes($item.Value); $stream.Write($bytes,0,$bytes.Length) }
            finally { $stream.Dispose() }
        }
        return $lease.Path
    } finally { $lease.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($WorkerName) {
        $ErrorActionPreference = 'Stop'; $WarningPreference = 'SilentlyContinue'; $ProgressPreference = 'SilentlyContinue'
        [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
        try {
            if ($WorkerContext.Length -gt 65536) { throw 'Worker context exceeds the input bound.' }
            $contextObject = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($WorkerContext)) | ConvertFrom-Json -ErrorAction Stop
            $payload = Invoke-Dot1xWorker -Name $WorkerName -Context $contextObject
        } catch { $payload = [pscustomobject]@{ Status='Failed'; Data=$null; Limitations=@("Worker unavailable: $($_.Exception.GetType().Name); HRESULT=$($_.Exception.HResult).") } }
        [Console]::Out.WriteLine(($payload | ConvertTo-Json -Depth 18 -Compress))
    } else {
        try {
            if ($EvidencePath) {
                $file = Get-Item -LiteralPath $EvidencePath -ErrorAction Stop
                if ($file.PSIsContainer -or $file.Length -gt 8388608) { throw 'Evidence input must be a JSON file no larger than 8 MiB.' }
                $evidence = [IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json -ErrorAction Stop
                if ((Get-Dot1xValue $evidence 'SchemaVersion') -ne 1) { throw 'Unsupported evidence schema. Expected SchemaVersion=1.' }
            } else {
                if ($OmitEventMessages) { $IncludeEventMessages = $false }
                elseif (-not $PSBoundParameters.ContainsKey('IncludeEventMessages')) { $IncludeEventMessages = $true }
                if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
                    $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
                    if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = Join-Path $env:USERPROFILE 'Desktop' }
                    $OutputDirectory = Join-Path $desktop 'Dot1x-Report'
                }
                $evidence = Get-Dot1xEvidence -ScriptPath $PSCommandPath -InterfaceAlias $InterfaceAlias -ProfileName $ProfileName `
                    -LookbackHours $LookbackHours -MaxEventsPerLog $MaxEventsPerLog -ProbeTimeoutSeconds $ProbeTimeoutSeconds `
                    -OverallTimeoutSeconds $OverallTimeoutSeconds -MaxProfiles $MaxProfiles -MaxCertificatesPerStore $MaxCertificatesPerStore -IncludeEventMessages:$IncludeEventMessages
            }
            $report = [pscustomobject][ordered]@{
                SchemaVersion=1; CapturedAtUtc=(Get-Dot1xValue $evidence 'CapturedAtUtc')
                Collection=(Get-Dot1xValue $evidence 'Collection'); Probes=@(Get-Dot1xValue $evidence 'Probes' @())
                Findings=@(Get-Dot1xDiagnosis -Evidence $evidence)
            }
            if ($OutputDirectory) { $null = Write-Dot1xReport -Report $report -Evidence $evidence -OutputDirectory $OutputDirectory }
            if ($PassThru) { $report } else { Format-Dot1xReport -Report $report }
        } catch { Write-Error -Message ('Diagnostics failed: ' + $_.Exception.Message) -ErrorAction Continue; exit 1 }
    }
}

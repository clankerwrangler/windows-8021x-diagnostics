<#
.SYNOPSIS
Tests the reviewed cache-only Crypt32 seam with public DER fixtures in memory.
.DESCRIPTION
No private keys are included or used, and no certificate store is mutated.
AIA is present in the leaf fixture. The reviewed cache-only API flags, not elapsed
runtime, provide the no-download contract. This is not a packet-level network test.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string]$ExpectedSourceSha256
)
. (Join-Path $PSScriptRoot 'Test-Library.ps1')
$hash = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $ExpectedSourceSha256.ToLowerInvariant()) { throw 'Source changed after native review.' }
Write-Output ('RECEIPT source_sha256=' + $hash + ' ps=' + $PSVersionTable.PSVersion.ToString() + ' os=' + [Environment]::OSVersion.Version.ToString())
. $ScriptPath
# Public synthetic certificates. Their private keys were discarded at generation.
# The AIA leaf uses a different issuer that is never supplied to Windows.
$rootDer = 'MIIDITCCAgmgAwIBAgIUMgOOD1a+RxDWDreUAm0VuYsp09kwDQYJKoZIhvcNAQELBQAwHzEdMBsGA1UEAwwUZG90MXgtc3ludGhldGljLXJvb3QwIBcNMjYwOTA2MTI1NjUyWhgPMjEyNjA4MTMxMjU2NTJaMB8xHTAbBgNVBAMMFGRvdDF4LXN5bnRoZXRpYy1yb290MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1tE8w+rLJF4cB9yOZbEXynELbL0JSeL7xGQnzvDjpLXd+4d5od5UlBYvJ2roDjtV6rcUFHI4rNYR9kwVi4Thib/973cFVGMSb9OSrJWk+YWrahCMjb2I6Cjhdd6fukqWNkuYhg25/pCLXadxJ7wqmmnWON6Z+vMHyQilcMe21fbjLqsl6BCVDKRqDQKEQ9nlV/2fR2m7Za+YiH/m3oVmuYSEu79kPUSVytdhbeZDJU2bbgc8DtNokrBaj+4EWAkdYYuB7OniYgudOeYEIlgaDDw7o2ZaWdEV5ACeF4zesJlFiE0V/8NU+WcddXCUK3hjPr9+mfB/POgITa9x2/tgTQIDAQABo1MwUTAdBgNVHQ4EFgQUE7sz8tzNRCYjUt2EwtGVB9MWdKEwHwYDVR0jBBgwFoAUE7sz8tzNRCYjUt2EwtGVB9MWdKEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAuPp05btQUCUJLne6MnaZbk9+1apepuvJ7QklTQKDktiUz1suWuSlJjgdqbuiE+nz3d4/NHYXdP/Wfmh9grGPIbOQjwxsuGIlO7BsOF0tFHnqQQpNHpO2k33qkVMotKO805o05hAej3C0ZXoqGs/YwToTDarDc3/xtmUZjJZA9C0tnttz8pvx4ZEN0ChRmORl69pbvlJZezfJOyLo1ddwcylcV2nHKVvsQQFC/00SI0j6bCxoDQY/MNkoHfeYk+ORWr/emtz+0tTiYZT+SlRdNA0mQfv3WEqxKmmcXHJCWmk8mDtQSlVU+sNXG4PWuavjjgpNngJFWitaaiD+x5BSpg=='
$leafDer = 'MIIDWjCCAkKgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDDCJkb3QxeC1hYnNlbnQtaXNzdWVyLW5ldmVyLXByb3ZpZGVkMCAXDTI2MDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAwWjAjMSEwHwYDVQQDDBhkb3QxeC1zeW50aGV0aWMtYWlhLWxlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmecjnJgKZPBKoKoRWeP7WCBKoQdIR9eKJwSCUOIqSBP0y7yXf+UbSiaMD78jMfBvhmso4tF7vgbYfxxZ0cFgZAHIku9hfvRZEtO92L51QGnV9InX5yIGmmLTPhdqsU/YkmkhVNS0DamFln31tNt5i75kAydwH7Pd1ykWNl/wWQPKcIcOMxjkxtWStGYsbtndCh+GB8P22XBdMjenu7PuMFQ8Q2PG/ORIJsSnD+bbdX/MrnyVKTv5UlsXqFAgtpFkfDDqlGFhssIXkAGgx5MKMJQ906qltscrZtVZf6HNQ1KDto5t8rhLrWYlEmuR0WSjrfxt0/wAZGtMB2BNUvq2JAgMBAAGjgYwwgYkwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAjAfBgNVHSMEGDAWgBQ5CNUkJRGMAk/by1R+1YvgbVDirjBDBggrBgEFBQcBAQQ3MDUwMwYIKwYBBQUHMAKGJ2h0dHA6Ly9kb3QxeC1maXh0dXJlLmludmFsaWQvaXNzdWVyLmRlcjANBgkqhkiG9w0BAQsFAAOCAQEAKJ8luIAfhwDuRXL31Knj8wTrQJgnMZIrFaa5dzkllPVZB23V+ODKr3U3TTpROXxAqQiOzc93pgy1hBV2sZ7jH0yCmUfgBBdQ35WwCPps54H5HecaMBj6IeDz383VHwMJgQDlvaUplEXxfaim/pJ2VElXd++KTq5iBoWVEKLuHbgBo+AKi9OCzuLBx/R69vjFXyneIF6xVMJKeKk5xMMFEKckWaKKNGcwf6aIPYUgCDVk3N96fzwqiH+cTg0cEZf5frgpf7ck2QlyIBw/8bgXuGhU8mBrWXaFsxwLJrcTVGo5hIPB23MBea9oko9G9wna6IEmXnB2yGzHfzyZHdSyDg=='
Test-Case 'reviewed native declarations compile on Windows PowerShell' {
    Initialize-Dot1xNative
    Assert-True ($null -ne ('Dot1x.Native' -as [type])) 'Reviewed native type did not load.'
}
Test-Case 'untrusted public self-signed certificate is not a trusted-chain proof' {
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($rootDer))
    try {
        Assert-Equal $cert.HasPrivateKey $false 'Public fixture unexpectedly contains a private key.'
        $r = [Dot1x.Native]::ReadChain($cert.Handle,$false)
        Assert-True ($r.Status -contains 'UntrustedRoot') 'Uninstalled synthetic root was not reported untrusted.'
        Assert-Equal $r.Assessment 'CachedChainErrors' 'Untrusted root was reported as a successful trust assessment.'
    } finally { $cert.Dispose() }
}
Test-Case 'missing issuer with AIA remains partial in the reviewed cache-only path' {
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($leafDer))
    try {
        Assert-Equal $cert.HasPrivateKey $false 'Public fixture unexpectedly contains a private key.'
        Assert-True (@($cert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' }).Count -eq 1) 'Missing-issuer fixture lacks AIA.'
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $r = [Dot1x.Native]::ReadChain($cert.Handle,$false)
        $clock.Stop()
        Assert-True ($r.Status -contains 'PartialChain') 'Missing issuer was not reported as a partial chain.'
        Assert-True ($r.Assessment -ne 'NoErrorsInCachedAssessment') 'Absent issuer was reported as a valid cached chain.'
        Assert-True ($clock.Elapsed.TotalSeconds -lt 10) 'Cache-only native call exceeded the test bound.'
    } finally { $cert.Dispose() }
}
Test-Case 'machine engine also keeps the absent issuer as incomplete evidence' {
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($leafDer))
    try {
        $r = [Dot1x.Native]::ReadChain($cert.Handle,$true)
        Assert-True ($r.Status -contains 'PartialChain') 'Machine chain engine concealed the missing issuer.'
        Assert-True ($r.Assessment -ne 'NoErrorsInCachedAssessment') 'Machine engine overstated cached evidence.'
    } finally { $cert.Dispose() }
}
Complete-Tests

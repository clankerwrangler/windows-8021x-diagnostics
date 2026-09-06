# All profile values are synthetic. No live profile or credential is read here.
function New-TestProfileXml {
    param(
        [ValidateSet('Wired', 'Wireless')][string]$Kind = 'Wireless',
        [int]$EapType = 13,
        [string]$AuthMode = 'machine',
        [string]$Root = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        [string]$ServerNames = 'radius.fixture.invalid',
        [string]$Extra = '',
        [string]$EapExtra = ''
    )
    $eap = @"
<OneX xmlns="http://www.microsoft.com/networking/OneX/v1"><authMode>$AuthMode</authMode><EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">$EapType</Type><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod><Config><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>$EapType</Type><EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1"><CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource><ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>$ServerNames</ServerNames><TrustedRootCA>$Root</TrustedRootCA></ServerValidation>$EapExtra</EapType></Eap></Config></EapHostConfig></EAPConfig></OneX>
"@
    if ($Kind -eq 'Wired') {
        return '<LANProfile xmlns="http://www.microsoft.com/networking/LAN/profile/v1"><MSM><security><OneXEnabled>true</OneXEnabled>' + $eap + '</security></MSM>' + $Extra + '</LANProfile>'
    }
    return '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>fixture-profile</name><SSIDConfig><SSID><name>fixture-ssid</name></SSID></SSIDConfig><connectionType>ESS</connectionType><connectionMode>auto</connectionMode><MSM><security><authEncryption><authentication>WPA2</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>' + $eap + '</security></MSM>' + $Extra + '</WLANProfile>'
}

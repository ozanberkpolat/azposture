# MFA registration coverage (% of users registered). Reporting needs Entra ID P1.
if (-not (Test-EntraLicence @('AAD_PREMIUM','AAD_PREMIUM_P2'))) { return Skip-Check 'MFA registration coverage' 'The authentication-methods registration report requires Entra ID P1 (not present).' }
$reg = Get-GraphAll 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isMfaRegistered,userType'
$members = @($reg | Where-Object { $_.userType -eq 'member' })
$notReg = @($members | Where-Object { -not $_.isMfaRegistered })
$items = @()
if ($members.Count -gt 0 -and $notReg.Count -gt 0) {
    $pct = [math]::Round(100.0 * $notReg.Count / $members.Count)
    foreach ($u in ($notReg | Select-Object -First 200)) {
        $items += [pscustomobject]@{ Title = $u.userPrincipalName; Detail = 'Not registered for MFA' }
    }
    # lead line via the check Name reflects the coverage gap
    $script:covLine = "$($notReg.Count) of $($members.Count) members ($pct%) are not registered for MFA"
}
$regCount = $members.Count - $notReg.Count
$regPct = if ($members.Count) { [math]::Round(100.0 * $regCount / $members.Count) } else { 0 }
[pscustomobject]@{
    Name = if ($script:covLine) { "MFA registration gap — $script:covLine" } else { 'MFA registration coverage' }
    Severity = 'high'
    Evidence = "$regCount of $($members.Count) members ($regPct%) are registered for MFA"
    Fix = 'Drive MFA registration (registration campaign / combined security info) so enforcement policies actually protect every account.'
    Items = $items
}

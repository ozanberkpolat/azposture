# Does any enabled CA policy targeting directory roles demand an authentication STRENGTH
# (e.g. phishing-resistant MFA) rather than plain "mfa"? Strength is a P1 Conditional Access feature.
if (-not (Test-EntraLicence @('AAD_PREMIUM','AAD_PREMIUM_P2'))) { return Skip-Check 'Authentication strength for admins' 'Conditional Access requires Entra ID P1 (not present on this tenant).' }
. (Join-Path $PSScriptRoot '_ca-common.ps1')
$pols = @(Get-EnabledCaPolicies)
$adminPols = @($pols | Where-Object { @($_.conditions.users.includeRoles).Count -gt 0 })
$strong = @($adminPols | Where-Object { $_.grantControls.authenticationStrength -and $_.grantControls.authenticationStrength.id })
$items = @()
if (-not $strong) {
    $detail = if ($adminPols.Count -gt 0) { "$($adminPols.Count) admin-targeting policies, all rely on the generic 'mfa' grant" }
              else { 'No enabled policy targets directory roles at all' }
    $items += [pscustomobject]@{ Title = 'No authentication strength required for admin sign-in'; Detail = $detail }
}
$names = @($strong | ForEach-Object { $_.grantControls.authenticationStrength.displayName }) -join ', '
$evidence = if ($strong) { "Admin policies enforce authentication strength: $names" }
            else { "$($adminPols.Count) admin-targeting CA policies, none enforce an authentication strength" }
[pscustomobject]@{ Name = 'Authentication strength for admins'; Severity = 'high'
    Evidence = $evidence
    Fix = 'Require a phishing-resistant authentication strength (FIDO2, Windows Hello for Business, or certificate-based) on the Conditional Access policy that covers directory roles.'
    Items = $items }

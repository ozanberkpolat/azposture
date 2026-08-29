if (-not (Test-EntraLicence @('AAD_PREMIUM','AAD_PREMIUM_P2'))) { return Skip-Check 'MFA-for-admins Conditional Access policy' 'Conditional Access requires Entra ID P1 (not present on this tenant).' }
. (Join-Path $PSScriptRoot '_ca-common.ps1')
$pols = @(Get-EnabledCaPolicies)
$match = $pols | Where-Object {
    (@($_.conditions.users.includeRoles).Count -gt 0) -and (@($_.grantControls.builtInControls) -contains 'mfa')
}
$items = @()
if (-not $match) { $items += [pscustomobject]@{ Title = 'No enabled policy requires MFA for directory roles'; Detail = "$($pols.Count) enabled CA policies, none target admin roles with MFA" } }
[pscustomobject]@{ Name = 'MFA for admins'; Severity = 'high'
    Evidence = "$($pols.Count) enabled Conditional Access policies; admin-MFA policy present: $([bool]$match)"
    Fix = 'Create an enabled Conditional Access policy requiring MFA for privileged directory roles.'
    Items = $items }

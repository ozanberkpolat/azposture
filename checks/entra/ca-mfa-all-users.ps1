if (-not (Test-EntraLicence @('AAD_PREMIUM','AAD_PREMIUM_P2'))) { return Skip-Check 'MFA-for-all Conditional Access policy' 'Conditional Access requires Entra ID P1 (not present on this tenant).' }
. (Join-Path $PSScriptRoot '_ca-common.ps1')
$pols = @(Get-EnabledCaPolicies)
$match = $pols | Where-Object {
    ($_.conditions.users.includeUsers -contains 'All') -and
    (@($_.grantControls.builtInControls) -contains 'mfa') -and
    (@($_.conditions.applications.includeApplications) -contains 'All')
}
$items = @()
if (-not $match) { $items += [pscustomobject]@{ Title = 'No enabled policy requires MFA for all users'; Detail = "$($pols.Count) enabled CA policies, none enforce all-user MFA" } }
[pscustomobject]@{ Name = 'MFA for all users'; Severity = 'high'
    Evidence = "$($pols.Count) enabled Conditional Access policies; all-user MFA policy present: $([bool]$match)"
    Fix = 'Create an enabled Conditional Access policy requiring MFA for All users and All cloud apps (exclude break-glass accounts).'
    Items = $items }

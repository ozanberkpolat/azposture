if (-not (Test-EntraLicence @('AAD_PREMIUM','AAD_PREMIUM_P2'))) { return Skip-Check 'MFA-for-Azure-management Conditional Access policy' 'Conditional Access requires Entra ID P1 (not present on this tenant).' }
. (Join-Path $PSScriptRoot '_ca-common.ps1')
$pols = @(Get-EnabledCaPolicies)
# Windows Azure Service Management API app id
$arm = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
$match = $pols | Where-Object {
    ((@($_.conditions.applications.includeApplications) -contains $arm) -or (@($_.conditions.applications.includeApplications) -contains 'All')) -and
    (@($_.grantControls.builtInControls) -contains 'mfa')
}
$items = @()
if (-not $match) { $items += [pscustomobject]@{ Title = 'No enabled policy requires MFA for Azure management'; Detail = "$($pols.Count) enabled CA policies, none require MFA for the Azure management API" } }
[pscustomobject]@{ Name = 'MFA for Azure management'; Severity = 'high'
    Evidence = "$($pols.Count) enabled Conditional Access policies; Azure-management MFA policy present: $([bool]$match)"
    Fix = 'Create an enabled Conditional Access policy requiring MFA for the Microsoft Azure Management app.'
    Items = $items }

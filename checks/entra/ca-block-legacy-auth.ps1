if (-not (Test-EntraLicence @('AAD_PREMIUM','AAD_PREMIUM_P2'))) { return Skip-Check 'Block-legacy-auth Conditional Access policy' 'Conditional Access requires Entra ID P1 (not present on this tenant).' }
. (Join-Path $PSScriptRoot '_ca-common.ps1')
$pols = @(Get-EnabledCaPolicies)
$match = $pols | Where-Object {
    (@($_.conditions.clientAppTypes) -contains 'exchangeActiveSync' -or @($_.conditions.clientAppTypes) -contains 'other') -and
    (@($_.grantControls.builtInControls) -contains 'block')
}
$items = @()
if (-not $match) { $items += [pscustomobject]@{ Title = 'No enabled policy blocks legacy authentication'; Detail = "$($pols.Count) enabled CA policies, none block legacy/basic-auth clients" } }
[pscustomobject]@{ Name = 'Block legacy authentication'; Severity = 'high'
    Evidence = "$($pols.Count) enabled Conditional Access policies; legacy-auth block present: $([bool]$match)"
    Fix = 'Create an enabled Conditional Access policy that blocks legacy authentication clients (exchangeActiveSync + other).'
    Items = $items }

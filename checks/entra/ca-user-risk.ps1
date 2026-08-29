# Risk-based CA: an enabled policy that acts on USER risk (compromised account). Needs Entra ID P2.
if (-not (Test-EntraLicence @('AAD_PREMIUM_P2'))) { return Skip-Check 'User risk Conditional Access policy' 'Risk-based Conditional Access requires Entra ID P2 (not present on this tenant).' }
. (Join-Path $PSScriptRoot '_ca-common.ps1')
$pols = @(Get-EnabledCaPolicies)
$match = @($pols | Where-Object { @($_.conditions.userRiskLevels).Count -gt 0 -and
    ((@($_.grantControls.builtInControls) -contains 'passwordChange') -or (@($_.grantControls.builtInControls) -contains 'block')) })
$items = @()
if (-not $match) { $items += [pscustomobject]@{ Title = 'No enabled policy acts on user risk'; Detail = "$($pols.Count) enabled CA policies, none condition on userRiskLevels" } }
[pscustomobject]@{ Name = 'User risk Conditional Access policy'; Severity = 'high'
    Evidence = "$($pols.Count) enabled Conditional Access policies; user-risk policy present: $([bool]$match)"
    Fix = 'Create an enabled Conditional Access policy that forces a secure password change (or blocks) when user risk is high.'
    Items = $items }

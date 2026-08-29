# Risk-based CA: an enabled policy that acts on SIGN-IN risk. Needs Entra ID P2 (risk signals).
if (-not (Test-EntraLicence @('AAD_PREMIUM_P2'))) { return Skip-Check 'Sign-in risk Conditional Access policy' 'Risk-based Conditional Access requires Entra ID P2 (not present on this tenant).' }
. (Join-Path $PSScriptRoot '_ca-common.ps1')
$pols = @(Get-EnabledCaPolicies)
$match = @($pols | Where-Object { @($_.conditions.signInRiskLevels).Count -gt 0 -and
    ((@($_.grantControls.builtInControls) -contains 'mfa') -or (@($_.grantControls.builtInControls) -contains 'block') -or $_.grantControls.authenticationStrength) })
$items = @()
if (-not $match) { $items += [pscustomobject]@{ Title = 'No enabled policy acts on sign-in risk'; Detail = "$($pols.Count) enabled CA policies, none condition on signInRiskLevels" } }
[pscustomobject]@{ Name = 'Sign-in risk Conditional Access policy'; Severity = 'high'
    Evidence = "$($pols.Count) enabled Conditional Access policies; sign-in-risk policy present: $([bool]$match)"
    Fix = 'Create an enabled Conditional Access policy that requires MFA (or blocks) when sign-in risk is medium or high.'
    Items = $items }

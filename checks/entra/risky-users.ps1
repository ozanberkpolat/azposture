# Users currently flagged at risk by Identity Protection. Needs Entra ID P2.
if (-not (Test-EntraLicence @('AAD_PREMIUM_P2'))) { return Skip-Check 'Risky users' 'Identity Protection risky-users requires Entra ID P2 (not present).' }
$risky = Get-GraphAll "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'&`$select=userPrincipalName,riskLevel,riskLastUpdatedDateTime"
$items = @()
foreach ($u in @($risky)) {
    $items += [pscustomobject]@{ Title = $u.userPrincipalName; Detail = "Risk level $($u.riskLevel), flagged $($u.riskLastUpdatedDateTime)"; Severity = (if ($u.riskLevel -eq 'high') { 'high' } else { 'medium' }) }
}
[pscustomobject]@{
    Name = 'Users flagged at risk'
    Severity = 'high'
    Evidence = "$($items.Count) user(s) currently flagged at risk by Identity Protection"
    Fix = 'Investigate and remediate at-risk users (password reset / dismiss) and enable risk-based Conditional Access.'
    Items = $items
}

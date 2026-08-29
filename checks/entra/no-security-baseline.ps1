# No identity security baseline: Security Defaults OFF *and* no enabled Conditional Access.
# Works on any tenant (Security Defaults + reading CA are free); a genuine "nothing protects sign-in" finding.
$sd = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -OutputType PSObject
$caCount = 0
try {
    $ca = Get-GraphAll 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=state'
    $caCount = @($ca | Where-Object { $_.state -eq 'enabled' }).Count
} catch {}
$items = @()
if (-not $sd.isEnabled -and $caCount -eq 0) {
    $items += [pscustomobject]@{ Title = 'No sign-in security baseline in place'; Detail = 'Security Defaults are disabled and there are no enabled Conditional Access policies'; Severity = 'critical' }
}
[pscustomobject]@{
    Name = 'Identity security baseline'
    Severity = 'critical'
    Evidence = "Security Defaults: $(if ($sd.isEnabled) { 'enabled' } else { 'disabled' }); $caCount enabled Conditional Access policies"
    Fix = 'Enable Security Defaults, or (on Entra ID P1+) create Conditional Access policies that enforce MFA and block legacy auth.'
    Items = $items
}

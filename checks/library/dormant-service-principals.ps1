# Enabled, tenant-owned service principals with no recent sign-in (beta signInActivity).
# If the beta endpoint/feature is unavailable the run-checks orchestrator records a loud skip.
$now = Get-Date
$items = @()
$sel = 'id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,signInActivity'
foreach ($sp in Get-GraphAll "https://graph.microsoft.com/beta/servicePrincipals?`$select=$sel&`$top=999") {
    if (-not $sp.accountEnabled) { continue }
    if ($sp.servicePrincipalType -eq 'ManagedIdentity') { continue }
    if (Test-MicrosoftFirstParty $sp) { continue }
    $last = To-Date $sp.signInActivity.lastSignInDateTime
    if (-not $last) { $last = To-Date $sp.signInActivity.lastNonInteractiveSignInDateTime }
    if (-not $last) {
        $items += [pscustomobject]@{ Title = $sp.displayName; Detail = "No recorded sign-in activity; appId $($sp.appId)" }
    } elseif (($now - $last).Days -gt 90) {
        $items += [pscustomobject]@{ Title = $sp.displayName; Detail = "Last sign-in $($last.ToString('yyyy-MM-dd')) (>90d); appId $($sp.appId)" }
    }
}
[pscustomobject]@{
    Name     = 'Dormant service principals (90+ days inactive)'
    Severity = 'high'
    Fix      = 'Review and disable or delete unused service principals after confirming no automation depends on them.'
    Items    = $items
}

# Accepted guest accounts with no successful sign-in in 120 days.
$now = Get-Date
$items = @()
$sel = 'id,userPrincipalName,displayName,accountEnabled,externalUserState,signInActivity'
foreach ($u in Get-GraphAll "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=$sel&`$top=999") {
    if (-not $u.accountEnabled) { continue }
    if ($u.externalUserState -eq 'PendingAcceptance') { continue }
    $label = if ($u.userPrincipalName) { $u.userPrincipalName } else { $u.displayName }
    $last = To-Date $u.signInActivity.lastSuccessfulSignInDateTime
    if (-not $last) {
        $items += [pscustomobject]@{ Title = $label; Detail = 'Guest with no successful sign-in on record' }
    } elseif (($now - $last).Days -gt 120) {
        $items += [pscustomobject]@{ Title = $label; Detail = "Guest last sign-in $($last.ToString('yyyy-MM-dd')) (>120d)" }
    }
}
[pscustomobject]@{
    Name     = 'Inactive guest users (120+ days)'
    Severity = 'high'
    Fix      = 'Remove stale guests; review B2B collaboration necessity and run periodic guest access reviews.'
    Items    = $items
}

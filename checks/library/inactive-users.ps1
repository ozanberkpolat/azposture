# Enabled member accounts with no successful sign-in in 90 days (excludes new accounts).
$now = Get-Date
$items = @()
$sel = 'id,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity'
foreach ($u in Get-GraphAll "https://graph.microsoft.com/v1.0/users?`$select=$sel&`$top=999") {
    if (-not $u.accountEnabled) { continue }
    if ($u.userType -eq 'Guest') { continue }
    $created = To-Date $u.createdDateTime
    if ($created -and ($now - $created).Days -lt 90) { continue }   # don't flag brand-new accounts
    $last = To-Date $u.signInActivity.lastSuccessfulSignInDateTime
    if (-not $last) {
        $items += [pscustomobject]@{ Title = $u.userPrincipalName; Detail = 'No successful sign-in on record' }
    } elseif (($now - $last).Days -gt 90) {
        $items += [pscustomobject]@{ Title = $u.userPrincipalName; Detail = "Last sign-in $($last.ToString('yyyy-MM-dd')) ($(($now - $last).Days)d ago)" }
    }
}
[pscustomobject]@{
    Name     = 'Inactive users (90+ days)'
    Severity = 'medium'
    Fix      = 'Disable or remove stale accounts after manager confirmation; route them through an access review.'
    Items    = $items
}

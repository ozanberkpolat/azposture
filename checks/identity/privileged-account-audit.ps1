# Generalized from an earlier internal audit script.
# Original needed a hardcoded group id + the "-z" UPN convention. Generalized to
# enumerate members of privileged DIRECTORY ROLES (works on any tenant), and flag
# admins with weak MFA or stale sign-in. Tenant comes from the signed-in session.
$privNames = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'Conditional Access Administrator', 'Application Administrator',
    'Cloud Application Administrator', 'User Administrator', 'Exchange Administrator',
    'SharePoint Administrator', 'Intune Administrator', 'Hybrid Identity Administrator',
    'Authentication Administrator'
)
$now = Get-Date
$roles = Get-GraphAll 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName'

# Collect unique privileged USER members and the roles each holds.
$users = @{}   # userId -> [pscustomobject]{ Upn; Roles }
foreach ($role in $roles) {
    if ($privNames -notcontains $role.displayName) { continue }
    $members = Get-GraphAll "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members?`$select=id,userPrincipalName"
    foreach ($m in $members) {
        if ($m.'@odata.type' -and $m.'@odata.type' -notlike '*user') { continue }  # SPs/groups handled elsewhere
        if (-not $m.userPrincipalName) { continue }
        if (-not $users.ContainsKey($m.id)) {
            $users[$m.id] = [pscustomobject]@{ Upn = $m.userPrincipalName; Roles = @() }
        }
        $users[$m.id].Roles += $role.displayName
    }
}

$items = @()
foreach ($id in $users.Keys) {
    $u = $users[$id]
    $reasons = @()
    try {
        $info = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/v1.0/users/$id`?`$select=signInActivity"
        $last = To-Date $info.signInActivity.lastSuccessfulSignInDateTime
        if (-not $last) { $reasons += 'no successful sign-in on record' }
        elseif (($now - $last).Days -gt 90) { $reasons += "last sign-in $($last.ToString('yyyy-MM-dd')) (>90d)" }
    } catch { Write-Warning "signInActivity $($u.Upn): $_" }
    try {
        $am = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/v1.0/users/$id/authentication/methods"
        $types = @($am.value | ForEach-Object { ($_.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod', '') })
        $strong = @($types | Where-Object { $_ -ne 'password' })
        if ($strong.Count -eq 0) { $reasons += 'no MFA method registered (password only)' }
    } catch { Write-Warning "authMethods $($u.Upn): $_" }
    if ($reasons.Count -gt 0) {
        $items += [pscustomobject]@{
            Title  = $u.Upn
            Detail = "Roles: $(@($u.Roles | Sort-Object -Unique) -join ', '). Issues: $($reasons -join '; ')."
        }
    }
}
[pscustomobject]@{
    Name     = 'Privileged accounts — weak MFA or stale sign-in'
    Severity = 'critical'
    Fix      = 'Enforce phishing-resistant MFA on all admins, remove stale admin assignments, and move standing access to PIM eligibility.'
    Items    = $items
}

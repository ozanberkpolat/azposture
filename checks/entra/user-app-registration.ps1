# Users can register applications (authorizationPolicy). Best practice: restrict to admins.
$p = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -OutputType PSObject
$items = @()
if ($p.defaultUserRolePermissions.allowedToCreateApps) {
    $items += [pscustomobject]@{ Title = 'Any user can register applications'; Detail = 'defaultUserRolePermissions.allowedToCreateApps = true' }
}
[pscustomobject]@{
    Name = 'Users can register applications'
    Severity = 'medium'
    Evidence = "allowedToCreateApps = $($p.defaultUserRolePermissions.allowedToCreateApps)"
    Fix = 'Set "Users can register applications" to No; delegate app registration to a named admin group.'
    Items = $items
}

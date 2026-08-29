# Users can create tenants / security groups (authorizationPolicy) — should be off.
$p = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -OutputType PSObject
$perms = $p.defaultUserRolePermissions
$items = @()
if ($perms.allowedToCreateTenants) { $items += [pscustomobject]@{ Title = 'Any user can create new tenants'; Detail = 'allowedToCreateTenants = true' } }
if ($perms.allowedToCreateSecurityGroups) { $items += [pscustomobject]@{ Title = 'Any user can create security groups'; Detail = 'allowedToCreateSecurityGroups = true' } }
[pscustomobject]@{
    Name = 'User self-service creation privileges'
    Severity = 'low'
    Evidence = "allowedToCreateTenants = $($perms.allowedToCreateTenants); allowedToCreateSecurityGroups = $($perms.allowedToCreateSecurityGroups)"
    Fix = 'Disable user creation of tenants and (where governed) security groups; delegate to admins.'
    Items = $items
}

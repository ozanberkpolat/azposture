# Service principals (workload identities) holding high-risk Entra directory roles.
$risky = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'Conditional Access Administrator', 'Application Administrator',
    'Cloud Application Administrator', 'Exchange Administrator', 'SharePoint Administrator',
    'User Administrator', 'Intune Administrator', 'Hybrid Identity Administrator'
)
$items = @()
foreach ($role in Get-GraphAll 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName') {
    if ($risky -notcontains $role.displayName) { continue }
    foreach ($m in Get-GraphAll "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members?`$select=id,displayName,appId") {
        if ($m.'@odata.type' -like '*servicePrincipal') {
            $items += [pscustomobject]@{ Title = $m.displayName; Detail = "Service principal holds '$($role.displayName)'; appId $($m.appId)" }
        }
    }
}
[pscustomobject]@{
    Name     = 'Service principals in high-risk directory roles'
    Severity = 'critical'
    Fix      = 'Remove standing admin roles from workload identities; scope to least privilege and monitor their use.'
    Items    = $items
}

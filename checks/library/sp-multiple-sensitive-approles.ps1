# Service principals assigned more than one high-privilege Microsoft Graph app role.
$graph = @(Get-GraphAll "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles")[0]
$roleMap = @{}
foreach ($r in @($graph.appRoles)) { $roleMap["$($r.id)"] = $r.value }
$risky = @(
    'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureAD',
    'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All', 'Organization.ReadWrite.All',
    'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Mail.ReadWrite'
)
$byPrincipal = @{}
foreach ($a in Get-GraphAll "https://graph.microsoft.com/v1.0/servicePrincipals/$($graph.id)/appRoleAssignedTo?`$top=999") {
    $val = $roleMap["$($a.appRoleId)"]
    if ($val -and ($risky -contains $val)) {
        if (-not $byPrincipal.ContainsKey($a.principalId)) {
            $byPrincipal[$a.principalId] = [pscustomobject]@{ Name = $a.principalDisplayName; Roles = @() }
        }
        $byPrincipal[$a.principalId].Roles += $val
    }
}
$items = @()
foreach ($p in $byPrincipal.Values) {
    $u = @($p.Roles | Sort-Object -Unique)
    if ($u.Count -gt 1) {
        $items += [pscustomobject]@{ Title = $p.Name; Detail = "Holds $($u.Count) high-privilege Graph permissions: $($u -join ', ')" }
    }
}
[pscustomobject]@{
    Name     = 'Service principals with multiple sensitive app roles'
    Severity = 'high'
    Fix      = 'Split workloads so each principal holds only the permissions it needs; remove excess grants.'
    Items    = $items
}

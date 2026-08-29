# Flag principals granted high-risk Microsoft Graph APPLICATION permissions.
# Read every grant of a Graph app-role via the Graph SP's appRoleAssignedTo.
$graph = @(Get-GraphAll "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles")[0]
$roleMap = @{}
foreach ($r in @($graph.appRoles)) { $roleMap["$($r.id)"] = $r.value }
$risky = @(
    'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureAD',
    'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All', 'Organization.ReadWrite.All',
    'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Mail.ReadWrite',
    'Mail.Send', 'Files.ReadWrite.All', 'Sites.ReadWrite.All'
)
$items = @()
foreach ($a in Get-GraphAll "https://graph.microsoft.com/v1.0/servicePrincipals/$($graph.id)/appRoleAssignedTo?`$top=999") {
    $val = $roleMap["$($a.appRoleId)"]
    if ($val -and ($risky -contains $val)) {
        $items += [pscustomobject]@{ Title = $a.principalDisplayName; Detail = "Graph application permission '$val'" }
    }
}
[pscustomobject]@{
    Name     = 'Service principals with over-privileged Graph permissions'
    Severity = 'critical'
    Fix      = 'Remove write-scoped Graph application permissions; grant least-privilege read scopes and prefer delegated access.'
    Items    = $items
}

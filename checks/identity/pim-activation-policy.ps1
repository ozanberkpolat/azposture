# Generalized from an earlier internal audit script.
# Original needed a hardcoded tenant id + the external Get-PIMEntraRolePolicy module.
# Generalized to raw Graph roleManagementPolicyAssignments (tenant from the session),
# flagging weak PIM activation settings on privileged roles. Needs Entra ID P2.
$privNames = @(
    'Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
    'Conditional Access Administrator', 'Application Administrator', 'User Administrator',
    'Exchange Administrator', 'SharePoint Administrator', 'Intune Administrator',
    'Privileged Authentication Administrator', 'Authentication Administrator', 'Hybrid Identity Administrator'
)
$defs = @{}
foreach ($d in Get-GraphAll 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName') {
    $defs[$d.id] = $d.displayName
}
$assignments = Get-GraphAll "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'Directory'&`$expand=policy(`$expand=rules)"

$items = @()
foreach ($a in $assignments) {
    $roleName = $defs[$a.roleDefinitionId]
    if (-not $roleName -or ($privNames -notcontains $roleName)) { continue }
    $rules = @($a.policy.rules)
    $issues = @()

    $act = $rules | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' } | Select-Object -First 1
    if ($act -and $act.maximumDuration) {
        try {
            $ts = [System.Xml.XmlConvert]::ToTimeSpan($act.maximumDuration)
            if ($ts.TotalHours -gt 8) { $issues += "activation up to $([int]$ts.TotalHours)h (>8h)" }
        } catch {}
    }
    $enable = $rules | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' } | Select-Object -First 1
    if ($enable -and (@($enable.enabledRules) -notcontains 'MultiFactorAuthentication')) {
        $issues += 'no MFA required on activation'
    }
    $appr = $rules | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' } | Select-Object -First 1
    if ($appr -and $appr.setting -and (-not $appr.setting.isApprovalRequired)) {
        $issues += 'no approval required on activation'
    }
    if ($issues.Count -gt 0) {
        $items += [pscustomobject]@{ Title = $roleName; Detail = ($issues -join '; ') }
    }
}
[pscustomobject]@{
    Name     = 'PIM activation policy weaknesses'
    Severity = 'medium'
    Fix      = 'Require MFA + approval on activation and cap activation duration (<= 8h, ideally <= 4h) for privileged roles.'
    Items    = $items
}

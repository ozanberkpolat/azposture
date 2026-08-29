# Permanent (non-PIM) active assignments to privileged directory roles. Needs Entra ID P2 (PIM).
if (-not (Test-EntraLicence @('AAD_PREMIUM_P2'))) { return Skip-Check 'Standing privileged assignments' 'PIM eligibility comparison requires Entra ID P2 (not present).' }
$privTemplates = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
}
$active = Get-GraphAll "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=assignmentType eq 'Assigned'&`$select=roleDefinitionId,principalId,memberType"
$items = @()
foreach ($a in @($active)) {
    $name = $privTemplates[$a.roleDefinitionId]
    if ($name) {
        $items += [pscustomobject]@{ Title = "$name — standing assignment"; Detail = "Principal $($a.principalId) has a permanent active assignment (should be PIM-eligible)" }
    }
}
[pscustomobject]@{
    Name = 'Standing privileged role assignments'
    Severity = 'high'
    Evidence = "$($items.Count) permanent (non-PIM) privileged role assignment(s)"
    Fix = 'Convert permanent privileged assignments to PIM-eligible (just-in-time) so admin rights are activated on demand, not always on.'
    Items = $items
}

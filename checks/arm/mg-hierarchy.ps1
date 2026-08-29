# CAF Govern — management-group hierarchy should exist (landing-zone organisation).
$mgs = Invoke-Arm -Path '/providers/Microsoft.Management/managementGroups' -ApiVersion '2021-04-01'
$items = @()
if (@($mgs).Count -le 1) {
    $items += [pscustomobject]@{
        Title  = 'Tenant Root group'
        Detail = 'Only the Tenant Root group exists; subscriptions are not organised into platform / landing-zone management groups.'
    }
}
[pscustomobject]@{
    Name     = 'Management group hierarchy'
    Severity = 'high'
    Fix      = 'Build a management-group hierarchy (e.g. Platform, Landing Zones, Sandbox) and move subscriptions into it.'
    Items    = $items
}

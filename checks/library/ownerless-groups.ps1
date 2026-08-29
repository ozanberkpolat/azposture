# Microsoft 365 groups with no owner (excludes dynamic-membership groups).
$items = @()
$uri = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$select=id,displayName,groupTypes&`$expand=owners(`$select=id)&`$top=999"
foreach ($g in Get-GraphAll $uri) {
    if (@($g.groupTypes) -contains 'DynamicMembership') { continue }
    if (@($g.owners).Count -eq 0) {
        $items += [pscustomobject]@{ Title = $g.displayName; Detail = 'Microsoft 365 group with no owner' }
    }
}
[pscustomobject]@{
    Name     = 'Ownerless Microsoft 365 groups'
    Severity = 'medium'
    Fix      = 'Assign at least two owners; enable the ownerless-group policy to prompt members for ownership.'
    Items    = $items
}

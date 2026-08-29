# Managed-identity service principals with no tags/notes for ownership traceability.
$items = @()
$uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=servicePrincipalType eq 'ManagedIdentity'&`$select=id,displayName,tags,notes&`$top=999"
foreach ($mi in Get-GraphAll $uri) {
    $tags = @(@($mi.tags) | Where-Object { $_ })
    if ($tags.Count -eq 0 -and -not $mi.notes) {
        $items += [pscustomobject]@{ Title = $mi.displayName; Detail = 'Managed identity with no tags or notes for ownership/workload traceability' }
    }
}
[pscustomobject]@{
    Name     = 'Unclassified managed identities'
    Severity = 'low'
    Fix      = 'Tag managed identities by workload/owner so they can be traced during audits.'
    Items    = $items
}

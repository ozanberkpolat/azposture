# Tenant-owned service principals with no assigned owner.
$items = @()
$sel = 'id,displayName,appId,servicePrincipalType,appOwnerOrganizationId'
foreach ($sp in Get-GraphAll "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$sel&`$expand=owners(`$select=id)&`$top=999") {
    if (Test-MicrosoftFirstParty $sp) { continue }
    if ($sp.servicePrincipalType -eq 'ManagedIdentity') { continue }
    if (@($sp.owners).Count -eq 0) {
        $items += [pscustomobject]@{ Title = $sp.displayName; Detail = "No owner assigned; appId $($sp.appId)" }
    }
}
[pscustomobject]@{
    Name     = 'Service principals without owners'
    Severity = 'medium'
    Fix      = 'Assign at least one (ideally two) accountable owners to each service principal.'
    Items    = $items
}

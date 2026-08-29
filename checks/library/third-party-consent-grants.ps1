# Tenant-wide delegated consent grants whose RESOURCE is a non-Microsoft (third-party) API.
$items = @()
$cache = @{}
function ResolveSp($id) {
    if ($cache.ContainsKey($id)) { return $cache[$id] }
    $sp = try { Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$id`?`$select=displayName,appOwnerOrganizationId,appId" } catch { $null }
    $cache[$id] = $sp
    $sp
}
foreach ($g in Get-GraphAll "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$top=999") {
    if ($g.consentType -ne 'AllPrincipals') { continue }
    $res = ResolveSp $g.resourceId
    if (-not $res) { continue }
    if (Test-MicrosoftFirstParty $res) { continue }   # skip Microsoft resources (Graph, etc.)
    $client = ResolveSp $g.clientId
    $clientName = if ($client -and $client.displayName) { $client.displayName } else { $g.clientId }
    $items += [pscustomobject]@{
        Title  = "$clientName -> $($res.displayName)"
        Detail = "Tenant-wide delegated grant to a third-party API; scopes: $($g.scope)"
    }
}
[pscustomobject]@{
    Name     = 'OAuth2 grants to third-party (non-Microsoft) APIs'
    Severity = 'medium'
    Fix      = 'Review third-party API consents; revoke unused grants and prefer per-user consent.'
    Items    = $items
}

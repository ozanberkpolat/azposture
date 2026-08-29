# Tenant-wide (AllPrincipals) delegated consent grants for sensitive Microsoft Graph scopes.
$graph = @(Get-GraphAll "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,displayName")[0]
$risky = @('Mail.ReadWrite', 'Mail.Send', 'Calendars.ReadWrite', 'Contacts.ReadWrite',
    'Files.ReadWrite.All', 'Sites.ReadWrite.All', 'Directory.ReadWrite.All', 'User.ReadWrite.All',
    'MailboxSettings.ReadWrite', 'Group.ReadWrite.All')
$items = @()
foreach ($g in Get-GraphAll "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$top=999") {
    if ($g.consentType -ne 'AllPrincipals') { continue }
    if ($g.resourceId -ne $graph.id) { continue }   # Microsoft Graph resource only
    $scopes = @(($g.scope -split '\s+') | Where-Object { $_ })
    $hit = @($scopes | Where-Object { $risky -contains $_ })
    if ($hit.Count -gt 0) {
        $client = try { (Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($g.clientId)?`$select=displayName").displayName } catch { $g.clientId }
        $items += [pscustomobject]@{ Title = $client; Detail = "Tenant-wide Graph delegated grant of: $($hit -join ', ')" }
    }
}
[pscustomobject]@{
    Name     = 'Risky tenant-wide OAuth2 consent grants'
    Severity = 'high'
    Fix      = 'Revoke broad admin consent; prefer per-user / incremental consent and least-privilege scopes.'
    Items    = $items
}

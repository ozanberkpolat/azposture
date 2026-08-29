# Secrets and certificates expiring within the next 30 days, plus any that have ALREADY
# lapsed, across BOTH app registrations (applications) and enterprise applications
# (servicePrincipals) — the latter is where the SAML token-signing certificate lives.
# Assumes an open Graph session (run-checks.ps1 connects once). Emits the contract.
$WindowDays = 30
$now   = Get-Date
$limit = $now.AddDays($WindowDays)
$items = @()
$checked = 0

# ── collect (owner-kind, object) pairs: app registrations + tenant-owned SPs ──
$objects = @()
$apps = Get-AppsCached
foreach ($app in $apps) { $objects += [pscustomobject]@{ Kind = 'App registration'; O = $app } }

$sel = 'id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,passwordCredentials,keyCredentials,preferredTokenSigningKeyThumbprint'
$sps = Get-GraphAll "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$sel&`$top=999"
foreach ($sp in $sps) {
    if ($sp.servicePrincipalType -eq 'ManagedIdentity') { continue }   # platform-rotated
    if (Test-MicrosoftFirstParty $sp) { continue }                     # Microsoft-owned
    $objects += [pscustomobject]@{ Kind = 'Enterprise application'; O = $sp }
}

$nExpired  = 0
$nExpiring = 0
foreach ($entry in $objects) {
    $obj = $entry.O
    $creds = @()

    foreach ($s in @($obj.passwordCredentials)) {
        if ($s) { $creds += [pscustomobject]@{ Type = 'Client secret'; C = $s } }
    }

    # A SAML signing cert is returned TWICE (usage 'Sign' and 'Verify') sharing one
    # customKeyIdentifier — keep the 'Sign' copy so it isn't reported as two credentials.
    $keys = @($obj.keyCredentials) | Where-Object { $_ }
    $signIds = @($keys | Where-Object { $_.usage -eq 'Sign' } | ForEach-Object { "$($_.customKeyIdentifier)" })
    foreach ($k in $keys) {
        if ($k.usage -eq 'Verify' -and $signIds -contains "$($k.customKeyIdentifier)") { continue }
        $type = if ($k.usage -eq 'Sign' -and $k.type -eq 'AsymmetricX509Cert') {
            'SAML signing certificate'
        } else { 'Certificate' }
        $creds += [pscustomobject]@{ Type = $type; C = $k }
    }

    $expired = @()
    foreach ($cred in $creds) {
        $end = To-Date $cred.C.endDateTime
        if (-not $end) { continue }
        $checked++
        if ($end -gt $limit) { continue }                     # beyond the window
        $desc = if ($cred.C.displayName) { " '$($cred.C.displayName)'" } else { '' }
        if ($end -le $now) {
            $expired += [pscustomobject]@{ Type = $cred.Type; End = $end }
            $nExpired++
            continue
        }
        $days = [math]::Floor(($end - $now).TotalDays)
        $sev  = if ($days -le 7) { 'high' } else { 'medium' }
        $nExpiring++
        $items += [pscustomobject]@{
            Title    = "$($obj.displayName) — $($cred.Type)"
            Detail   = "Expires $($end.ToString('yyyy-MM-dd')) (in $days day(s)); $($entry.Kind)$desc; appId $($obj.appId)"
            Severity = $sev
        }
    }

    # ── already lapsed ────────────────────────────────────────────────────────────
    # ONE item per app, not per credential: the Title is the resource identity, so four dead
    # secrets on one app must not emit four rows sharing a Title (they would collide in
    # finding_item_state). The count goes in the Detail.
    # A lapsed SAML signing certificate is NOT hygiene — that application's sign-in is already
    # broken — so it is its own item at its own severity.
    foreach ($grp in @($expired | Group-Object { if ($_.Type -eq 'SAML signing certificate') { 'saml' } else { 'other' } })) {
        $cs  = @($grp.Group | Sort-Object End)
        $ago = [math]::Floor(($now - $cs[0].End).TotalDays)
        if ($grp.Name -eq 'saml') {
            $items += [pscustomobject]@{
                Title    = "$($obj.displayName) — expired SAML signing certificate"
                Detail   = "Expired $($cs[0].End.ToString('yyyy-MM-dd')) ($ago day(s) ago); sign-in to this application is already broken; $($entry.Kind); appId $($obj.appId)"
                Severity = 'critical'
            }
        } else {
            $what = (@($cs | ForEach-Object { $_.Type }) | Sort-Object -Unique) -join ' + '
            $items += [pscustomobject]@{
                Title    = "$($obj.displayName) — expired credentials"
                Detail   = "$($cs.Count) lapsed $what; oldest $($cs[0].End.ToString('yyyy-MM-dd')), newest $($cs[-1].End.ToString('yyyy-MM-dd')); authenticates nothing, safe to delete; $($entry.Kind); appId $($obj.appId)"
                Severity = 'low'
            }
        }
    }
}

$items = @($items | Sort-Object { $_.Detail })
[pscustomobject]@{
    Name     = "App credentials expired or expiring within $WindowDays days"
    Severity = 'high'
    Evidence = "$nExpiring expiring within $WindowDays days, $nExpired already lapsed, of $checked credential(s) checked"
    Fix      = 'Roll the affected secrets/certificates before they lapse and update every consumer. For SAML signing certificates, upload the new certificate, notify the relying party, then activate it during a change window. Delete credentials that have already lapsed - they authenticate nothing, so removing them is safe and needs no change window. Prefer federated (workload identity) credentials over secrets where supported.'
    Items    = $items
}

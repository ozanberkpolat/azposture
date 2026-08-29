# Guest invite + guest access-level settings (authorizationPolicy).
$p = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -OutputType PSObject
$items = @()
if ($p.allowInvitesFrom -in @('everyone')) {
    $items += [pscustomobject]@{ Title = 'Anyone (including guests) can invite guests'; Detail = "allowInvitesFrom = $($p.allowInvitesFrom)" }
}
# most-restricted guest role = 2af84b1e-32c8-42b7-82bc-daa82404023b
if ($p.guestUserRoleId -and $p.guestUserRoleId -ne '2af84b1e-32c8-42b7-82bc-daa82404023b') {
    $items += [pscustomobject]@{ Title = 'Guest users are not set to the most-restricted access level'; Detail = "guestUserRoleId = $($p.guestUserRoleId)" }
}
[pscustomobject]@{
    Name = 'Guest access restrictions'
    Severity = 'medium'
    Evidence = "allowInvitesFrom = $($p.allowInvitesFrom); guestUserRoleId = $($p.guestUserRoleId)"
    Fix = 'Restrict who can invite guests (admins/inviters only) and set guest access to the most-restricted level.'
    Items = $items
}

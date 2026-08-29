# Privileged accounts synced from on-prem AD: an on-prem compromise becomes a cloud compromise,
# and the account cannot be protected by cloud-only controls during an on-prem incident.
$roles = @(Get-GraphAll 'https://graph.microsoft.com/v1.0/directoryRoles')
if (-not $roles) { return Skip-Check 'Cloud-only privileged accounts' 'No activated directory roles are readable.' }
$items = @(); $checked = 0; $synced = 0
foreach ($r in $roles) {
    $members = @(Get-GraphAll "https://graph.microsoft.com/v1.0/directoryRoles/$($r.id)/members?`$select=id,userPrincipalName,onPremisesSyncEnabled")
    foreach ($m in $members) {
        if (-not $m.userPrincipalName) { continue }   # groups / service principals: not in scope here
        $checked++
        if ($m.onPremisesSyncEnabled -eq $true) {
            $synced++
            $items += [pscustomobject]@{ Title = "$($m.userPrincipalName)"; Detail = "Synced from on-premises AD, holds '$($r.displayName)'"; Severity = 'high' }
        }
    }
}
[pscustomobject]@{ Name = 'Cloud-only privileged accounts'; Severity = 'high'
    Evidence = "$checked privileged user assignment(s) across $($roles.Count) activated role(s); $synced synced from on-premises"
    Fix = 'Give privileged roles to cloud-only accounts. Remove directory roles from any account synced from on-premises Active Directory.'
    Items = $items }

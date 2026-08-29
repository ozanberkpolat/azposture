# RBAC/IAM — deprecated classic Service/Co-Administrators should be removed.
$items = @()
foreach ($s in Get-Subs) {
    try {
        $admins = Invoke-Arm -Path "/subscriptions/$($s.Id)/providers/Microsoft.Authorization/classicAdministrators" -ApiVersion '2015-07-01'
        foreach ($a in $admins) {
            $items += [pscustomobject]@{
                Title  = $a.properties.emailAddress
                Detail = "Classic role '$($a.properties.role)' on $($s.Name) | sub $($s.Id)"
            }
        }
    } catch { Write-Warning "classic-admins $($s.Name): $_" }
}
[pscustomobject]@{
    Name     = 'Classic (co-)administrators still present'
    Severity = 'high'
    Fix      = 'Remove classic administrators; manage access exclusively through Azure RBAC role assignments.'
    Items    = $items
}

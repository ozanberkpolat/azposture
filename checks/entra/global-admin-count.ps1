# Global Administrator count should be small but include break-glass (best practice 2-4).
$role = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId='62e90394-69f5-4237-9190-012177145e10')" -OutputType PSObject -ErrorAction SilentlyContinue
$items = @()
if ($role -and $role.id) {
    $members = Get-GraphAll "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members?`$select=id,userPrincipalName"
    $n = @($members).Count
    if ($n -lt 2) { $items += [pscustomobject]@{ Title = "Only $n Global Administrator(s)"; Detail = 'Too few for a break-glass account; you risk being locked out'; Severity = 'high' } }
    elseif ($n -gt 4) { $items += [pscustomobject]@{ Title = "$n Global Administrators"; Detail = 'More than the recommended maximum of 4; reduce standing Global Admin sprawl'; Severity = 'medium' } }
} else {
    return Skip-Check 'Global Administrator count' 'Global Administrator role is not activated / not readable.'
}
[pscustomobject]@{
    Name = 'Global Administrator count'
    Severity = 'medium'
    Evidence = "$n Global Administrator(s) assigned (recommended baseline: 2-4)"
    Fix = 'Keep 2 to 4 Global Administrators including one cloud-only break-glass account; move the rest to least-privilege or PIM-eligible roles.'
    Items = $items
}

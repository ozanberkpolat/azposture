# Generalized from OBP/Azure/Audit/Authentication/Guests-With-Password-Only.ps1
$guests = Get-GraphAll "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName&`$top=999"
$items = @()
foreach ($g in $guests) {
    try {
        $m = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/v1.0/users/$($g.id)/authentication/methods"
        $types = @($m.value | ForEach-Object { ($_.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod', '') })
        if ($types.Count -eq 1 -and $types[0] -eq 'password') {
            $items += [pscustomobject]@{
                Title  = $g.userPrincipalName
                Detail = "$($g.displayName): only registered method is password (no MFA / passwordless)"
            }
        }
    } catch {
        # Per-guest read failure: warn (captured in logs), keep going — don't abort the check.
        Write-Warning "guest $($g.userPrincipalName): $_"
    }
}
[pscustomobject]@{
    Name     = 'Guest users with password-only authentication'
    Severity = 'high'
    Fix      = 'Require MFA for guests via Conditional Access and prompt re-registration with an authenticator.'
    Items    = $items
}

# Weak (phishable) authentication methods still enabled: SMS / Voice.
$items = @()
$states = @()
foreach ($m in @('sms','voice')) {
    try {
        $cfg = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$m" -OutputType PSObject
        $states += "$($m.ToUpper()): $($cfg.state)"
        if ($cfg.state -eq 'enabled') { $items += [pscustomobject]@{ Title = "$($m.ToUpper()) authentication method is enabled"; Detail = 'Phishable / SIM-swappable method; prefer app or FIDO2' } }
    } catch { $states += "$($m.ToUpper()): unknown" }
}
[pscustomobject]@{
    Name = 'Weak authentication methods enabled'
    Severity = 'medium'
    Evidence = ($states -join '; ')
    Fix = 'Disable SMS and Voice methods in the Authentication Methods policy; move users to Authenticator or FIDO2 / passkeys.'
    Items = $items
}

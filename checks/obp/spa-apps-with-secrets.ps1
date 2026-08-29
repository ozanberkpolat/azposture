# Generalized from OBP/Azure/Audit/App_Registrations/SinglePageApp-With-Secrets.ps1
$apps = Get-AppsCached
$now = Get-Date
$items = @()
foreach ($app in $apps) {
    $spa = $app.spa
    if ($spa -and @($spa.redirectUris).Count -gt 0) {
        $active = @(@($app.passwordCredentials) | Where-Object { $_ -and (To-Date $_.endDateTime) -gt $now })
        if ($active.Count -gt 0) {
            $items += [pscustomobject]@{
                Title  = $app.displayName
                Detail = "SPA with $($active.Count) active secret(s); single-page apps are public clients and must not hold secrets; appId $($app.appId)"
            }
        }
    }
}
[pscustomobject]@{
    Name     = 'SPA apps holding client secrets'
    Severity = 'high'
    Fix      = 'Remove secrets from SPA apps; use the authorization-code + PKCE flow without a secret.'
    Items    = $items
}

# Generalized from OBP/Azure/Audit/App_Registrations/Apps-With-Multiple-Secrets.ps1
$apps = Get-AppsCached
$now = Get-Date
$items = @()
foreach ($app in $apps) {
    $secs = @(@($app.passwordCredentials) | Where-Object { $_ })
    if ($secs.Count -gt 1) {
        $active = @($secs | Where-Object { (To-Date $_.endDateTime) -gt $now })
        $items += [pscustomobject]@{
            Title  = $app.displayName
            Detail = "$($secs.Count) secrets ($($active.Count) active); appId $($app.appId)"
        }
    }
}
[pscustomobject]@{
    Name     = 'App registrations with multiple secrets'
    Severity = 'low'
    Fix      = 'Consolidate to a single active secret and remove unused credentials.'
    Items    = $items
}

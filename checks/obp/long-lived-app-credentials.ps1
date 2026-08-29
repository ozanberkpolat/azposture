# Generalized from OBP/Azure/Audit/App_Registrations/LongLivedCreds.ps1
# Assumes an open Graph session (run-checks.ps1 connects once). Emits the contract.
$apps = Get-AppsCached
$now = Get-Date
$items = @()
foreach ($app in $apps) {
    $creds = @()
    foreach ($s in @($app.passwordCredentials)) { if ($s) { $creds += [pscustomobject]@{ Type = 'Client secret'; C = $s } } }
    foreach ($k in @($app.keyCredentials))      { if ($k) { $creds += [pscustomobject]@{ Type = 'Certificate';   C = $k } } }
    foreach ($cred in $creds) {
        $start = To-Date $cred.C.startDateTime
        $end   = To-Date $cred.C.endDateTime
        if ($start -and $end -and $end -gt $now) {
            $life = ($end - $start).Days
            if ($life -gt 730) {
                $items += [pscustomobject]@{
                    Title  = "$($app.displayName) — $($cred.Type)"
                    Detail = "Lifetime $life days; expires $($end.ToString('yyyy-MM-dd')); appId $($app.appId)"
                }
            }
        }
    }
}
[pscustomobject]@{
    Name     = 'Long-lived app credentials (> 2 years)'
    Severity = 'high'
    Fix      = 'Rotate secrets/certs to <= 24 months, or move workloads to federated (workload identity) credentials.'
    Items    = $items
}

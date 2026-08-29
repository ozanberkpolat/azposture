# Generalized from an earlier internal audit script.
$apps = Get-AppsCached
$now = Get-Date
$items = @()
foreach ($app in $apps) {
    if ($app.displayName -match '^(?i)azdo') {
        $active = @(@($app.passwordCredentials) | Where-Object { $_ -and (To-Date $_.endDateTime) -gt $now })
        foreach ($s in $active) {
            $items += [pscustomobject]@{
                Title  = $app.displayName
                Detail = "Active secret expires $((To-Date $s.endDateTime).ToString('yyyy-MM-dd')); appId $($app.appId)"
            }
        }
    }
}
[pscustomobject]@{
    Name     = 'Azure DevOps (azdo*) apps with active secrets'
    Severity = 'medium'
    Fix      = 'Migrate azdo* service connections to workload identity federation (federated credentials).'
    Items    = $items
}

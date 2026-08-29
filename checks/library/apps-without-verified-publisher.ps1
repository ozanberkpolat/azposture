# Multi-tenant / published apps that have no verified publisher set.
$apps = Get-AppsCached
$items = @()
foreach ($app in $apps) {
    $isMulti = $app.signInAudience -and $app.signInAudience -ne 'AzureADMyOrg'
    $hasVp = $app.verifiedPublisher -and $app.verifiedPublisher.displayName
    if ($isMulti -and -not $hasVp) {
        $items += [pscustomobject]@{ Title = $app.displayName; Detail = "Multi-tenant app with no verified publisher; appId $($app.appId)" }
    }
}
[pscustomobject]@{
    Name     = 'Apps without a verified publisher'
    Severity = 'medium'
    Fix      = 'Complete publisher verification (Microsoft Partner Network), or restrict the app to single-tenant if internal.'
    Items    = $items
}

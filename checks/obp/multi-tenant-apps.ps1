# Generalized from OBP/Azure/Audit/App_Registrations/Apps-With-Multi-Tenant-Audience.ps1
$apps = Get-AppsCached
$items = @()
foreach ($app in $apps) {
    if ($app.signInAudience -and $app.signInAudience -ne 'AzureADMyOrg') {
        $items += [pscustomobject]@{
            Title  = $app.displayName
            Detail = "signInAudience = $($app.signInAudience); appId $($app.appId)"
        }
    }
}
[pscustomobject]@{
    Name     = 'Multi-tenant app registrations'
    Severity = 'medium'
    Fix      = 'Set the sign-in audience to AzureADMyOrg unless multi-tenant is genuinely required and reviewed.'
    Items    = $items
}

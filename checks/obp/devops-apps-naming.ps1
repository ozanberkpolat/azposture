# Generalized from OBP/Azure/Audit/App_Registrations/DevOps-App-Regs-Without-AZDO.ps1
$apps = Get-AppsCached
$items = @()
foreach ($app in $apps) {
    if (($app.notes -like '*Managed by Azure DevOps*') -and ($app.displayName -notmatch '^(?i)azdo')) {
        $items += [pscustomobject]@{
            Title  = $app.displayName
            Detail = "Notes mark it Azure DevOps-managed but the name is off the azdo* convention; appId $($app.appId)"
        }
    }
}
[pscustomobject]@{
    Name     = 'DevOps-managed apps off the azdo* naming convention'
    Severity = 'low'
    Fix      = 'Rename to the azdo* convention or correct the internal notes so governance tooling can find them.'
    Items    = $items
}

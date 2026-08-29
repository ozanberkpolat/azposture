# App registrations with no assigned owner.
$items = @()
foreach ($a in Get-GraphAll "https://graph.microsoft.com/v1.0/applications?`$select=id,displayName,appId&`$expand=owners(`$select=id)&`$top=999") {
    if (@($a.owners).Count -eq 0) {
        $items += [pscustomobject]@{ Title = $a.displayName; Detail = "No owner assigned; appId $($a.appId)" }
    }
}
[pscustomobject]@{
    Name     = 'Ownerless app registrations'
    Severity = 'medium'
    Fix      = 'Assign accountable owners to every app registration for lifecycle and security accountability.'
    Items    = $items
}

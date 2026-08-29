# Registered/joined devices with no sign-in activity in 90+ days.
$cut = (Get-Date).AddDays(-90)
$devices = Get-GraphAll 'https://graph.microsoft.com/v1.0/devices?$select=displayName,approximateLastSignInDateTime,operatingSystem,trustType'
$items = @()
foreach ($d in @($devices)) {
    $last = To-Date $d.approximateLastSignInDateTime
    if ($last -and $last -lt $cut) {
        $items += [pscustomobject]@{ Title = $d.displayName; Detail = "Last activity $($last.ToString('yyyy-MM-dd')) ($($d.operatingSystem), $($d.trustType))" }
    }
}
[pscustomobject]@{
    Name = 'Stale devices (90+ days)'
    Severity = 'low'
    Evidence = "$($items.Count) device(s) with no sign-in activity in 90+ days"
    Fix = 'Review and remove devices with no recent activity; stale devices still hold tokens and widen the attack surface.'
    Items = $items
}

# CAF Manage — every subscription should have a Cost Management budget + alert.
$items = @()
foreach ($s in Get-Subs) {
    try {
        $b = Invoke-Arm -Path "/subscriptions/$($s.Id)/providers/Microsoft.Consumption/budgets" -ApiVersion '2021-10-01'
        if (@($b).Count -eq 0) {
            $items += [pscustomobject]@{ Title = $s.Name; Detail = "No budget configured | sub $($s.Id)" }
        }
    } catch { Write-Warning "budgets $($s.Name): $_" }
}
[pscustomobject]@{
    Name     = 'Subscriptions without a budget'
    Severity = 'medium'
    Fix      = 'Create a Cost Management budget per subscription with alert thresholds (e.g. 50/75/90%).'
    Items    = $items
}

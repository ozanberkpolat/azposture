# Access review instances that are overdue or expiring within 7 days with work outstanding.
$now = Get-Date
$items = @()
foreach ($d in Get-GraphAll "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?`$select=id,displayName,status&`$top=999") {
    $insts = try {
        Get-GraphAll "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/$($d.id)/instances?`$select=status,endDateTime&`$top=50"
    } catch { @() }
    foreach ($i in $insts) {
        if ($i.status -notin @('InProgress', 'NotStarted')) { continue }
        $end = To-Date $i.endDateTime
        if (-not $end) { continue }
        if ($end -lt $now) {
            $items += [pscustomobject]@{ Title = $d.displayName; Detail = "Instance still $($i.status), ended $($end.ToString('yyyy-MM-dd')) (overdue)" }
        } elseif (($end - $now).Days -le 7) {
            $items += [pscustomobject]@{ Title = $d.displayName; Detail = "Instance $($i.status), ends $($end.ToString('yyyy-MM-dd')) (<= 7d)" }
        }
    }
}
[pscustomobject]@{
    Name     = 'Overdue or expiring access reviews'
    Severity = 'high'
    Fix      = 'Complete or reassign overdue reviews; ensure recurring reviews for privileged roles and guests.'
    Items    = $items
}

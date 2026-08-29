# CAF Govern — the subscription activity log should be exported (diagnostic settings).
$items = @()
foreach ($s in Get-Subs) {
    try {
        $d = Invoke-Arm -Path "/subscriptions/$($s.Id)/providers/Microsoft.Insights/diagnosticSettings" -ApiVersion '2021-05-01-preview'
        $hasSink = @($d | Where-Object { $_.properties.workspaceId -or $_.properties.storageAccountId -or $_.properties.eventHubAuthorizationRuleId }).Count -gt 0
        if (-not $hasSink) {
            $items += [pscustomobject]@{ Title = $s.Name; Detail = "Activity log not exported to a workspace/storage/event hub | sub $($s.Id)" }
        }
    } catch { Write-Warning "diag-activity $($s.Name): $_" }
}
[pscustomobject]@{
    Name     = 'Subscriptions without activity-log diagnostics'
    Severity = 'high'
    Fix      = 'Add a diagnostic setting on each subscription routing the Activity Log to a central Log Analytics workspace.'
    Items    = $items
}

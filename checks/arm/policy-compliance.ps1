# CAF Govern — Azure Policy non-compliant resources per subscription (live state).
$items = @()
foreach ($s in Get-Subs) {
    try {
        $r = Invoke-AzRestMethod -Method POST -Payload '{}' `
            -Path "/subscriptions/$($s.Id)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
        if ([int]$r.StatusCode -ge 400) { continue }
        $c = ($r.Content | ConvertFrom-Json)
        $res = $c.value[0].results
        $nc = [int]$res.nonCompliantResources
        if ($nc -gt 0) {
            $items += [pscustomobject]@{
                Title  = $s.Name
                Detail = "$nc non-compliant resources across $([int]$res.policyAssignments) policy assignments | sub $($s.Id)"
            }
        }
    } catch { Write-Warning "policy compliance $($s.Name): $_" }
}
[pscustomobject]@{
    Name     = 'Azure Policy non-compliant resources'
    Severity = 'high'
    Fix      = 'Remediate non-compliant resources or add deployIfNotExists/modify remediation tasks; assign baseline policy initiatives at management-group scope.'
    Items    = $items
}

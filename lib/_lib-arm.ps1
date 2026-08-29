<#
  Shared helpers for the ARM-plane checks (Resources / CAF / WAF / Defender).
  Dot-sourced once by run-checks.ps1 after Connect-AzAccount. Everything runs off
  the Az context, so no manual token threading.

  Azure Resource Graph (Search-Graph) is the workhorse — one KQL query spans every
  subscription the signed-in user can read, including the securityresources (Defender),
  advisorresources (Advisor) and authorizationresources (RBAC) tables. Invoke-Arm is
  the REST fallback for the few things Resource Graph doesn't expose (management-group
  hierarchy, budgets, diagnostic settings, classic admins, policy compliance).
#>

function global:Search-Graph {
    <# Run a Resource Graph KQL query across all readable subscriptions, paging.
       -Skip has a minimum of 1, so the first page must omit it entirely. #>
    param([Parameter(Mandatory)][string]$Query)
    $all = @(); $skip = 0
    do {
        $batch = if ($skip -gt 0) { @(Search-AzGraph -Query $Query -First 1000 -Skip $skip -ErrorAction Stop) }
                 else { @(Search-AzGraph -Query $Query -First 1000 -ErrorAction Stop) }
        if ($batch.Count) { $all += $batch }
        $skip += 1000
    } while ($batch.Count -eq 1000)
    , $all
}

function global:Get-Subs {
    <# Enabled subscriptions the signed-in user can read. #>
    @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
}

function global:Invoke-Arm {
    <# GET an ARM REST path (relative, no host) and follow nextLink. Returns .value[]. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion)
    $sep = if ($Path -like '*`?*') { '&' } else { '?' }
    $uri = "$Path${sep}api-version=$ApiVersion"
    $all = @()
    while ($uri) {
        $resp = Invoke-AzRestMethod -Method GET -Path $uri -ErrorAction Stop
        if ([int]$resp.StatusCode -ge 400) { throw "ARM $($resp.StatusCode): $($resp.Content)" }
        # 204 No Content is a documented empty result (reservationRecommendations returns it
        # when there is nothing to recommend). ConvertFrom-Json throws on an empty string, so
        # without this guard "nothing to report" reaches the caller as a failure.
        if (-not $resp.Content) { break }
        $c = $resp.Content | ConvertFrom-Json
        if ($null -ne $c.value) { $all += $c.value } else { $all += $c }
        $uri = $c.nextLink
        if ($uri) { $uri = $uri -replace '^https://management\.azure\.com', '' }
    }
    , $all
}

function global:Sub-Name {
    <# Friendly "<name> (<id>)" for a subscription id, cached. #>
    param([string]$Id)
    if (-not $global:AZTK_subnames) { $global:AZTK_subnames = @{} }
    if (-not $global:AZTK_subnames.ContainsKey($Id)) {
        $s = try { (Get-AzSubscription -SubscriptionId $Id -ErrorAction Stop).Name } catch { $null }
        $global:AZTK_subnames[$Id] = if ($s) { "$s ($Id)" } else { $Id }
    }
    $global:AZTK_subnames[$Id]
}

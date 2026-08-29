<#
  Shared helpers for the custom Graph checks. Dot-sourced once by run-checks.ps1
  (so the cache below persists across all checks in a run). Everything is raw
  Microsoft Graph REST via Invoke-MgGraphRequest — no Graph SDK submodules needed.
#>

# Well-known Microsoft first-party tenant ids — used to exclude Microsoft-owned
# service principals/apps from "your tenant's risk" findings.
$global:AZTK_MS_TENANTS = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a',  # Microsoft Services
    '72f988bf-86f1-41af-91ab-2d7cd011db47'   # Microsoft corp
)

function global:Get-GraphAll {
    <# Follow @odata.nextLink and return all .value entries as PSObjects.

       Emits the entries individually (no ", $all" wrapper). The comma idiom returns the
       array as ONE pipeline object, which silently breaks the two most natural call sites:
         foreach ($x in Get-GraphAll ...)   -> ONE iteration, $x bound to the whole array
         Get-GraphAll ... | Where-Object    -> the filter sees one array, not N objects
       Guard expressions then evaluate against the array ("$x.type -eq 'ManagedIdentity'"
       returns a non-empty match set), so a check would `continue` past everything and
       record a silent PASS. Callers that want a guaranteed array wrap in @(...). #>
    param([Parameter(Mandatory)][string]$Uri)
    $all = @()
    while ($Uri) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($null -ne $resp.value) { $all += $resp.value } else { $all += $resp }
        $Uri = $resp.'@odata.nextLink'
    }
    $all
}

function global:Get-AppsCached {
    <# One applications enumeration shared by every app-registration check. #>
    if (-not $global:AZTK_apps) {
        $sel = 'id,appId,displayName,signInAudience,passwordCredentials,keyCredentials,spa,notes,publicClient,web,verifiedPublisher'
        $global:AZTK_apps = @(Get-GraphAll "https://graph.microsoft.com/v1.0/applications?`$select=$sel&`$top=999")
    }
    $global:AZTK_apps
}

function global:Test-MicrosoftFirstParty {
    <# True if a servicePrincipal/app object is Microsoft-owned (exclude from risk). #>
    param($Obj)
    $owner = $Obj.appOwnerOrganizationId
    return ($owner -and ($global:AZTK_MS_TENANTS -contains $owner))
}

function global:To-Date {
    <# Parse a Graph ISO timestamp to [datetime], or $null. #>
    param($Value)
    if (-not $Value) { return $null }
    try { return [datetime]$Value } catch { return $null }
}

function global:Get-EntraPlans {
    <# Service-plan names present on the tenant (cached), for licence gating. #>
    if (-not $global:AZTK_plans) {
        try {
            $skus = @(Get-GraphAll 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=servicePlans')
            $global:AZTK_plans = @($skus.servicePlans.servicePlanName) | Sort-Object -Unique
        } catch { $global:AZTK_plans = @() }
    }
    $global:AZTK_plans
}

function global:Test-EntraLicence {
    <# True if any of the given service-plan names is present. AAD_PREMIUM = Entra ID P1,
       AAD_PREMIUM_P2 = Entra ID P2. Used to loud-skip P1/P2-only checks. #>
    param([Parameter(Mandatory)][string[]]$Plan)
    $have = Get-EntraPlans
    foreach ($p in $Plan) { if ($have -contains $p) { return $true } }
    return $false
}

function global:Skip-Check {
    <# Return a loud-skip result object (never a silent pass). #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Reason)
    return [pscustomobject]@{ Name = $Name; Status = 'skip'; Detail = $Reason }
}

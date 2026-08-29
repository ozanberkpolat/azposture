#Requires -Version 7.2
<#
  AzPosture: measure an Azure and Entra ID tenant against the AzPosture checklist,
  read-only, on your own machine, under your own sign-in. Nothing leaves the tenant;
  the output is a folder of JSON on your disk.

  Two planes:
    identity  Microsoft Graph, custom PowerShell checks (Global Reader is enough)
    estate    Azure Resource Graph KQL + a few ARM REST checks (Reader on subscriptions)

  The check scripts, the shared helpers and checks.json are assembled by build.py from
  the azure-toolkit source. Do not edit them here; edit the source and rebuild.
#>
Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$script:Root = $PSScriptRoot
$script:Catalog = $null
$script:Weight = @{ critical = 4; high = 3; medium = 2; low = 1 }

function Get-AzPostureCatalog {
    if (-not $script:Catalog) {
        $script:Catalog = Get-Content (Join-Path $script:Root 'checks.json') -Raw | ConvertFrom-Json
    }
    $script:Catalog
}

function Get-AzPostureCheck {
    <#
    .SYNOPSIS
      List the checks in the AzPosture checklist, optionally filtered.
    .EXAMPLE
      Get-AzPostureCheck -Plane Identity -Severity critical, high
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Identity', 'Estate')] [string] $Plane,
        [string[]] $Framework,
        [ValidateSet('critical', 'high', 'medium', 'low')] [string[]] $Severity
    )
    $c = @((Get-AzPostureCatalog).checks)
    if ($Plane) { $p = if ($Plane -eq 'Identity') { 'graph' } else { 'arm' }; $c = @($c | Where-Object plane -eq $p) }
    if ($Framework) { $c = @($c | Where-Object { $Framework -contains $_.tab }) }
    if ($Severity) { $c = @($c | Where-Object { $Severity -contains $_.severity }) }
    $c | Select-Object key, label, tab, domain, severity, plane, min_role, licence
}

function Write-Marker {
    param([string] $Marker, [string] $Text = '', [ConsoleColor] $Color = 'Cyan')
    Write-Host ('AZPOSTURE::{0}' -f $Marker) -ForegroundColor $Color -NoNewline
    if ($Text) { Write-Host (' ' + $Text) } else { Write-Host '' }
}

function New-Finding {
    param($Meta, [string] $Title, [string] $Severity, [string] $Status, $Detail, $Fix, $ResourceId)
    [ordered]@{
        check_key = $Meta.key; code = $Meta.key; framework = $Meta.framework; domain = $Meta.domain
        tab = $Meta.tab; title = $Title; severity = $Severity; status = $Status
        detail = $Detail; fix = $Fix; resource_id = $ResourceId
        min_role = $Meta.min_role; licence = $Meta.licence
        impact = $Meta.impact; best_practice = $Meta.best_practice
    }
}

function Add-CheckFindings {
    <# Port of run-checks.ps1's merge: one check result -> zero or more findings. #>
    param($Findings, $Meta, $Res)
    if ($Res -and $Res.Status -eq 'skip') {
        [void]$Findings.Add((New-Finding $Meta "$($Res.Name)" 'info' 'skip' $Res.Detail $null $null)); return
    }
    $ev = if ($Res -and $Res.PSObject.Properties['Evidence'] -and $Res.Evidence) { "$($Res.Evidence)" } else { $null }
    $items = if ($Res) { @($Res.Items) } else { @() }
    if ($items.Count -eq 0) {
        $t = if ($ev) { "$($Meta.label)" } else { "$($Meta.label) (no issues)" }
        [void]$Findings.Add((New-Finding $Meta $t 'info' 'pass' $ev $null $null)); return
    }
    $cfix = if ($Res.Fix) { $Res.Fix } else { $Meta.fix }
    foreach ($it in $items) {
        $sev = if ($it.Severity) { $it.Severity } elseif ($Res.Severity) { $Res.Severity } else { $Meta.severity }
        $idet = if ($ev -and $it.Detail) { "$ev - $($it.Detail)" } elseif ($ev) { $ev } else { $it.Detail }
        $rid = if ($it.PSObject.Properties['ResourceId'] -and $it.ResourceId) { "$($it.ResourceId)" } else { $null }
        [void]$Findings.Add((New-Finding $Meta "$($it.Title)" $sev 'fail' $idet $cfix $rid))
    }
}

function Invoke-AzPosture {
    <#
    .SYNOPSIS
      Run the AzPosture checklist against a tenant, read-only, and write findings.json.
    .DESCRIPTION
      Signs in as you (interactive browser, or -UseDeviceCode), runs the identity checks
      over Microsoft Graph and the estate checks over Azure Resource Graph, and writes
      findings.json plus summary.json into a timestamped folder. Nothing is uploaded.
      A check that cannot run is reported as skipped with the reason, never as a pass.
    .EXAMPLE
      Invoke-AzPosture
      Signs you in and runs against the tenant you land in.
    .EXAMPLE
      Invoke-AzPosture -TenantId contoso.onmicrosoft.com -Plane Identity -UseDeviceCode
    #>
    [CmdletBinding()]
    param(
        [string] $TenantId,
        [string] $OutputFolder = (Join-Path (Get-Location) 'azposture'),
        [ValidateSet('Both', 'Identity', 'Estate')] [string] $Plane = 'Both',
        [string[]] $Check,
        [switch] $UseDeviceCode,
        [switch] $PassThru
    )

    $cat = Get-AzPostureCatalog
    $all = @($cat.checks)
    if ($Check) {
        $unknown = @($Check | Where-Object { $all.key -notcontains $_ })
        if ($unknown.Count) { throw "Unknown check key(s): $($unknown -join ', '). See Get-AzPostureCheck." }
        $all = @($all | Where-Object { $Check -contains $_.key })
    }
    if ($Plane -eq 'Identity') { $all = @($all | Where-Object plane -eq 'graph') }
    elseif ($Plane -eq 'Estate') { $all = @($all | Where-Object plane -eq 'arm') }

    $custom = @($all | Where-Object engine -eq 'custom')
    $armGraph = @($all | Where-Object engine -eq 'arm-graph')
    $armScript = @($all | Where-Object engine -eq 'arm-script')
    $needsGraph = $custom.Count -gt 0
    $needsArm = ($armGraph.Count + $armScript.Count) -gt 0
    $scopes = @($custom | ForEach-Object { $_.scopes } | Where-Object { $_ } | Sort-Object -Unique)

    $started = Get-Date
    $out = Join-Path $OutputFolder $started.ToString('yyyy-MM-dd-HHmm')
    New-Item -ItemType Directory -Force -Path $out | Out-Null

    Write-Host ''
    Write-Host ('AzPosture {0} · checklist {1} · {2} checks selected' -f $cat.module_version, $cat.catalog_version, $all.Count) -ForegroundColor White
    Write-Host 'read-only · nothing is installed in the tenant · nothing is uploaded' -ForegroundColor DarkGray
    Write-Host ''

    $findings = [System.Collections.ArrayList]::new()

    # No -TenantId: take it from a session that already exists, otherwise from the
    # account's home tenant after the first sign-in. Nothing has to be looked up first.
    if (-not $TenantId) {
        $mg = if (Get-Module -ListAvailable Microsoft.Graph.Authentication) { Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue; Get-MgContext } else { $null }
        if ($mg -and $mg.TenantId) { $TenantId = $mg.TenantId }
        elseif ((Get-Module -ListAvailable Az.Accounts) -and (Import-Module Az.Accounts -PassThru -ErrorAction SilentlyContinue) -and (Get-AzContext)) { $TenantId = (Get-AzContext).Tenant.Id }
    }
    $isGuid = $TenantId -match '^[0-9a-fA-F-]{36}$'

    # ── identity plane sign-in ─────────────────────────────────────────────────
    if ($needsGraph) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        $ctx = Get-MgContext
        $have = if ($ctx) { @($ctx.Scopes) } else { @() }
        $missing = @($scopes | Where-Object { $have -notcontains $_ })
        $sameTenant = $ctx -and ((-not $isGuid) -or ($ctx.TenantId -eq $TenantId))
        if ($ctx -and $sameTenant -and $missing.Count -eq 0) {
            Write-Marker 'CONNECTED' ('Microsoft Graph as {0} (existing session)' -f $ctx.Account) 'Green'
        } else {
            Write-Marker 'SIGNIN' 'Microsoft Graph · sign in as yourself; every scope requested is read-only'
            $tenantArg = if ($TenantId) { @{ TenantId = $TenantId } } else { @{} }
            try {
                if ($UseDeviceCode) { Connect-MgGraph @tenantArg -Scopes $scopes -UseDeviceCode -NoWelcome }
                else { Connect-MgGraph @tenantArg -Scopes $scopes -NoWelcome }
            } catch {
                # The identity checks need admin-consent-only scopes. In a tenant that restricts
                # user consent, a non-admin sees "Approval required" and lands here. Say what
                # gets through instead of leaving a raw AADSTS error on the screen.
                $t = if ($TenantId) { $TenantId } else { 'common' }
                $consent = 'https://login.microsoftonline.com/{0}/v2.0/adminconsent?client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e&scope={1}' -f $t, [uri]::EscapeDataString(($scopes | ForEach-Object { "https://graph.microsoft.com/$_" }) -join ' ')
                Write-Marker 'BLOCKED' 'Microsoft Graph sign-in did not complete.' 'Red'
                Write-Host ''
                Write-Host 'If the dialog said "Approval required": the identity checks need scopes only an' -ForegroundColor Yellow
                Write-Host 'administrator can consent to. Any one of these gets through:' -ForegroundColor Yellow
                Write-Host '  1. Run it as a Global Reader or Global Administrator of the tenant.' -ForegroundColor Yellow
                Write-Host '  2. Have an administrator approve Microsoft Graph Command Line Tools once, for the' -ForegroundColor Yellow
                Write-Host '     exact read-only scopes this run needs. After that any Global Reader can run it:' -ForegroundColor Yellow
                Write-Host ('     ' + $consent) -ForegroundColor Cyan
                Write-Host '  3. Use "Request approval" in the dialog if your tenant offers it, then run again.' -ForegroundColor Yellow
                Write-Host ''
                Write-Host 'Nothing is installed or registered in the tenant by any of these; the app being' -ForegroundColor DarkGray
                Write-Host 'approved is Microsoft''s own command-line tools app, and every scope is read-only.' -ForegroundColor DarkGray
                throw
            }
            if (-not $TenantId) { $TenantId = (Get-MgContext).TenantId; $isGuid = $true }
            Write-Marker 'CONNECTED' ('Microsoft Graph as {0} · tenant {1}' -f (Get-MgContext).Account, $TenantId) 'Green'
        }
        Write-Marker 'SCOPES' ($scopes -join ', ') 'DarkGray'
        . (Join-Path $script:Root 'lib' '_lib.ps1')
    }

    # ── estate plane sign-in: loud skip when it cannot run ─────────────────────
    $armReady = $false; $armReason = $null
    if ($needsArm) {
        $azOk = (Get-Module -ListAvailable Az.Accounts) -and (Get-Module -ListAvailable Az.ResourceGraph)
        if (-not $azOk) {
            $armReason = 'Az.Accounts and Az.ResourceGraph are not installed on this machine. Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser, then run again.'
        } else {
            Import-Module Az.Accounts, Az.ResourceGraph -ErrorAction Stop
            $actx = Get-AzContext
            $sameTenant = $actx -and ((-not $isGuid) -or ($actx.Tenant.Id -eq $TenantId))
            if ($actx -and $sameTenant) {
                Write-Marker 'CONNECTED' ('Azure as {0} (existing session)' -f $actx.Account.Id) 'Green'
            } else {
                Write-Marker 'SIGNIN' 'Azure · the Reader role on your subscriptions is enough'
                $tenantArg = if ($TenantId) { @{ Tenant = $TenantId } } else { @{} }
                if ($UseDeviceCode) { Connect-AzAccount @tenantArg -UseDeviceAuthentication -WarningAction SilentlyContinue | Out-Null }
                else { Connect-AzAccount @tenantArg -WarningAction SilentlyContinue | Out-Null }
                if (-not $TenantId) { $TenantId = (Get-AzContext).Tenant.Id; $isGuid = $true }
                Write-Marker 'CONNECTED' ('Azure as {0} · tenant {1}' -f (Get-AzContext).Account.Id, $TenantId) 'Green'
            }
            . (Join-Path $script:Root 'lib' '_lib-arm.ps1')
            $subs = @(Get-Subs)
            if ($subs.Count -eq 0) {
                $armReason = 'No enabled Azure subscription is readable by this account. Assign the Reader role at subscription or management-group scope, then run again.'
            } else {
                $armReady = $true
                Write-Host ('           {0} subscription(s) readable' -f $subs.Count) -ForegroundColor DarkGray
            }
        }
        if ($armReason) { Write-Marker 'SKIPPED' ('Azure estate · ' + $armReason) 'Yellow' }
    }

    # ── dispatch ───────────────────────────────────────────────────────────────
    $checksDir = Join-Path $script:Root 'checks'
    $i = 0
    foreach ($cc in $custom) {
        $i++; Write-Progress -Id 1 -Activity 'identity' -Status $cc.label -PercentComplete (100 * $i / [Math]::Max(1, $custom.Count))
        try { $res = & (Join-Path $checksDir $cc.script) }
        catch { [void]$findings.Add((New-Finding $cc "$($cc.label) (could not run)" $cc.severity 'skip' "$_" $null $null)); continue }
        Add-CheckFindings $findings $cc $res
    }
    Write-Progress -Id 1 -Activity 'identity' -Completed
    if ($custom.Count) { Write-Host ('identity   {0} checks' -f $custom.Count) -ForegroundColor White }

    $estate = @($armScript) + @($armGraph)
    if ($estate.Count) {
        if (-not $armReady) {
            foreach ($cc in $estate) { [void]$findings.Add((New-Finding $cc "$($cc.label)" 'info' 'skip' $armReason $null $null)) }
            Write-Host ('estate     {0} checks not assessed' -f $estate.Count) -ForegroundColor Yellow
        } else {
            $i = 0
            foreach ($cc in $armScript) {
                $i++; Write-Progress -Id 2 -Activity 'estate' -Status $cc.label -PercentComplete (100 * $i / [Math]::Max(1, $estate.Count))
                try { $res = & (Join-Path $checksDir $cc.script) }
                catch { [void]$findings.Add((New-Finding $cc "$($cc.label) (could not run)" $cc.severity 'skip' "$_" $null $null)); continue }
                Add-CheckFindings $findings $cc $res
            }
            foreach ($cc in $armGraph) {
                $i++; Write-Progress -Id 2 -Activity 'estate' -Status $cc.label -PercentComplete (100 * $i / [Math]::Max(1, $estate.Count))
                try {
                    $rows = Search-Graph $cc.kql
                    $items = @($rows | ForEach-Object {
                        $r = $_; $parts = @()
                        if ($r.PSObject.Properties['detail'] -and $r.detail) { $parts += "$($r.detail)" }
                        if ($r.PSObject.Properties['rtype'] -and $r.rtype) { $parts += (("$($r.rtype)" -split '/')[-1]) }
                        if ($r.PSObject.Properties['rg'] -and $r.rg) { $parts += "$($r.rg)" }
                        if ($r.PSObject.Properties['sub'] -and $r.sub) { $s = "$($r.sub)"; $parts += ('sub ' + $(if ($s.Length -ge 8) { $s.Substring(0, 8) } else { $s })) }
                        [pscustomobject]@{ Title = "$($r.title)"; Detail = ($parts -join ', ')
                            ResourceId = $(if ($r.PSObject.Properties['id'] -and $r.id) { "$($r.id)" } else { $null }) }
                    })
                    $res = [pscustomobject]@{ Name = $cc.label; Severity = $cc.severity; Fix = $cc.fix; Items = $items }
                    Add-CheckFindings $findings $cc $res
                } catch {
                    [void]$findings.Add((New-Finding $cc "$($cc.label) (could not run)" $cc.severity 'skip' "$_" $null $null))
                }
            }
            Write-Progress -Id 2 -Activity 'estate' -Completed
            Write-Host ('estate     {0} checks' -f $estate.Count) -ForegroundColor White
        }
    }

    # ── roll up: one control per check, weighted 4/3/2/1 ───────────────────────
    $byKey = @{}
    foreach ($f in $findings) {
        if (-not $byKey.ContainsKey($f.check_key)) { $byKey[$f.check_key] = @{ status = 'pass'; severity = $null } }
        $c = $byKey[$f.check_key]
        if ($f.status -eq 'fail') { $c.status = 'fail' } elseif ($f.status -eq 'skip' -and $c.status -ne 'fail') { $c.status = 'skip' }
    }
    $meta = @{}; foreach ($m in $all) { $meta[$m.key] = $m }
    $wPass = 0; $wFail = 0; $nPass = 0; $nFail = 0; $nSkip = 0
    foreach ($k in $byKey.Keys) {
        $w = $script:Weight[$meta[$k].severity]; if (-not $w) { $w = 1 }
        switch ($byKey[$k].status) {
            'fail' { $wFail += $w; $nFail++ }
            'pass' { $wPass += $w; $nPass++ }
            default { $nSkip++ }
        }
    }
    $score = if (($wPass + $wFail) -gt 0) { [int][Math]::Round(100 * $wPass / ($wPass + $wFail)) } else { $null }
    $failItems = @($findings | Where-Object status -eq 'fail')
    $sev = [ordered]@{}
    foreach ($s in 'critical', 'high', 'medium', 'low') { $sev[$s] = @($failItems | Where-Object severity -eq $s).Count }

    $summary = [ordered]@{
        module_version = $cat.module_version; catalog_version = $cat.catalog_version; catalog_commit = $cat.catalog_commit
        tenant = $TenantId; started = $started.ToString('o'); finished = (Get-Date).ToString('o')
        plane = $Plane; checks_selected = $all.Count
        controls = [ordered]@{ pass = $nPass; fail = $nFail; skip = $nSkip }
        failing_items_by_severity = $sev
        score = $score
        estate_assessed = $armReady; estate_skip_reason = $armReason
    }

    $findings | ConvertTo-Json -Depth 8 | Out-File (Join-Path $out 'findings.json') -Encoding utf8
    $summary | ConvertTo-Json -Depth 6 | Out-File (Join-Path $out 'summary.json') -Encoding utf8

    Write-Host ''
    Write-Host (('{0} critical · {1} high · {2} medium · {3} low' -f $sev.critical, $sev.high, $sev.medium, $sev.low) + ('   ({0} controls pass, {1} fail, {2} not assessed)' -f $nPass, $nFail, $nSkip)) -ForegroundColor White
    if ($null -ne $score) { Write-Host ('score      {0} / 100   (85+ strong · 60 to 84 fair · under 60 at risk)' -f $score) -ForegroundColor White }
    Write-Marker 'DONE' '' 'Green'
    Write-Host ('wrote      {0}' -f (Join-Path $out 'findings.json')) -ForegroundColor Green
    Write-Host ('           {0}' -f (Join-Path $out 'summary.json')) -ForegroundColor Green
    Write-Host 'next       open the report, then book the readout if you want a second opinion on it' -ForegroundColor DarkGray
    Write-Host ''

    if ($PassThru) { [pscustomobject]$summary }
}

Export-ModuleMember -Function Invoke-AzPosture, Get-AzPostureCheck

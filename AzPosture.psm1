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
      Run the AzPosture checklist against a tenant, read-only, and write an HTML report
      plus the findings as JSON.
    .DESCRIPTION
      Signs in ONCE as you through Microsoft's own Azure PowerShell app (browser, or
      -UseDeviceCode). That app is pre-authorised in every tenant, so there is no consent
      dialog, and a Global Reader is enough. The same sign-in serves both planes: its
      Microsoft Graph token runs the identity checks, its Azure context runs the estate
      checks. Findings and summary are written to a timestamped folder; nothing is
      uploaded. A check that cannot run is reported as skipped with the reason.

      -GraphConsent uses Microsoft Graph Command Line Tools with explicit scopes instead,
      for tenants where Azure PowerShell sign-in is blocked by policy. That route needs
      an administrator's consent.
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
        [switch] $GraphConsent,
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

    # ── one sign-in for both planes, through Microsoft's own Azure PowerShell app ────
    # That first-party app is pre-authorised in every tenant: no consent dialog, and a
    # Global Reader is enough. Its session yields a Microsoft Graph token carrying what
    # your sign-in can read; a check needing a scope the token lacks loud-skips. This is
    # the route the toolkit itself uses. -GraphConsent is the explicit-scopes alternative.
    $azOk = [bool](Get-Module -ListAvailable Az.Accounts)
    $azReady = $false
    if (($needsGraph -and -not $GraphConsent) -or $needsArm) {
        if (-not $azOk) {
            if ($needsGraph -and -not $GraphConsent) { throw 'Az.Accounts is required for sign-in. Install-Module Az.Accounts -Scope CurrentUser, then run again (or use -GraphConsent).' }
        } else {
            Import-Module Az.Accounts -ErrorAction Stop
            $actx = Get-AzContext
            $sameTenant = $actx -and ((-not $isGuid) -or ($actx.Tenant.Id -eq $TenantId))
            if ($actx -and $sameTenant) {
                Write-Marker 'CONNECTED' ('Azure as {0} (existing session)' -f $actx.Account.Id) 'Green'
            } else {
                Write-Marker 'SIGNIN' 'Azure · Microsoft''s own Azure PowerShell app, your identity, read-only use · no consent prompt'
                $tenantArg = if ($TenantId) { @{ Tenant = $TenantId } } else { @{} }
                if ($UseDeviceCode) { Connect-AzAccount @tenantArg -UseDeviceAuthentication -WarningAction SilentlyContinue | Out-Null }
                else { Connect-AzAccount @tenantArg -WarningAction SilentlyContinue | Out-Null }
                $actx = Get-AzContext
                Write-Marker 'CONNECTED' ('Azure as {0}' -f $actx.Account.Id) 'Green'
            }
            if (-not $TenantId) { $TenantId = $actx.Tenant.Id; $isGuid = $true }
            Write-Host ('           tenant {0}' -f $TenantId) -ForegroundColor DarkGray
            $azReady = $true
        }
    }

    if ($needsGraph) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        if ($azReady -and -not $GraphConsent) {
            $tok = Get-AzAccessToken -ResourceTypeName MSGraph -ErrorAction Stop
            $secure = if ($tok.Token -is [securestring]) { $tok.Token } else { ConvertTo-SecureString $tok.Token -AsPlainText -Force }
            Connect-MgGraph -AccessToken $secure -NoWelcome
            Write-Marker 'CONNECTED' 'Microsoft Graph · through the same sign-in' 'Green'
        } else {
            $ctx = Get-MgContext
            $have = if ($ctx) { @($ctx.Scopes) } else { @() }
            $missing = @($scopes | Where-Object { $have -notcontains $_ })
            $sameTenant = $ctx -and ((-not $isGuid) -or ($ctx.TenantId -eq $TenantId))
            if ($ctx -and $sameTenant -and $missing.Count -eq 0) {
                Write-Marker 'CONNECTED' ('Microsoft Graph as {0} (existing session)' -f $ctx.Account) 'Green'
            } else {
                Write-Marker 'SIGNIN' 'Microsoft Graph · Microsoft Graph Command Line Tools, explicit read-only scopes · needs admin consent'
                $tenantArg = if ($TenantId) { @{ TenantId = $TenantId } } else { @{} }
                try {
                    if ($UseDeviceCode) { Connect-MgGraph @tenantArg -Scopes $scopes -UseDeviceCode -NoWelcome }
                    else { Connect-MgGraph @tenantArg -Scopes $scopes -NoWelcome }
                } catch {
                    $t = if ($TenantId) { $TenantId } else { 'common' }
                    $consent = 'https://login.microsoftonline.com/{0}/v2.0/adminconsent?client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e&scope={1}' -f $t, [uri]::EscapeDataString(($scopes | ForEach-Object { "https://graph.microsoft.com/$_" }) -join ' ')
                    Write-Marker 'BLOCKED' 'Microsoft Graph sign-in did not complete.' 'Red'
                    Write-Host ''
                    Write-Host 'The default route (no -GraphConsent) signs in through Azure PowerShell and needs no' -ForegroundColor Yellow
                    Write-Host 'consent at all; try that first. If this route is required, an administrator can' -ForegroundColor Yellow
                    Write-Host 'approve Microsoft Graph Command Line Tools once for these read-only scopes:' -ForegroundColor Yellow
                    Write-Host ('  ' + $consent) -ForegroundColor Cyan
                    throw
                }
                if (-not $TenantId) { $TenantId = (Get-MgContext).TenantId; $isGuid = $true }
                Write-Marker 'CONNECTED' ('Microsoft Graph as {0}' -f (Get-MgContext).Account) 'Green'
            }
        }
        $got = @((Get-MgContext).Scopes)
        Write-Marker 'SCOPES' ($(if ($got.Count) { $got -join ', ' } else { 'as granted to your sign-in' })) 'DarkGray'
        . (Join-Path $script:Root 'lib' '_lib.ps1')
    }

    # ── estate plane: needs Az.ResourceGraph and a readable subscription, else loud skip ──
    $armReady = $false; $armReason = $null
    if ($needsArm) {
        if (-not $azReady) {
            $armReason = 'Az.Accounts is not installed on this machine. Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser, then run again.'
        } elseif (-not (Get-Module -ListAvailable Az.ResourceGraph)) {
            $armReason = 'Az.ResourceGraph is not installed on this machine. Install-Module Az.ResourceGraph -Scope CurrentUser, then run again.'
        } else {
            Import-Module Az.ResourceGraph -ErrorAction Stop
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
    $report = New-AzPostureReport -Path $out -Findings $findings -Summary ([pscustomobject]$summary)

    Write-Host ''
    Write-Host (('{0} critical · {1} high · {2} medium · {3} low' -f $sev.critical, $sev.high, $sev.medium, $sev.low) + ('   ({0} controls pass, {1} fail, {2} not assessed)' -f $nPass, $nFail, $nSkip)) -ForegroundColor White
    if ($null -ne $score) { Write-Host ('score      {0} / 100   (85+ strong · 60 to 84 fair · under 60 at risk)' -f $score) -ForegroundColor White }
    Write-Marker 'DONE' '' 'Green'
    Write-Host ('report     {0}' -f $report) -ForegroundColor Green
    Write-Host ('wrote      {0}' -f (Join-Path $out 'findings.json')) -ForegroundColor Green
    Write-Host ('           {0}' -f (Join-Path $out 'summary.json')) -ForegroundColor Green
    Write-Host 'next       open the report in a browser; it is yours to keep, print or forward' -ForegroundColor DarkGray
    Write-Host ''

    if ($PassThru) { [pscustomobject]$summary }
}

# ── the report ────────────────────────────────────────────────────────────────
# One self-contained interactive HTML file: charts are hand-drawn SVG and the
# filtering is a few lines of vanilla JS, so nothing is fetched at any point. It
# opens on a machine with no internet, and it prints to A4 with every row expanded.

$script:SevColor = @{ critical = '#C0263A'; high = '#DD6B3D'; medium = '#D9A521'; low = '#6B7787'; pass = '#1E9E6A'; skip = '#9AA4B2' }
$script:SevLabel = @{ critical = 'Critical'; high = 'High'; medium = 'Medium'; low = 'Low' }
$script:SevDesc = [ordered]@{
    critical = 'Directly exploitable or exposing data today. Address immediately.'
    high     = 'A significant weakness attackers actively look for. Address within days.'
    medium   = 'A real gap that compounds other risks. Plan into the next change window.'
    low      = 'Housekeeping and hygiene. Batch into routine maintenance.'
}

function Enc {
    param($Text)
    if ($null -eq $Text) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-ScoreBand {
    param($Score)
    if ($null -eq $Score) { return @{ color = '#6B7787'; word = 'not yet scored'; text = 'n/a'; pct = 0 } }
    if ($Score -ge 85) { return @{ color = '#1E9E6A'; word = 'a strong posture'; text = "$Score"; pct = $Score } }
    if ($Score -ge 60) { return @{ color = '#D9A521'; word = 'a fair posture'; text = "$Score"; pct = $Score } }
    @{ color = '#C0263A'; word = 'an at-risk posture'; text = "$Score"; pct = $Score }
}

function Get-ControlRollup {
    <# Findings collapse to one row per check: the control is what gets fixed, the
       findings under it are the resources it affects. A finding's own title names the
       RESOURCE, so the control's name comes from the catalog; only a key the catalog does
       not know falls back to the first finding's title. #>
    param($Items, $Labels)
    $groups = $Items | Group-Object check_key
    $rows = foreach ($g in $groups) {
        $first = $g.Group[0]
        $label = $(if ($Labels -and $Labels.ContainsKey($g.Name)) { $Labels[$g.Name] } else { $first.title })
        [pscustomobject]@{
            Key = $g.Name; Title = $label; Severity = $first.severity
            Domain = $(if ($first.domain) { $first.domain } else { 'Other' })
            Impact = $first.impact; Fix = $first.fix; BestPractice = $first.best_practice
            Status = $first.status; MinRole = $first.min_role; Licence = $first.licence
            Count = $g.Count; Items = $g.Group
            Weight = $(if ($script:Weight[$first.severity]) { $script:Weight[$first.severity] } else { 1 })
        }
    }
    @($rows | Sort-Object -Property @{ Expression = 'Weight'; Descending = $true }, @{ Expression = 'Count'; Descending = $true }, 'Title')
}

function Get-ResourceRollup {
    <# The estate side of a run names ARM resources, so the same findings regroup by
       resource: which ones carry the most failing controls, worst severity first.
       Identity findings carry no resource id and are left out by design. #>
    param($Fails)
    $withId = @($Fails | Where-Object { $_.resource_id })
    if (-not $withId.Count) { return @() }
    $rows = foreach ($g in ($withId | Group-Object resource_id)) {
        $id = $g.Name
        $leaf = ($id -split '/')[-1]
        $rg = ''
        $parts = $id -split '/'
        for ($i = 0; $i -lt $parts.Count - 1; $i++) { if ($parts[$i] -eq 'resourceGroups') { $rg = $parts[$i + 1] } }
        $worst = @($g.Group | Sort-Object { -$(if ($script:Weight[$_.severity]) { $script:Weight[$_.severity] } else { 1 }) })[0].severity
        [pscustomobject]@{
            Id = $id; Name = $(if ($leaf) { $leaf } else { $id }); Group = $rg
            Controls = @($g.Group | Select-Object -ExpandProperty check_key -Unique).Count
            Severity = $worst
            Weight = (@($g.Group | ForEach-Object { $(if ($script:Weight[$_.severity]) { $script:Weight[$_.severity] } else { 1 }) } | Measure-Object -Sum).Sum)
        }
    }
    @($rows | Sort-Object -Property @{ Expression = 'Weight'; Descending = $true }, @{ Expression = 'Controls'; Descending = $true }, 'Name')
}

function New-AzPostureDonut {
    <# A severity ring drawn as stroked arcs on one circle: no library, no canvas. #>
    param($Counts, [int] $Total)
    if ($Total -le 0) { return '' }
    $r = 54; $c = 2 * [Math]::PI * $r
    $off = 0; $arcs = ''
    foreach ($s in 'critical', 'high', 'medium', 'low') {
        $n = [int]$Counts[$s]
        if ($n -le 0) { continue }
        $len = $c * $n / $Total
        $arcs += ('<circle class="arc" cx="70" cy="70" r="{0}" fill="none" stroke="{1}" stroke-width="18" stroke-dasharray="{2:F2} {3:F2}" stroke-dashoffset="{4:F2}" transform="rotate(-90 70 70)"><title>{5}: {6}</title></circle>' -f
            $r, $script:SevColor[$s], $len, ($c - $len), (-$off), $script:SevLabel[$s], $n)
        $off += $len
    }
    ('<svg class="donut" viewBox="0 0 140 140" width="140" height="140" role="img" aria-label="failing findings by severity">' +
        ('<circle cx="70" cy="70" r="{0}" fill="none" stroke="#EDF0F5" stroke-width="18"></circle>' -f $r) + $arcs +
        ('<text x="70" y="66" text-anchor="middle" class="dnum">{0}</text>' -f $Total) +
        '<text x="70" y="84" text-anchor="middle" class="dlbl">findings</text></svg>')
}

function New-AzPostureGauge {
    <# The score as a 240 degree arc, filled to the score. #>
    param($Band)
    $pct = [Math]::Max(0, [Math]::Min(100, [int]$Band.pct))
    $r = 62; $sweep = 240.0
    $len = [Math]::PI * $r * ($sweep / 180.0)
    $fill = $len * $pct / 100.0
    ('<svg class="gauge" viewBox="0 0 160 116" width="160" height="116" role="img" aria-label="posture score">' +
        ('<path d="M 18 96 A {0} {0} 0 1 1 142 96" fill="none" stroke="#EDF0F5" stroke-width="13" stroke-linecap="round"></path>' -f $r) +
        ('<path d="M 18 96 A {0} {0} 0 1 1 142 96" fill="none" stroke="{1}" stroke-width="13" stroke-linecap="round" stroke-dasharray="{2:F2} {3:F2}"></path>' -f $r, $Band.color, $fill, ($len - $fill)) +
        ('<text x="80" y="80" text-anchor="middle" class="gnum" fill="{0}">{1}</text>' -f $Band.color, $Band.text) +
        '<text x="80" y="100" text-anchor="middle" class="glbl">posture score</text></svg>')
}

function New-AzPostureReport {
    <#
    .SYNOPSIS
      Render a run's findings as one self-contained, interactive HTML report.
    .DESCRIPTION
      Invoke-AzPosture writes this alongside the JSON, so you rarely need to call it.
      Point it at a run folder to re-render one you already have, or one you were sent.
      Nothing is fetched: the charts are inline SVG and the filtering is inline script,
      so the file opens offline and prints with every row expanded.
    .EXAMPLE
      New-AzPostureReport -Path .\azposture-2026-08-30
    #>
    [CmdletBinding()]
    param(
        # Folder holding findings.json and summary.json. Defaults to the working directory.
        [Parameter(Position = 0)] [string] $Path = '.',
        # Where to write the HTML. Defaults to report.html inside -Path.
        [string] $OutFile,
        # In-memory objects, used by Invoke-AzPosture instead of reading the JSON back.
        $Findings,
        $Summary
    )

    if (-not $Findings) {
        $fp = Join-Path $Path 'findings.json'
        if (-not (Test-Path $fp)) { throw "No findings.json in $Path. Run Invoke-AzPosture first, or pass -Path to a run folder." }
        $Findings = Get-Content $fp -Raw | ConvertFrom-Json
    }
    if (-not $Summary) {
        $sp = Join-Path $Path 'summary.json'
        if (-not (Test-Path $sp)) { throw "No summary.json in $Path." }
        $Summary = Get-Content $sp -Raw | ConvertFrom-Json
    }
    if (-not $OutFile) { $OutFile = Join-Path $Path 'report.html' }

    $all = @($Findings)
    $fails = @($all | Where-Object status -eq 'fail')
    $labels = @{}
    try { foreach ($c in (Get-AzPostureCatalog).checks) { $labels[$c.key] = $c.label } } catch { }
    $failControls = Get-ControlRollup $fails $labels
    $allControls = Get-ControlRollup $all $labels
    $sev = $Summary.failing_items_by_severity
    $counts = @{}
    foreach ($s in 'critical', 'high', 'medium', 'low') {
        $counts[$s] = $(if ($sev -and $sev.PSObject.Properties[$s]) { [int]$sev.$s } else { 0 })
    }
    $nPass = [int]$Summary.controls.pass; $nFail = [int]$Summary.controls.fail; $nSkip = [int]$Summary.controls.skip
    $score = $(if ($null -ne $Summary.score) { [int]$Summary.score } else { $null })
    $band = Get-ScoreBand $score
    $when = $(try { ([datetime]$Summary.finished).ToUniversalTime().ToString('dd MMM yyyy') } catch { (Get-Date).ToString('dd MMM yyyy') })
    $tenant = $(if ($Summary.tenant) { $Summary.tenant } else { 'this tenant' })
    $planeWord = switch ("$($Summary.plane)") { 'Identity' { 'Entra ID only' } 'Estate' { 'the Azure estate only' } default { 'Entra ID and the Azure estate' } }

    $b = [System.Text.StringBuilder]::new()
    $add = { param($s) [void]$b.Append($s) }

    # ── the header, sticky, with the score always in view ─────────────────────
    & $add ('<header class="top"><div class="brand"><span class="mark">AzPosture</span><span class="sep"></span><span class="tn">{0}</span></div>' -f (Enc $tenant) +
        ('<div class="topright"><span class="scorepill" style="--c:{0}">{1}<i>/100</i></span><span class="meta">{2} &middot; {3}</span>' -f $band.color, $band.text, (Enc $when), (Enc $planeWord)) +
        '<button type="button" class="btn" onclick="window.print()">Print</button></div></header>')

    # ── hero: gauge, donut, tally ─────────────────────────────────────────────
    $totalFindings = $fails.Count
    $stats = ''
    foreach ($s in 'critical', 'high', 'medium', 'low') {
        $stats += ('<button type="button" class="stat" data-jump="{0}"><span class="num" style="color:{1}">{2}</span><span class="lbl">{3}</span></button>' -f
            $s, $script:SevColor[$s], $counts[$s], $script:SevLabel[$s])
    }
    & $add ('<section class="hero"><div class="eyebrow">Findings</div><h1>Azure and Entra ID posture</h1>' +
        ('<p class="sub">Measured against the AzPosture checklist, read-only, on {0}. {1}</p>' -f (Enc $when), (Enc $planeWord)) +
        '<div class="charts">' +
        ('<div class="chart"><div class="cwrap">{0}</div><div class="cside"><div class="cw">{1}</div><p class="cnote">Above 85 is strong, 60 to 84 fair, below 60 at risk. The score is the share of severity weight that passes, so it answers how much of what matters is in place.</p></div></div>' -f (New-AzPostureGauge $band), (Enc $band.word)) +
        ('<div class="chart"><div class="cwrap">{0}</div><div class="cside"><div class="row">{1}</div><p class="cnote">Click a severity to filter the controls below.</p></div></div>' -f (New-AzPostureDonut $counts $totalFindings), $stats) +
        '</div>' +
        ('<div class="tally"><b>{0}</b> controls assessed &middot; <b>{1}</b> pass &middot; <b>{2}</b> fail &middot; <b>{3}</b> not assessed &middot; checklist <b>{4}</b></div>' -f ($nPass + $nFail), $nPass, $nFail, $nSkip, (Enc $Summary.catalog_version)) +
        '</section>')

    # ── executive summary ─────────────────────────────────────────────────────
    $sentences = @()
    if ($nFail -eq 0) {
        $sentences += 'No controls are failing in the areas assessed. The checklist moves as the platform does, so this is a statement about today, not a permanent one.'
    } else {
        $s1 = ('<b>{0}</b> of <b>{1}</b> assessed controls are failing' -f $nFail, ($nPass + $nFail))
        if ($fails.Count -gt $nFail) { $s1 += (' across {0} individual findings' -f $fails.Count) }
        $lead = @()
        if ($counts['critical'] -gt 0) { $lead += ('<b>{0} critical</b>' -f $counts['critical']) }
        if ($counts['high'] -gt 0) { $lead += ('<b>{0} high-severity</b>' -f $counts['high']) }
        if ($lead.Count) { $s1 += ', including ' + ($lead -join ' and ') + ' items that should be addressed first' }
        $sentences += ($s1 + '.')
        if ($null -ne $score) {
            $sentences += ('The weighted posture score is <b>{0} out of 100</b>, {1}. Severity is weighted 4, 3, 2 and 1, so closing one critical item moves the score as far as closing four low ones.' -f $score, $band.word)
        }
    }
    if ($nSkip -gt 0) {
        $reason = $(if ($Summary.estate_skip_reason) { ' ' + [string]$Summary.estate_skip_reason } else { '' })
        $sentences += ('<b>{0}</b> controls were not assessed.{1}' -f $nSkip, (Enc $reason))
    }
    & $add ('<section class="block"><h2>Executive summary</h2><p class="lead">{0}</p></section>' -f ($sentences -join ' '))

    # ── by domain: a bar per domain, longest first ────────────────────────────
    if ($failControls.Count) {
        $doms = $failControls | Group-Object Domain | Sort-Object { -(@($_.Group | Measure-Object Weight -Sum).Sum) }
        $max = @($doms | ForEach-Object { (@($_.Group | Measure-Object Weight -Sum).Sum) } | Measure-Object -Maximum).Maximum
        $bars = ''
        foreach ($d in $doms) {
            $w = (@($d.Group | Measure-Object Weight -Sum).Sum)
            $worst = @($d.Group | Sort-Object -Property @{ Expression = 'Weight'; Descending = $true })[0].Severity
            $bars += ('<button type="button" class="bar" data-domain="{0}"><span class="bl">{1}</span><span class="bt"><i style="width:{2}%;background:{3}"></i></span><span class="bv">{4}</span></button>' -f
                (Enc $d.Name), (Enc $d.Name), [Math]::Round(100 * $w / [Math]::Max($max, 1)), $script:SevColor[$worst], $d.Count)
        }
        & $add ('<section class="block"><h2>Where it is concentrated</h2><p class="secsub">Failing controls by domain, weighted by severity. Click a domain to filter.</p><div class="bars">{0}</div></section>' -f $bars)
    }

    # ── the resources carrying it ─────────────────────────────────────────────
    $resources = Get-ResourceRollup $fails
    if ($resources.Count) {
        $top = @($resources | Select-Object -First 12)
        $maxW = ($top | Measure-Object Weight -Maximum).Maximum
        $rrows = ''
        foreach ($r in $top) {
            $rrows += ('<button type="button" class="res" data-res="{0}"><span class="rn">{1}</span><span class="rg">{2}</span><span class="bt"><i style="width:{3}%;background:{4}"></i></span><span class="rv">{5}</span></button>' -f
                (Enc $r.Name), (Enc $r.Name), (Enc $r.Group), [Math]::Round(100 * $r.Weight / [Math]::Max($maxW, 1)),
                $script:SevColor[$r.Severity], $(if ($r.Controls -eq 1) { '1 control' } else { "$($r.Controls) controls" }))
        }
        $more = $(if ($resources.Count -gt $top.Count) { '<p class="pmore">{0} further resources are named in the findings below.</p>' -f ($resources.Count - $top.Count) } else { '' })
        & $add ('<section class="block"><h2>The resources carrying it</h2><p class="secsub">{0} Azure resources are named by a failing control. These carry the most, weighted by severity. Click one to see every control that names it.</p><div class="bars">{1}</div>{2}</section>' -f $resources.Count, $rrows, $more)
    }

    # ── top priorities ────────────────────────────────────────────────────────
    if ($failControls.Count) {
        $critHigh = @($failControls | Where-Object { $_.Severity -in 'critical', 'high' }).Count
        $top = @($failControls | Select-Object -First ([Math]::Max(8, $critHigh)))
        $items = ''; $i = 0
        foreach ($c in $top) {
            $i++
            $items += ('<div class="prio"><div class="pnum">{0}</div><div class="pbody">' -f $i +
                ('<div class="phead"><span class="chip" style="--c:{0}">{1}</span><span class="pt">{2}</span>{3}</div>' -f
                    $script:SevColor[$c.Severity], $script:SevLabel[$c.Severity], (Enc $c.Title),
                    $(if ($c.Count -gt 1) { '<span class="pn">affects {0} resources</span>' -f $c.Count } else { '' })) +
                $(if ($c.Impact) { '<p class="pimp">{0}</p>' -f (Enc $c.Impact) } else { '' }) +
                $(if ($c.Fix) { '<p class="pact"><b>Action</b> {0}</p>' -f (Enc $c.Fix) } else { '' }) +
                $(if ($c.BestPractice) { '<p class="pbp"><b>The target, and why that one</b> {0}</p>' -f (Enc $c.BestPractice) } else { '' }) +
                '</div></div>')
        }
        $more = $(if ($top.Count -lt $failControls.Count) { '<p class="pmore">{0} further failing controls are in the table below.</p>' -f ($failControls.Count - $top.Count) } else { '' })
        & $add ('<section class="block"><h2>What to fix first</h2><p class="secsub">Ordered by severity weight, then by how many resources each one affects.</p>{0}{1}</section>' -f $items, $more)
    }

    # ── every control, filterable, expandable ─────────────────────────────────
    $domainOpts = @($allControls | Select-Object -ExpandProperty Domain -Unique | Sort-Object | ForEach-Object { '<option value="{0}">{0}</option>' -f (Enc $_) }) -join ''
    $rows = ''
    foreach ($c in $allControls) {
        $statusChip = switch ($c.Status) {
            'fail' { '<span class="chip" style="--c:{0}">{1}</span>' -f $script:SevColor[$c.Severity], $script:SevLabel[$c.Severity] }
            'pass' { '<span class="chip" style="--c:#1E9E6A">Pass</span>' }
            default { '<span class="chip" style="--c:#9AA4B2">Not assessed</span>' }
        }
        $res = ''
        if ($c.Status -eq 'fail') {
            $lis = @($c.Items | ForEach-Object {
                    '<li>{0}{1}</li>' -f (Enc $_.title), $(if ($_.detail) { '<span class="fd">{0}</span>' -f (Enc $_.detail) } else { '' })
                })
            $res = '<div class="dsec"><h4>Affected</h4><ul class="flist">{0}</ul></div>' -f ($lis -join '')
        } elseif ($c.Items[0].detail) {
            $res = '<div class="dsec"><h4>Why not assessed</h4><p>{0}</p></div>' -f (Enc $c.Items[0].detail)
        }
        $detail = ('<div class="det">' +
            $(if ($c.Impact) { '<div class="dsec"><h4>Why it matters</h4><p>{0}</p></div>' -f (Enc $c.Impact) } else { '' }) +
            $(if ($c.BestPractice) { '<div class="dsec"><h4>The target, and why that one</h4><p>{0}</p></div>' -f (Enc $c.BestPractice) } else { '' }) +
            $(if ($c.Fix) { '<div class="dsec"><h4>Action</h4><p>{0}</p></div>' -f (Enc $c.Fix) } else { '' }) +
            $res +
            ('<div class="dmeta"><span>key <b>{0}</b></span><span>domain <b>{1}</b></span>{2}{3}</div>' -f
                (Enc $c.Key), (Enc $c.Domain),
                $(if ($c.MinRole) { '<span>role <b>{0}</b></span>' -f (Enc $c.MinRole) } else { '' }),
                $(if ($c.Licence) { '<span>licence <b>{0}</b></span>' -f (Enc $c.Licence) } else { '' })) +
            '</div>')
        $idx = "$($c.Title) $($c.Domain) $($c.Key)"
        foreach ($it in ($c.Items | Select-Object -First 40)) { $idx += " $($it.title) $($it.detail) $($it.resource_id)" }
        $rows += ('<div class="ctl" data-status="{0}" data-sev="{1}" data-domain="{2}" data-text="{3}">' -f
            $c.Status, $c.Severity, (Enc $c.Domain), (Enc ($idx.ToLower())) +
            ('<button type="button" class="chead" aria-expanded="false">{0}<span class="ct">{1}</span><span class="cd">{2}</span><span class="cn">{3}</span><span class="carrow" aria-hidden="true"></span></button>' -f
                $statusChip, (Enc $c.Title), (Enc $c.Domain),
                $(if ($c.Status -eq 'fail' -and $c.Count -gt 1) { "$($c.Count) resources" } elseif ($c.Status -eq 'fail') { '1 resource' } else { '' })) +
            $detail + '</div>')
    }
    & $add ('<section class="block" id="controls"><h2>Every control</h2><p class="secsub">All {0} controls the run selected. Open one for the reasoning, the action and the resources it names.</p>' -f $allControls.Count +
        '<div class="filters"><div class="chips">' +
        '<button type="button" class="fchip on" data-f="status" data-v="fail">Failing</button>' +
        '<button type="button" class="fchip" data-f="status" data-v="pass">Passing</button>' +
        '<button type="button" class="fchip" data-f="status" data-v="skip">Not assessed</button>' +
        '<span class="fgap"></span>' +
        '<button type="button" class="fchip" data-f="sev" data-v="critical">Critical</button>' +
        '<button type="button" class="fchip" data-f="sev" data-v="high">High</button>' +
        '<button type="button" class="fchip" data-f="sev" data-v="medium">Medium</button>' +
        '<button type="button" class="fchip" data-f="sev" data-v="low">Low</button>' +
        '</div><div class="frow">' +
        ('<select id="fdomain" aria-label="Filter by domain"><option value="">Every domain</option>{0}</select>' -f $domainOpts) +
        '<input id="fsearch" type="search" placeholder="Search controls" aria-label="Search controls">' +
        '<span class="fcount" id="fcount"></span>' +
        '<button type="button" class="btn ghost" id="fexpand">Expand all</button>' +
        '</div></div>' +
        ('<div class="ctls">{0}</div><p class="empty" id="fempty" hidden>Nothing matches those filters.</p></section>' -f $rows))

    # ── methodology ───────────────────────────────────────────────────────────
    $sevRows = ''
    foreach ($k in $script:SevDesc.Keys) {
        $sevRows += ('<div class="mrow"><span class="chip" style="--c:{0}">{1}</span><span>{2}</span></div>' -f $script:SevColor[$k], $script:SevLabel[$k], $script:SevDesc[$k])
    }
    & $add ('<section class="block"><h2>How this was measured</h2>' +
        ('<p class="secsub">Read-only throughout. The run used Microsoft Graph and Azure Resource Graph under the signed-in account, wrote to this machine only, and changed nothing in the tenant. Checklist <b>{0}</b>, module <b>{1}</b>, run finished {2}.</p>' -f (Enc $Summary.catalog_version), (Enc $Summary.module_version), (Enc $when)) +
        '<p class="secsub">The posture score is the share of severity weight that passes: each control counts 4, 3, 2 or 1 by its severity, so the score answers "how much of what matters is in place", not "how many boxes are ticked". A control that could not be assessed is left out of the score entirely rather than counted as a pass.</p>' +
        $sevRows + '</section>')

    $doc = ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width, initial-scale=1">' +
        ('<title>{0}, AzPosture findings, {1}</title>' -f (Enc $tenant), (Enc $when)) +
        $script:ReportCss + '</head><body><div class="page">' + $b.ToString() +
        ('<footer><span>Generated {0} by AzPosture {1}, checklist {2}</span><span>Run on your own machine. Nothing left the tenant.</span></footer>' -f (Enc $when), (Enc $Summary.module_version), (Enc $Summary.catalog_version)) +
        '</div>' + $script:ReportJs + '</body></html>')

    [System.IO.File]::WriteAllText($OutFile, $doc, [System.Text.UTF8Encoding]::new($false))
    (Resolve-Path $OutFile).Path
}

$script:ReportCss = @'
<style>
  :root{--ink:#151A22;--muted:#59616E;--faint:#8A93A0;--line:#E7EAF0;--paper:#F4F5F8;--card:#fff;
    --brand:#5B3FD8;--brand-soft:#F0EDFD;
    --sans:system-ui,-apple-system,"Segoe UI Variable Text","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    --mono:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace}
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.55;
    -webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums}
  .page{max-width:1000px;margin:0 auto;padding:0 24px 70px}
  button{font:inherit;color:inherit;background:none;border:0;cursor:pointer}
  :where(button,select,input,a):focus-visible{outline:2px solid var(--brand);outline-offset:2px;border-radius:6px}

  .top{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:16px;
    flex-wrap:wrap;padding:12px 0;margin-bottom:22px;background:rgba(244,245,248,.92);backdrop-filter:blur(8px);
    border-bottom:1px solid var(--line)}
  .brand{display:flex;align-items:center;gap:12px;min-width:0}
  .mark{font-weight:700;letter-spacing:-.01em}
  .sep{width:1px;height:14px;background:var(--line)}
  .tn{color:var(--muted);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .topright{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  .scorepill{font-weight:700;font-size:15px;color:var(--c);border:1px solid var(--c);border-radius:999px;padding:2px 12px}
  .scorepill i{font-style:normal;font-weight:500;font-size:11px;opacity:.75}
  .meta{color:var(--faint);font-size:12px}
  .btn{border:1px solid var(--line);background:var(--card);border-radius:999px;padding:6px 16px;font-size:13px;font-weight:600}
  .btn:hover{border-color:var(--brand);color:var(--brand)}
  .btn.ghost{background:none}

  .hero{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:32px 36px 26px;margin-bottom:22px}
  .eyebrow{text-transform:uppercase;letter-spacing:.2em;font-size:11px;color:var(--brand);font-weight:600}
  h1{font-size:34px;font-weight:680;letter-spacing:-.02em;line-height:1.1;margin:10px 0 4px}
  .sub{color:var(--muted);margin:0 0 8px}
  .charts{display:flex;gap:44px;flex-wrap:wrap;margin:14px 0 22px}
  .chart{display:flex;gap:20px;align-items:center;min-width:300px;flex:1}
  .cwrap{flex:none}
  .cside{min-width:0}
  .cw{font-weight:640;font-size:15px;margin-bottom:4px}
  .cnote{margin:0;color:var(--muted);font-size:12.5px;line-height:1.5;max-width:34ch}
  .gnum{font-size:34px;font-weight:700;font-family:var(--sans)}
  .glbl,.dlbl{font-size:9px;letter-spacing:.14em;text-transform:uppercase;fill:#8A93A0;font-weight:600;font-family:var(--sans)}
  .dnum{font-size:26px;font-weight:700;fill:#151A22;font-family:var(--sans)}
  .arc{transition:opacity .2s}
  .row{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:8px}
  .stat{text-align:left;padding:2px 6px 2px 0;border-radius:8px}
  .stat:hover .lbl{color:var(--brand)}
  .stat .num{display:block;font-weight:680;font-size:24px;letter-spacing:-.02em}
  .stat .lbl{display:block;text-transform:uppercase;letter-spacing:.13em;font-size:9.5px;color:var(--faint);margin-top:2px;font-weight:600}
  .tally{border-top:1px solid var(--line);padding-top:14px;color:var(--muted);font-size:13px}
  .tally b{color:var(--ink);font-weight:600}

  .block{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:26px 32px 28px;margin-bottom:22px}
  h2{font-size:20px;font-weight:640;letter-spacing:-.01em;margin:0 0 4px}
  .secsub{color:var(--muted);margin:0 0 18px;font-size:13.5px}
  .lead{margin:12px 0 0;font-size:15.5px;line-height:1.65}
  .lead b{font-weight:640}
  .chip{display:inline-block;flex:none;color:var(--c);border:1px solid var(--c);border-radius:999px;
    padding:1px 9px;font-size:10.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}

  .bars{display:flex;flex-direction:column;gap:2px}
  .bar{display:grid;grid-template-columns:190px minmax(0,1fr) 34px;gap:14px;align-items:center;padding:7px 8px;border-radius:8px;text-align:left}
  .bar:hover{background:var(--brand-soft)}
  .bl{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .bt{display:block;height:9px;border-radius:999px;background:#EDF0F5;overflow:hidden}
  .bt i{display:block;height:100%;border-radius:999px}
  .bv{font-size:12px;color:var(--faint);text-align:right}
  .res{display:grid;grid-template-columns:200px 130px minmax(0,1fr) 78px;gap:14px;align-items:center;padding:7px 8px;border-radius:8px;text-align:left}
  .res:hover{background:var(--brand-soft)}
  .rn{font-size:13px;font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .rg{font-size:11.5px;color:var(--faint);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .rv{font-size:12px;color:var(--faint);text-align:right}

  .prio{display:flex;gap:16px;padding:16px 0;border-top:1px solid var(--line);break-inside:avoid;page-break-inside:avoid}
  .prio:first-of-type{border-top:0;padding-top:2px}
  .pnum{font-weight:640;font-size:15px;color:var(--brand);background:var(--brand-soft);border-radius:9px;
    width:30px;height:30px;display:flex;align-items:center;justify-content:center;flex:none}
  .pbody{min-width:0}
  .phead{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;margin-bottom:6px}
  .pt{font-weight:640;font-size:15px}
  .pn{font-size:11.5px;color:var(--faint)}
  .pimp,.pact,.pbp{margin:0 0 5px;color:var(--muted);font-size:13.5px;line-height:1.6}
  .pact b,.pbp b{color:var(--ink);font-weight:600;margin-right:6px}
  .pmore{margin:14px 0 0;color:var(--faint);font-size:13px}

  .filters{border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-bottom:14px;background:#FBFCFD}
  .chips{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .fgap{width:10px}
  .fchip{border:1px solid var(--line);background:var(--card);border-radius:999px;padding:5px 13px;font-size:12.5px;font-weight:600;color:var(--muted)}
  .fchip:hover{border-color:var(--brand);color:var(--brand)}
  .fchip.on{background:var(--brand);border-color:var(--brand);color:#fff}
  .frow{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px}
  select,input[type=search]{border:1px solid var(--line);border-radius:999px;padding:7px 14px;font:inherit;font-size:13px;background:var(--card);color:var(--ink);min-width:0}
  input[type=search]{flex:1;min-width:180px}
  .fcount{color:var(--faint);font-size:12.5px;margin-left:auto}

  .ctls{display:flex;flex-direction:column}
  .ctl{border-top:1px solid var(--line)}
  .ctl:first-child{border-top:0}
  .ctl[hidden]{display:none}
  .chead{display:grid;grid-template-columns:94px minmax(0,1fr) 170px 92px 16px;gap:14px;align-items:center;
    width:100%;padding:12px 6px;text-align:left;border-radius:8px}
  .chead:hover{background:var(--brand-soft)}
  .ct{font-weight:600;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .cd,.cn{font-size:12px;color:var(--faint);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .cn{text-align:right}
  .carrow{width:8px;height:8px;border-right:1.6px solid var(--faint);border-bottom:1.6px solid var(--faint);
    transform:rotate(45deg);margin:0 auto;transition:transform .18s}
  .ctl.open .carrow{transform:rotate(-135deg)}
  .det{display:none;padding:2px 6px 20px 108px}
  .ctl.open .det{display:block}
  .dsec{margin-bottom:12px}
  .dsec h4{margin:0 0 3px;font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--brand);font-weight:600}
  .dsec p{margin:0;color:var(--muted);font-size:13.5px;line-height:1.6}
  .flist{margin:4px 0 0;padding-left:18px;color:var(--muted);font-size:13px;line-height:1.7}
  .fd{display:block;font-family:var(--mono);font-size:11.5px;color:var(--faint);word-break:break-all}
  .dmeta{display:flex;gap:18px;flex-wrap:wrap;padding-top:8px;border-top:1px dashed var(--line);color:var(--faint);font-size:11.5px}
  .dmeta b{color:var(--muted);font-weight:600;font-family:var(--mono)}
  .empty{color:var(--faint);padding:18px 6px}

  .mrow{display:flex;gap:12px;align-items:baseline;padding:7px 0;color:var(--muted);font-size:13.5px}
  footer{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;color:var(--faint);font-size:11.5px;padding:6px 4px 0}

  @media (max-width:760px){
    .chead{grid-template-columns:80px minmax(0,1fr) 16px}
    .cd,.cn{display:none}
    .det{padding-left:12px}
    .bar{grid-template-columns:120px minmax(0,1fr) 30px}
    .res{grid-template-columns:minmax(0,1fr) 70px}
    .res .rg,.res .bt{display:none}
    .hero{padding:24px 20px}
    .block{padding:22px 20px 24px}
  }
  @media print{
    body{background:#fff}
    .page{max-width:none;padding:0}
    .top,.filters,.btn{display:none!important}
    .hero,.block{border-radius:0;border-width:0 0 1px 0;padding-left:0;padding-right:0;margin-bottom:14px}
    h2{break-after:avoid;page-break-after:avoid}
    /* everything opens for print: a filtered screen must not become a partial document */
    .ctl[hidden]{display:block!important}
    .det{display:block!important}
    .ctl{break-inside:avoid;page-break-inside:avoid}
    .carrow{display:none}
    footer{padding-top:10px}
  }
  @page{size:A4;margin:16mm 14mm 18mm}
</style>
'@

$script:ReportJs = @'
<script>
(function () {
  var state = { status: ['fail'], sev: [], domain: '', q: '' };
  var ctls = Array.prototype.slice.call(document.querySelectorAll('.ctl'));
  var count = document.getElementById('fcount');
  var empty = document.getElementById('fempty');

  function apply() {
    var shown = 0;
    ctls.forEach(function (c) {
      var ok = (!state.status.length || state.status.indexOf(c.dataset.status) > -1)
        && (!state.sev.length || (c.dataset.status === 'fail' && state.sev.indexOf(c.dataset.sev) > -1))
        && (!state.domain || c.dataset.domain === state.domain)
        && (!state.q || c.dataset.text.indexOf(state.q) > -1);
      c.hidden = !ok;
      if (ok) shown++;
    });
    count.textContent = shown + ' of ' + ctls.length + ' shown';
    empty.hidden = shown > 0;
  }

  document.querySelectorAll('.fchip').forEach(function (chip) {
    chip.addEventListener('click', function () {
      var k = chip.dataset.f, v = chip.dataset.v, list = state[k], i = list.indexOf(v);
      if (i > -1) { list.splice(i, 1); chip.classList.remove('on'); }
      else { list.push(v); chip.classList.add('on'); }
      // a severity filter only means anything among failures
      if (k === 'sev' && list.length && state.status.indexOf('fail') === -1) {
        state.status.push('fail');
        document.querySelector('.fchip[data-f="status"][data-v="fail"]').classList.add('on');
      }
      apply();
    });
  });

  document.getElementById('fdomain').addEventListener('change', function (e) { state.domain = e.target.value; apply(); });
  document.getElementById('fsearch').addEventListener('input', function (e) { state.q = e.target.value.trim().toLowerCase(); apply(); });

  var expand = document.getElementById('fexpand');
  expand.addEventListener('click', function () {
    var open = expand.dataset.on === '1';
    ctls.forEach(function (c) {
      if (c.hidden) return;
      c.classList.toggle('open', !open);
      c.querySelector('.chead').setAttribute('aria-expanded', String(!open));
    });
    expand.dataset.on = open ? '' : '1';
    expand.textContent = open ? 'Expand all' : 'Collapse all';
  });

  ctls.forEach(function (c) {
    var head = c.querySelector('.chead');
    head.addEventListener('click', function () {
      var open = c.classList.toggle('open');
      head.setAttribute('aria-expanded', String(open));
    });
  });

  // the hero is a control surface: a severity or a domain jumps to the table already filtered
  document.querySelectorAll('.stat[data-jump]').forEach(function (s) {
    s.addEventListener('click', function () {
      var v = s.dataset.jump;
      state.sev = [v]; state.status = ['fail'];
      document.querySelectorAll('.fchip').forEach(function (ch) {
        ch.classList.toggle('on', (ch.dataset.f === 'sev' && ch.dataset.v === v) || (ch.dataset.f === 'status' && ch.dataset.v === 'fail'));
      });
      apply();
      document.getElementById('controls').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
  document.querySelectorAll('.res[data-res]').forEach(function (r) {
    r.addEventListener('click', function () {
      var q = r.dataset.res.toLowerCase();
      state.q = q; state.sev = []; state.domain = '';
      document.getElementById('fsearch').value = r.dataset.res;
      document.getElementById('fdomain').value = '';
      document.querySelectorAll('.fchip[data-f="sev"]').forEach(function (ch) { ch.classList.remove('on'); });
      apply();
      document.getElementById('controls').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
  document.querySelectorAll('.bar[data-domain]').forEach(function (bar) {
    bar.addEventListener('click', function () {
      state.domain = bar.dataset.domain;
      document.getElementById('fdomain').value = state.domain;
      apply();
      document.getElementById('controls').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  apply();
})();
</script>
'@


Export-ModuleMember -Function Invoke-AzPosture, Get-AzPostureCheck, New-AzPostureReport

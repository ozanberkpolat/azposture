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
# One self-contained HTML file: no fonts fetched, no scripts, no images, nothing
# external at all, so it opens from a locked-down laptop and prints to A4 as it is.

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
    if ($null -eq $Score) { return @{ color = '#6B7787'; word = 'not yet scored'; text = 'n/a' } }
    if ($Score -ge 85) { return @{ color = '#1E9E6A'; word = 'a strong posture'; text = "$Score" } }
    if ($Score -ge 60) { return @{ color = '#D9A521'; word = 'a fair posture'; text = "$Score" } }
    @{ color = '#C0263A'; word = 'an at-risk posture'; text = "$Score" }
}

function Get-ControlRollup {
    <# Failing findings collapse to one row per check: the control is what gets fixed,
       the findings under it are the resources it affects. #>
    param($Fails)
    $groups = $Fails | Group-Object check_key
    $rows = foreach ($g in $groups) {
        $first = $g.Group[0]
        [pscustomobject]@{
            Key = $g.Name; Title = $first.title; Severity = $first.severity
            Domain = $first.domain; Impact = $first.impact; Fix = $first.fix
            BestPractice = $first.best_practice; Count = $g.Count; Items = $g.Group
            Weight = $(if ($script:Weight[$first.severity]) { $script:Weight[$first.severity] } else { 1 })
        }
    }
    @($rows | Sort-Object -Property @{ Expression = 'Weight'; Descending = $true }, @{ Expression = 'Count'; Descending = $true }, 'Title')
}

function New-AzPostureReport {
    <#
    .SYNOPSIS
      Render a run's findings as one self-contained HTML report.
    .DESCRIPTION
      Invoke-AzPosture writes this alongside the JSON, so you rarely need to call it.
      Point it at a run folder to re-render one you already have, or one you were sent.
      Nothing is fetched: the file carries its own styling and opens offline.
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
    $skips = @($all | Where-Object status -eq 'skip')
    $controls = Get-ControlRollup $fails
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

    $b = [System.Text.StringBuilder]::new()
    $add = { param($s) [void]$b.Append($s) }

    # ── cover ─────────────────────────────────────────────────────────────────
    $total = $nPass + $nFail
    $segs = ''
    foreach ($s in 'critical', 'high', 'medium', 'low') {
        $n = @($controls | Where-Object Severity -eq $s).Count
        if ($n -gt 0 -and $total -gt 0) {
            $segs += ('<span class="seg" style="width:{0}%;background:{1}"></span>' -f ([Math]::Round(100 * $n / $total, 2)), $script:SevColor[$s])
        }
    }
    # passing weight is the rest of the bar: green, so a clean run does not read as an empty gauge
    if ($total -gt 0 -and $nPass -gt 0) { $segs += ('<span class="seg" style="width:{0}%;background:#8FD3B4"></span>' -f ([Math]::Round(100 * $nPass / $total, 2))) }
    if (-not $segs) { $segs = '<span class="seg" style="width:100%;background:#DCE3EC"></span>' }

    $stats = ''
    foreach ($s in 'critical', 'high', 'medium', 'low') {
        $stats += ('<div class="stat"><div class="num" style="color:{0}">{1}</div><div class="lbl">{2}</div></div>' -f $script:SevColor[$s], $counts[$s], $script:SevLabel[$s])
    }

    $planeWord = switch ("$($Summary.plane)") { 'Identity' { 'Entra ID only' } 'Estate' { 'the Azure estate only' } default { 'Entra ID and the Azure estate' } }
    & $add ('<div class="cover"><div class="eyebrow">AzPosture &middot; Findings</div>' +
        '<h1>Azure and Entra ID posture</h1>' +
        ('<div class="sub">{0} &middot; {1} &middot; {2}</div>' -f (Enc $tenant), (Enc $when), (Enc $planeWord)) +
        ('<div class="hero"><div class="score" style="color:{0}">{1}<small>posture score</small><span class="gword">{2}</span></div>' -f $band.color, $band.text, $band.word) +
        ('<div class="barwrap"><div class="bar">{0}</div><div class="row">{1}</div></div></div>' -f $segs, $stats) +
        ('<div class="tally"><b>{0}</b> controls assessed &middot; <b>{1}</b> pass &middot; <b>{2}</b> fail &middot; <b>{3}</b> not assessed &middot; checklist <b>{4}</b></div>' -f ($nPass + $nFail), $nPass, $nFail, $nSkip, (Enc $Summary.catalog_version)) +
        '</div>')

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
        $sentences += ('<b>{0}</b> controls were not assessed and are listed at the end.{1}' -f $nSkip, (Enc $reason))
    }
    & $add ('<section class="block"><h2>Executive summary</h2><p class="lead">{0}</p></section>' -f ($sentences -join ' '))

    # ── top priorities ────────────────────────────────────────────────────────
    if ($controls.Count) {
        $critHigh = @($controls | Where-Object { $_.Severity -in 'critical', 'high' }).Count
        $take = [Math]::Max(8, $critHigh)
        $top = @($controls | Select-Object -First $take)
        $items = ''
        $i = 0
        foreach ($c in $top) {
            $i++
            $head = ('<div class="phead"><span class="chip" style="--c:{0}">{1}</span><span class="pt">{2}</span>{3}</div>' -f
                $script:SevColor[$c.Severity], $script:SevLabel[$c.Severity], (Enc $c.Title),
                $(if ($c.Count -gt 1) { '<span class="pn">affects {0} resources</span>' -f $c.Count } else { '' }))
            $imp = $(if ($c.Impact) { '<p class="pimp">{0}</p>' -f (Enc $c.Impact) } else { '' })
            $act = $(if ($c.Fix) { '<p class="pact"><b>Action</b> {0}</p>' -f (Enc $c.Fix) } else { '' })
            $bp = $(if ($c.BestPractice) { '<p class="pbp"><b>The target, and why that one</b> {0}</p>' -f (Enc $c.BestPractice) } else { '' })
            $items += ('<div class="prio"><div class="pnum">{0}</div><div class="pbody">{1}{2}{3}{4}</div></div>' -f $i, $head, $imp, $act, $bp)
        }
        $more = $(if ($top.Count -lt $controls.Count) { '<p class="pmore">{0} further failing controls follow in the findings below.</p>' -f ($controls.Count - $top.Count) } else { '' })
        & $add ('<section class="block"><h2>Top priorities</h2><p class="secsub">What to fix first, and why it matters. Ordered by severity weight, then by how many resources each one affects.</p>{0}{1}</section>' -f $items, $more)
    }

    # ── every finding, by domain ──────────────────────────────────────────────
    if ($controls.Count) {
        $byDomain = $controls | Group-Object Domain | Sort-Object { -(@($_.Group | Measure-Object Weight -Sum).Sum) }
        $blocks = ''
        foreach ($d in $byDomain) {
            $rows = ''
            foreach ($c in ($d.Group | Sort-Object -Property @{ Expression = 'Weight'; Descending = $true }, 'Title')) {
                $lines = ''
                $shown = @($c.Items | Select-Object -First 12)
                foreach ($it in $shown) {
                    $detail = $(if ($it.detail) { '<span class="fd">{0}</span>' -f (Enc $it.detail) } else { '' })
                    $lines += ('<li>{0}{1}</li>' -f (Enc $it.title), $detail)
                }
                if ($c.Items.Count -gt $shown.Count) { $lines += ('<li class="fmore">and {0} more</li>' -f ($c.Items.Count - $shown.Count)) }
                $rows += ('<div class="fctl"><div class="fhead"><span class="chip" style="--c:{0}">{1}</span><span class="ft">{2}</span><span class="fn">{3}</span></div><ul class="flist">{4}</ul></div>' -f
                    $script:SevColor[$c.Severity], $script:SevLabel[$c.Severity], (Enc $c.Title),
                    $(if ($c.Count -gt 1) { "$($c.Count) resources" } else { '1 resource' }), $lines)
            }
            $blocks += ('<div class="dom"><h3>{0}</h3>{1}</div>' -f (Enc $d.Name), $rows)
        }
        & $add ('<section class="block"><h2>Findings by domain</h2><p class="secsub">Every failing control, with the resources it names.</p>{0}</section>' -f $blocks)
    }

    # ── not assessed ──────────────────────────────────────────────────────────
    if ($skips.Count) {
        $sk = @($skips | Group-Object check_key | ForEach-Object {
                '<li>{0}{1}</li>' -f (Enc $_.Group[0].title),
                $(if ($_.Group[0].detail) { '<span class="fd">{0}</span>' -f (Enc $_.Group[0].detail) } else { '' })
            })
        & $add ('<section class="block"><h2>Not assessed</h2><p class="secsub">Nothing here passed or failed. A control is skipped when the licence, the role or the service it inspects was not present.</p><ul class="flist">{0}</ul></section>' -f ($sk -join ''))
    }

    # ── methodology ───────────────────────────────────────────────────────────
    $sevRows = ''
    foreach ($k in $script:SevDesc.Keys) {
        $sevRows += ('<div class="mrow"><span class="chip" style="--c:{0}">{1}</span><span>{2}</span></div>' -f $script:SevColor[$k], $script:SevLabel[$k], $script:SevDesc[$k])
    }
    & $add ('<section class="block"><h2>How this was measured</h2>' +
        ('<p class="secsub">Read-only throughout. The run used Microsoft Graph and Azure Resource Graph under the signed-in account, wrote to this machine only, and changed nothing in the tenant. Checklist <b>{0}</b>, module <b>{1}</b>, run finished {2}.</p>' -f (Enc $Summary.catalog_version), (Enc $Summary.module_version), (Enc $when)) +
        '<p class="secsub">The posture score is the share of severity weight that passes: each control counts 4, 3, 2 or 1 by its severity, so the score answers "how much of what matters is in place", not "how many boxes are ticked". Above 85 is strong, 60 to 84 fair, below 60 at risk. A control that could not be assessed is left out of the score entirely rather than counted as a pass.</p>' +
        $sevRows + '</section>')

    $doc = ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width, initial-scale=1">' +
        ('<title>{0}, AzPosture findings, {1}</title>' -f (Enc $tenant), (Enc $when)) +
        $script:ReportCss + '</head><body><div class="page">' + $b.ToString() +
        ('<footer><span>Generated {0} by AzPosture {1}, checklist {2}</span><span>Run on your own machine. Nothing left the tenant.</span></footer>' -f (Enc $when), (Enc $Summary.module_version), (Enc $Summary.catalog_version)) +
        '</div></body></html>')

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
  .page{max-width:940px;margin:0 auto;padding:52px 44px 80px}
  .cover{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:38px 40px 30px;margin-bottom:26px}
  .eyebrow{text-transform:uppercase;letter-spacing:.2em;font-size:11px;color:var(--brand);font-weight:600}
  h1{font-size:38px;font-weight:680;letter-spacing:-.02em;line-height:1.08;margin:12px 0 4px}
  .sub{color:var(--muted);font-size:14.5px}
  .hero{display:flex;gap:38px;align-items:center;margin:28px 0 22px}
  .score{font-weight:680;font-size:74px;line-height:.9;letter-spacing:-.03em;flex:none}
  .score small{display:block;font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);margin-top:10px;font-weight:600}
  .score .gword{display:block;font-size:13px;font-weight:600;color:var(--ink);margin-top:5px;letter-spacing:0}
  .barwrap{flex:1;min-width:0}
  .bar{display:flex;height:12px;border-radius:999px;overflow:hidden;background:#DCE3EC}
  .seg{display:block;height:100%}
  .row{display:flex;gap:26px;margin-top:16px}
  .stat .num{font-weight:680;font-size:26px;letter-spacing:-.02em}
  .stat .lbl{text-transform:uppercase;letter-spacing:.13em;font-size:9.5px;color:var(--faint);margin-top:3px;font-weight:600}
  .tally{border-top:1px solid var(--line);padding-top:14px;color:var(--muted);font-size:13px}
  .tally b{color:var(--ink);font-weight:600}
  .block{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px 32px 30px;margin-bottom:22px}
  h2{font-size:21px;font-weight:640;letter-spacing:-.01em;margin:0 0 4px}
  h3{font-size:13px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--brand);margin:26px 0 10px}
  .dom:first-child h3{margin-top:8px}
  .secsub{color:var(--muted);margin:0 0 18px;font-size:13.5px}
  .lead{margin:14px 0 0;font-size:15.5px;line-height:1.65}
  .lead b{font-weight:640}
  .chip{display:inline-block;flex:none;color:var(--c);border:1px solid var(--c);border-radius:999px;
    padding:1px 9px;font-size:10.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase}
  .prio{display:flex;gap:16px;padding:16px 0;border-top:1px solid var(--line);break-inside:avoid;page-break-inside:avoid}
  .prio:first-of-type{border-top:0;padding-top:4px}
  .pnum{font-weight:640;font-size:15px;color:var(--brand);background:var(--brand-soft);border-radius:9px;
    width:30px;height:30px;display:flex;align-items:center;justify-content:center;flex:none}
  .pbody{min-width:0}
  .phead{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;margin-bottom:6px}
  .pt{font-weight:640;font-size:15px}
  .pn{font-size:11.5px;color:var(--faint);font-weight:500}
  .pimp,.pact,.pbp{margin:0 0 5px;color:var(--muted);font-size:13.5px;line-height:1.6}
  .pact b,.pbp b{color:var(--ink);font-weight:600;margin-right:6px}
  .pmore{margin:14px 0 0;color:var(--faint);font-size:13px}
  .fctl{padding:14px 0;border-top:1px solid var(--line);break-inside:avoid;page-break-inside:avoid}
  .fhead{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
  .ft{font-weight:600;font-size:14px}
  .fn{font-size:11.5px;color:var(--faint);margin-left:auto}
  .flist{margin:8px 0 0;padding-left:18px;color:var(--muted);font-size:13px;line-height:1.7}
  .flist li{break-inside:avoid;page-break-inside:avoid}
  .fd{display:block;font-family:var(--mono);font-size:11.5px;color:var(--faint);word-break:break-all}
  .fmore{color:var(--faint);list-style:none;margin-left:-18px}
  .mrow{display:flex;gap:12px;align-items:baseline;padding:7px 0;color:var(--muted);font-size:13.5px}
  footer{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;color:var(--faint);font-size:11.5px;padding:6px 4px 0}
  @media print{
    body{background:#fff}
    .page{max-width:none;padding:0}
    .cover,.block{border-radius:0;border-width:0 0 1px 0;padding-left:0;padding-right:0;margin-bottom:14px}
    .block{break-inside:auto}
    h2{break-after:avoid;page-break-after:avoid}
    footer{padding-top:10px}
  }
  @page{size:A4;margin:16mm 14mm 18mm}
</style>
'@

Export-ModuleMember -Function Invoke-AzPosture, Get-AzPostureCheck, New-AzPostureReport

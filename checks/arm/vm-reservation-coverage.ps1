# Cost — reserved VM instance coverage.
#
# Four independent sources, each optional. The maths lives in _reservations.ps1 (pure,
# self-checked by ps/tests/reservation-coverage.ps1); this file only fetches and reports.
#
#   1. running inventory       Resource Graph                                Azure Reader
#   2. size-flexibility ratios Microsoft.Capacity/catalogs                   Azure Reader
#   3. owned reservations      Microsoft.Capacity/reservationOrders   RESERVATIONS READER (tenant)
#   4. purchase candidates     Microsoft.Consumption/reservationRecommendations  Azure Reader
#
# The maths is deliberately SIMPLE: reserved units vs running units per region x flexibility
# group. A reservation is a POOL any machine in that family can draw on, so a per-family
# shortfall is the honest answer. Per-instance billing attribution was tried and removed —
# it was harder to trust, not easier (user's call, 2026-08-08).
#
# Source 3 is the only one that can see a reservation you already own sitting idle, and it
# needs a tenant-scope role that Azure Reader on subscriptions does NOT grant. When it is
# unavailable the check says which questions it could not answer — it must never report a
# clean result on the strength of the other three.
. (Join-Path $PSScriptRoot '_reservations.ps1')

$gaps = @()          # human-readable "what I could not read"
$instances = @(); $ratios = @{}; $reservations = @(); $recs = @()
$invOk = $false; $resOk = $false; $recOk = $false; $ratioOk = $false

# --- 1. running inventory -------------------------------------------------------------
# TWO queries, not one union. ARG rejected the union form with "Failed to resolve column
# named 'cnt'": a column created by `project`/`extend` cannot be referenced by a later
# `where` in ARG's KQL subset (same family as the projected-`title` trap already documented).
# Hence: filter with the FULL expression before projecting, and concatenate in PowerShell.
# Flexible-orchestration scale sets are excluded because their members already appear as
# individual microsoft.compute/virtualmachines rows — counting both doubles the footprint.
$kqlVm = @'
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where isnotempty(tostring(properties.hardwareProfile.vmSize))
| project id, name, size=tostring(properties.hardwareProfile.vmSize),
          power=tostring(properties.extended.instanceView.powerState.code),
          prio=tostring(properties.priority),
          loc=location, sub=subscriptionId
'@
$kqlSs = @'
resources
| where type =~ 'microsoft.compute/virtualmachinescalesets'
| where tostring(properties.orchestrationMode) != 'Flexible'
| where isnotempty(tostring(sku.name)) and toint(sku.capacity) > 0
| project id, name, size=tostring(sku.name), cap=toint(sku.capacity),
          prio=tostring(properties.virtualMachineProfile.priority),
          loc=location, sub=subscriptionId
'@
try {
    # assign-then-iterate: Search-Graph returns the whole array as ONE object (`, $all`),
    # so piping it directly member-enumerates rows into column arrays.
    $vmRows = Search-Graph $kqlVm
    $instances = @($vmRows | ForEach-Object {
        [pscustomobject]@{ Id = $_.id; Name = $_.name; Size = $_.size; Power = $_.power
                           Loc = "$($_.loc)".ToLower(); Sub = $_.sub; Count = 1; Kind = 'vm'
                           Prio = $_.prio }
    })
    $invOk = $true
} catch { $gaps += "running VM inventory unreadable ($_)" }
try {
    $ssRows = Search-Graph $kqlSs
    $instances += @($ssRows | ForEach-Object {
        [pscustomobject]@{ Id = $_.id; Name = $_.name; Size = $_.size; Power = 'PowerState/running'
                           Loc = "$($_.loc)".ToLower(); Sub = $_.sub; Count = $_.cap; Kind = 'scaleset'
                           Prio = $_.prio }
    })
} catch { $gaps += "scale-set inventory unreadable, so their instances are not counted ($_)" }

# Spot VMs and the A/G series can never draw a reservation discount, so leaving them in the
# running total invents a shortfall no purchase could ever close. Dropped here, and counted
# so the omission is stated rather than silent.
$ineligible = @($instances | Where-Object { -not (Test-ReservationEligible $_.Size $_.Prio) })
if ($ineligible.Count) {
    $instances = @($instances | Where-Object { Test-ReservationEligible $_.Size $_.Prio })
    $spotN = @($ineligible | Where-Object { "$($_.Prio)" -match '(?i)spot' }).Count
    $gaps += ("$($ineligible.Count) instance(s) excluded as ineligible for any reservation" +
              $(if ($spotN) { " ($spotN Spot" + $(if ($ineligible.Count -gt $spotN) { ', rest A/G-series' } else { '' }) + ')' }
                else { ' (A/G-series)' }))
}

# --- 2. instance size flexibility ratios ----------------------------------------------
# Per region, from the reservation catalog. The published CSV at aka.ms/isf is removed on
# 2026-08-30, so the API is the only durable source. Ratios are used RAW: Microsoft does
# not normalise them to 1 for the smallest SKU in a group, but both sides of every
# comparison use the same scale, so normalising would change no answer.
$subs = @()
try { $subs = @(Get-Subs) } catch { $gaps += "could not list subscriptions ($_)" }
$regions = @($instances | ForEach-Object { $_.Loc } | Where-Object { $_ } | Sort-Object -Unique)
# The catalog pages with $skip/$take and returns NO nextLink, so Invoke-Arm's paging does
# not apply — ask for one big page explicitly or you silently get the first slice only.
# The reservedResourceType spelling also differs between references (the reservations enum
# says VirtualMachines, the Az.Reservations example says VirtualMachine), so try both: the
# wrong value yields a 400/empty, which is what left this table empty on the first live run.
$catErr = @{}
foreach ($region in $regions) {
    $got = $false
    foreach ($s in @($subs | Select-Object -First 3)) {
      foreach ($rrt in 'VirtualMachines', 'VirtualMachine') {
        try {
            # Retry once: the whole family comparison is withheld if this returns nothing, so a
            # single transient 429/timeout silently degrades the entire check.
            $cat = $null
            foreach ($attempt in 1..2) {
                try {
                    $cat = Invoke-Arm -ApiVersion '2022-11-01' `
                        -Path "/subscriptions/$($s.Id)/providers/Microsoft.Capacity/catalogs?reservedResourceType=$rrt&location=$region&`$take=2000"
                    break
                } catch { if ($attempt -eq 2) { throw } ; Start-Sleep -Seconds 3 }
            }
            foreach ($c in @($cat)) {
                if (-not $c.name) { continue }
                $grp = $null; $ratio = $null
                foreach ($p in @($c.skuProperties)) {
                    # The property names differ by api-version; accept both spellings.
                    switch -Regex ("$($p.name)") {
                        '(?i)^(ReservationsAutofitGroup|InstanceSizeFlexibilityGroup)$' { $grp = "$($p.value)" }
                        '(?i)^(ReservationsAutofitRatio|InstanceSizeFlexibilityRatio)$' { $ratio = "$($p.value)" }
                    }
                }
                if (-not $grp -or -not $ratio) { continue }
                if (-not $ratios.ContainsKey($region)) { $ratios[$region] = @{} }
                $ratios[$region]["$($c.name)".ToLower()] = @{ Group = $grp; Ratio = [double]$ratio }
            }
            # A 200 with no usable rows is NOT success — claiming "ratios from the catalog"
            # while silently comparing exact sizes is the kind of quiet lie this check exists
            # to stop. Only a region that actually yielded ratios counts.
            if ($ratios.ContainsKey($region) -and $ratios[$region].Count) { $got = $true; $ratioOk = $true; break }
        } catch { $catErr[$region] = "$_"; continue }
      }
      if ($got) { break }
    }
    if (-not $got) {
        $why = if ($catErr.ContainsKey($region)) { ": $($catErr[$region])" } else { ': the catalog returned no rows carrying autofit properties' }
        $gaps += "no size-flexibility ratios for $region (coverage comparison withheld there)$why"
    }
}

# --- 3. owned reservations ------------------------------------------------------------
$DEAD = @('Expired', 'Cancelled', 'Split', 'Merged', 'Failed')
# Audit trail of every reservation the API returned, kept and skipped alike. "It says none
# reserved but I own one" is unanswerable without this, and the reasons for skipping (wrong
# resource type, dead provisioning state, archived) are all invisible from the outside.
$seenRes = @(); $skipRes = @()
# TWO ways to enumerate reservations, because they do not always agree:
#   Reservation_ListAll  -> one tenant-wide call, "the reservations the user has access to"
#   the reservationOrders walk -> orders, then each order's reservations
# ListAll is the primary (simpler, and the portal's own view); the order walk is the fallback
# and a cross-check. Both counts are reported, because "the portal shows a reservation this
# check never saw" is only answerable if the check says which list it used and how big it was.
# ⚠️ THERE ARE TWO AUTHORIZATION METHODS FOR RESERVATIONS, AND THEY HAVE DIFFERENT APIS.
# Per MS Learn ("Permissions to view and manage Azure reservations"): access comes from either
# BILLING ADMIN roles or reservation RBAC roles, and the portal exposes them in two different
# blades — RBAC users go to Home > Reservations, billing admins go to Cost Management + Billing
# > Billing scopes > Products + services > "Reservations + Hybrid Benefit", which shows the
# COMPLETE list for the enrollment/billing profile.
#
# Those blades are backed by different providers:
#   Microsoft.Capacity/reservationOrders|reservations  <- honours reservation RBAC roles only
#   Microsoft.Billing/billingAccounts/{ba}/reservations <- honours EA/MCA BILLING roles
#
# An EA Enterprise Administrator (read-only) or MCA billing-profile Reader therefore sees every
# reservation in the portal while Microsoft.Capacity returns 403 for the same reservation —
# billing roles are not Azure RBAC, never appear in IAM, and need no PIM activation. That is
# exactly what happened on one customer tenant: 26 visible in the portal, 7 via Capacity, and a specific
# reservation order returning 403. So query BOTH and take the union.
$rawRes = @(); $srcUsed = @(); $orderWalkCount = $null; $listAllCount = $null; $billingCount = $null
$byKeyRes = @{}
function Add-Res($rows, $label) {
    $n = 0
    foreach ($x in @($rows)) {
        if (-not $x -or -not $x.properties) { continue }
        # ids differ by provider, so key on orderId/reservationId, not the whole path
        $k = if ("$($x.id)" -match '(?i)reservationOrders/([^/]+)/reservations/([^/]+)') {
                 "$($matches[1])/$($matches[2])".ToLower()
             } else { "$($x.id)".ToLower() }
        if (-not $byKeyRes.ContainsKey($k)) { $byKeyRes[$k] = $x; $n++ }
    }
    if ($n) { $script:srcUsed += "$label(+$n)" }
    return $n
}
try {
    # ⚠️ NEVER @(Invoke-Arm ...) — the helper returns `, $all`, so wrapping it in @() nests the
    # whole result set into ONE element. 46 reservations collapsed to a single object whose
    # fields member-enumerated into parallel arrays, and only the order walk's 7 survived.
    # Assign, then use. (Same trap as the _lib.ps1 enumeration contract.)
    $la = Invoke-Arm -Path '/providers/Microsoft.Capacity/reservations?$take=200' -ApiVersion '2022-11-01'
    $listAllCount = @($la | Where-Object { $_ -and $_.properties }).Count
    [void](Add-Res $la 'Capacity_ListAll')
} catch { $gaps += "Capacity reservation ListAll unreadable ($_)" }
try {
    $orders = Invoke-Arm -Path '/providers/Microsoft.Capacity/reservationOrders' -ApiVersion '2022-11-01'
    $walk = @()
    foreach ($o in @($orders)) {
        if (-not $o.name) { continue }
        try { $w1 = Invoke-Arm -Path "/providers/Microsoft.Capacity/reservationOrders/$($o.name)/reservations" -ApiVersion '2022-11-01'
               foreach ($w in $w1) { $walk += $w } }
        catch { $gaps += "reservations of order $($o.name) unreadable ($_)" }
    }
    $orderWalkCount = @($walk | Where-Object { $_ -and $_.properties }).Count
    [void](Add-Res $walk 'Capacity_orderWalk')
} catch { $gaps += "Capacity reservationOrders unreadable ($_)" }
# The billing path — the one a billing admin's portal view actually uses.
try {
    $bas = Invoke-Arm -Path '/providers/Microsoft.Billing/billingAccounts' -ApiVersion '2024-04-01'
    $bn = 0
    foreach ($ba in @($bas)) {
        if (-not $ba.name) { continue }
        try {
            $br = Invoke-Arm -Path "/providers/Microsoft.Billing/billingAccounts/$($ba.name)/reservations" -ApiVersion '2024-04-01'
            if ($null -eq $br) { $br = @() }
            $bn += @($br | Where-Object { $_ -and $_.properties }).Count
            [void](Add-Res $br "Billing[$($ba.name)]")
        } catch { $gaps += "billing-account reservations unreadable for $($ba.name) ($_)" }
    }
    $billingCount = $bn
} catch { $gaps += "billing accounts unreadable, so billing-role-visible reservations are missed ($_)" }

$rawRes = @($byKeyRes.Values)
if ($rawRes.Count) { $resOk = $true }
else {
    $gaps += ('no reservations readable by ANY route - needs either Reservations Reader at tenant scope ' +
              '(Azure RBAC) or an EA/MCA billing-reader role')
}
$srcUsed = $(if ($srcUsed.Count) { $srcUsed -join ' + ' } else { 'none' })

foreach ($r in $rawRes) {
    $p = $r.properties
    $rlbl = "$(if ($p.displayName) { $p.displayName } else { $r.name }) [$($r.sku.name) x$($p.quantity) $($r.location) $($p.provisioningState)]"
    $seenRes += $rlbl
    if ("$($p.reservedResourceType)" -ne 'VirtualMachines') {
        $skipRes += "$rlbl -> not a VM reservation (type=$($p.reservedResourceType))"; continue }
    if ("$($p.provisioningState)" -in $DEAD) {
        $skipRes += "$rlbl -> provisioningState=$($p.provisioningState)"; continue }
    if ("$($p.archived)" -eq 'True') { $skipRes += "$rlbl -> archived"; continue }
    $isf = if ($p.reservedResourceProperties -and $p.reservedResourceProperties.instanceFlexibility) {
               "$($p.reservedResourceProperties.instanceFlexibility)"
           } else { "$($p.instanceFlexibility)" }
    $util = $null; $grain = $null
    foreach ($want in 30, 7, 1) {
        $a = @($p.utilization.aggregates | Where-Object { $_ -and [int]$_.grain -eq $want })
        if ($a.Count) { $util = [double]$a[0].value; $grain = $want; break }
    }
    $scopes = @($p.appliedScopes)
    if (-not $scopes.Count -and $p.appliedScopeProperties) {
        $scopes = @($p.appliedScopeProperties | ForEach-Object { $_.subscriptionId } | Where-Object { $_ })
    }
    $reservations += [pscustomobject]@{
        Id = $r.id
        Name = $(if ($p.displayName) { "$($p.displayName)" } else { "$($r.name)" })
        Sku = "$($r.sku.name)"; Loc = "$($r.location)".ToLower(); Quantity = [double]$p.quantity
        Term = "$($p.term)"; Expiry = $(if ($p.expiryDateTime) { $p.expiryDateTime } else { $p.expiryDate })
        ScopeType = "$($p.appliedScopeType)"; Scopes = $scopes
        Isf = $isf; Renew = $p.renew; Util = $util; UtilGrain = $grain
    }
}

# --- 3c. savings plans (detect only) ---------------------------------------------------
# An Azure savings plan for compute is NOT a reservation: different provider
# (Microsoft.BillingBenefits), no per-family SKU, it discounts eligible compute spend
# broadly. This check cannot model one — but a family covered by a savings plan would
# otherwise be reported as "nothing is reserved here", which is actively misleading. So:
# detect them and say so. Doubly relevant since the 2026-07-01 RI retirement pushes
# customers onto savings plans for exactly these families.
$savingsPlans = @(); $spOk = $false
try {
    $sp = Invoke-Arm -Path '/providers/Microsoft.BillingBenefits/savingsPlanOrders' -ApiVersion '2022-11-01'
    $spOk = $true
    foreach ($o in @($sp)) {
        $q = $o.properties
        if (-not $q) { continue }
        $savingsPlans += "$(if ($q.displayName) { $q.displayName } else { $o.name }) [$($q.term) $($q.billingPlan)]"
    }
} catch { $gaps += "savings plans unreadable, so a family covered by one may read as unreserved ($_)" }

# --- 4. purchase candidates -----------------------------------------------------------
# The server applies defaults of scope=Single, resourceType=VirtualMachines and
# lookBackPeriod=Last7Days when no filter is given, so the filter is ALWAYS explicit here.
# Never re-filter resourceType client-side: it is absent from legacy rows, and dropping on
# a missing value is what made this check silently report nothing at all.
$unwrap = { param($x) if ($null -eq $x) { $null } elseif ($x -is [pscustomobject]) { $x.value } else { $x } }
foreach ($s in $subs) {
    foreach ($scope in 'Single', 'Shared') {
        foreach ($look in 'Last60Days', 'Last30Days', 'Last7Days') {
            $f = "properties/scope eq '$scope' AND properties/resourceType eq 'VirtualMachines' AND properties/lookBackPeriod eq '$look'"
            $page = $null
            try {
                $page = Invoke-Arm -ApiVersion '2024-08-01' `
                    -Path ("/subscriptions/$($s.Id)/providers/Microsoft.Consumption/reservationRecommendations?`$filter=" + [uri]::EscapeDataString($f))
            } catch { continue }
            $page = @($page | Where-Object { $_ -and $_.properties })
            if (-not $page.Count) { continue }   # nothing for this window; try a shorter one
            $recOk = $true
            foreach ($r in $page) {
                $p = $r.properties
                $sku = $(if ($p.skuName) { "$($p.skuName)" } else { "$($r.sku)" })
                $loc = $(if ($p.location) { "$($p.location)".ToLower() } else { "$($r.location)".ToLower() })
                # Free second source of flexibility ratios: every recommendation row carries
                # the group and ratio for its own SKU. It only covers recommended sizes, so it
                # cannot replace the catalog, but it fills gaps when the catalog is unreadable.
                if ($p.instanceFlexibilityGroup -and $p.instanceFlexibilityRatio -and $loc -and $sku) {
                    if (-not $ratios.ContainsKey($loc)) { $ratios[$loc] = @{} }
                    if (-not $ratios[$loc].ContainsKey("$sku".ToLower())) {
                        $ratios[$loc]["$sku".ToLower()] = @{ Group = "$($p.instanceFlexibilityGroup)"
                                                             Ratio = [double]$p.instanceFlexibilityRatio }
                    }
                }
                $recs += [pscustomobject]@{
                    Sku = $sku; Loc = $loc
                    Sub      = "$($p.subscriptionId)"; Quantity = $p.recommendedQuantity
                    Term     = "$($p.term)"; Scope = "$($p.scope)"; LookBack = $look
                    Savings  = & $unwrap $p.netSavings
                    Currency = $(if ($p.netSavings -is [pscustomobject]) { "$($p.netSavings.currency)" } else { $null })
                }
            }
            break   # longest window with data wins - 7 days is noise if a machine was off for three of them
        }
    }
}

# Nothing at all was readable -> loud skip, never a silent clean.
if (-not ($invOk -or $resOk -or $recOk)) {
    return [pscustomobject]@{
        Name   = 'Reserved VM instance coverage'
        Status = 'skip'
        Detail = ('Could not read any of: Resource Graph inventory, Microsoft.Capacity reservations, ' +
                  'Microsoft.Consumption recommendations. ' + ($gaps -join '; '))
    }
}

# Inventory that failed OR came back empty cannot support a coverage comparison. Passing
# that fact down is what stops "5 of 5 units idle" being asserted against a reservation
# Azure itself reports at 100%.
$inventoryUsable = ($invOk -and @($instances).Count -gt 0)

# --- collapse recommendations to one row per (sku, region, scope), carrying both terms --
$byKey = @{}
foreach ($r in $recs) {
    $k = "$($r.Sku)|$($r.Loc)|$($r.Scope)".ToLower()
    if (-not $byKey.ContainsKey($k)) {
        $byKey[$k] = [pscustomobject]@{ Sku = $r.Sku; Loc = $r.Loc; Sub = $r.Sub; Quantity = $r.Quantity
                                        Scope = $r.Scope; LookBack = $r.LookBack; Currency = $r.Currency
                                        Savings1Y = $null; Savings3Y = $null }
    }
    if ("$($r.Term)" -eq 'P3Y') { $byKey[$k].Savings3Y = $r.Savings } else { $byKey[$k].Savings1Y = $r.Savings }
    if ([double]$r.Quantity -gt [double]$byKey[$k].Quantity) { $byKey[$k].Quantity = $r.Quantity }
}

# Is anything actually running there NOW? A recommendation is built from a 60-day lookback,
# so a burst that finished a month ago still generates one — and a reservation for a region
# you have since left is worse than useless. Two grains, because they answer different
# questions: REGION presence is robust (no VMs there at all = not a live opportunity, demote
# it), whereas exact-SKU presence is only an annotation — with size flexibility a D2s_v5
# recommendation is still relevant while you run D4s_v5 in that group.
$regionHasVms = @{}; $skuRunning = @{}
foreach ($i in $instances) {
    if (Test-BillablePower $i.Power) {
        $regionHasVms["$($i.Loc)".ToLower()] = $true
        $skuRunning["$($i.Loc)|$($i.Size)".ToLower()] = $true
    }
}
foreach ($v in $byKey.Values) {
    $v | Add-Member -NotePropertyName RegionActive `
         -NotePropertyValue $(if ($inventoryUsable) { $regionHasVms.ContainsKey("$($v.Loc)".ToLower()) } else { $null }) -Force
    $v | Add-Member -NotePropertyName RunningNow `
         -NotePropertyValue $(if ($inventoryUsable) { $skuRunning.ContainsKey("$($v.Loc)|$($v.Sku)".ToLower()) } else { $null }) -Force
}

$groups = @(Get-CoverageGroups $instances $reservations $ratios)
# Only recommend buying where nothing is reserved for that size group yet. Where a
# reservation already exists, the shortfall is reported above as units-beyond-the-
# reservation, with real numbers instead of a generic "buy more".
# NOT $covered — that name already holds the per-INSTANCE billing coverage set from 3b.
# Reusing it here silently overwrote it, so every machine looked uncovered while the billing
# data was perfect. Distinct concepts get distinct names.
$reservedGroups = @{}
foreach ($g in $groups) { if ($g.ReservedUnits -gt 0) { $reservedGroups["$($g.Region)|$($g.Group)".ToLower()] = $true } }
$candidates = @($byKey.Values | Where-Object {
    $isf = Get-SizeIsf $ratios $_.Loc $_.Sku
    -not $reservedGroups.ContainsKey("$($_.Loc)|$($isf.Group)".ToLower())
})

$items = @(Get-ReservationFindings -Groups $groups -Recommendations $candidates -InventoryOk $inventoryUsable -SavingsPlansKnown $spOk)

# ⚠️ Reservations are TENANT-level resources with their own RBAC that does NOT inherit from
# subscriptions, so an identity can hold read on some reservation orders and not others — and
# the ones it cannot see are simply absent, with no error anywhere. That silently inflates
# every shortfall. Reservation_ListAll ("what this user can see") returning fewer than the
# order walk is the tell. Verified live on a customer tenant 2026-08-08: ListAll=1, walk=7, and a
# reservation order the consultant could see in the portal returned 403 to this identity.
if ($null -eq $billingCount -or ($null -ne $listAllCount -and $null -ne $orderWalkCount -and $listAllCount -lt $orderWalkCount)) {
    $items += [pscustomobject]@{
        Title    = 'Reservation visibility is incomplete - shortfalls may be overstated'
        Detail   = ("Azure's tenant-wide reservation list returned $listAllCount reservation(s) for this " +
                    "sign-in, while enumerating reservation orders found $orderWalkCount. Reservations are " +
                    'tenant-level resources with their own RBAC that does not inherit from subscriptions, so ' +
                    'any reservation whose order this identity is not on is invisible here - it simply does ' +
                    'not appear, with no error. Every "short on reservations" and "no reservation for" finding ' +
                    'above assumes the list is complete, so treat them as an upper bound until this is fixed. ' +
                    'There are TWO authorization methods with TWO different APIs: reservation RBAC roles ' +
                    '(Microsoft.Capacity, portal Home > Reservations) and EA/MCA BILLING roles ' +
                    '(Microsoft.Billing/billingAccounts/../reservations, portal Cost Management + Billing > ' +
                    'Billing scopes > Products + services > Reservations + Hybrid Benefit). This run queried ' +
                    'both and took the union. Fix whichever failed: grant Reservations Reader at TENANT scope ' +
                    'for the RBAC route, or an EA Enterprise Administrator (read-only) / MCA billing profile ' +
                    'Reader role for the billing route.')
        Severity = 'medium'
        ResourceId = $null
    }
}

# --- degradation is a finding, never silence ------------------------------------------
# Withholding a comparison must itself be reported, or it is just silence with extra steps.
# Two ways to lose it: no inventory at all, or no size-flexibility ratios for a region that
# HAS reservations (Get-ReservationFindings withholds that group's comparisons per `Degraded`).
$degradedGroups = @($groups | Where-Object { $_.Degraded -and $_.ReservedUnits -gt 0 })
if ($reservations.Count -and (-not $inventoryUsable -or $degradedGroups.Count)) {
    $why = if (-not $inventoryUsable) {
        'The Resource Graph VM inventory ' + $(if ($invOk) { 'came back empty' } else { 'could not be read' }) +
        ', so idle and over-run capacity could only be judged from the utilization Azure reports, ' +
        'applied-scope and flexibility-group problems were not assessed at all, and purchase ' +
        'recommendations could not be checked against the regions you actually run in.'
    } else {
        'Not compared: ' +
        (@($degradedGroups | ForEach-Object { "$($_.Group) in $($_.Region)" } | Sort-Object -Unique) -join '; ') +
        ' - the catalog has no flexibility ratio for ' +
        (@($degradedGroups | ForEach-Object { $_.MissingRatio } | Sort-Object -Unique |
           ForEach-Object { $_ -replace '(?i)^Standard_', '' }) -join ', ') +
        '. Every other family was compared normally. Older series often carry no ratio, so there ' +
        'may be nothing to fix.'
    }
    $items += [pscustomobject]@{
        Title    = 'Reservation coverage not compared against running VMs'
        Detail   = $why
        Severity = 'low'
        ResourceId = $null
    }
}
if (-not $resOk) {
    $items += [pscustomobject]@{
        Title    = 'Reservation utilization not assessed (missing Reservations Reader)'
        Detail   = ('Could not read Microsoft.Capacity/reservationOrders, so this run cannot say whether an ' +
                    'existing reservation is idle, scoped to the wrong subscription, has instance size ' +
                    'flexibility switched off, or is about to expire. Grant Reservations Reader at tenant ' +
                    'scope (Azure portal > Home > Reservations > Role assignment) and re-run.')
        Severity = 'low'
        ResourceId = $null
    }
}

# Evidence surfaces on BOTH pass and fail rows; the returned Name does not, so the
# always-visible summary has to live here.
# Count INSTANCES, not rows: a uniform scale-set row carries sku.capacity instances.
$vmCount  = [int](@($instances | Where-Object { Test-BillablePower $_.Power }) | Measure-Object -Property Count -Sum).Sum
$deadCnt  = [int](@($instances | Where-Object { -not (Test-BillablePower $_.Power) }) | Measure-Object -Property Count -Sum).Sum
$resUnits = [double](@($groups) | Measure-Object -Property ReservedUnits -Sum).Sum
$runUnits = [double](@($groups) | Measure-Object -Property RunningUnits -Sum).Sum
# Any source that failed gets ONE always-visible item with a stable title. Routing gaps
# through some other finding's detail has now hidden a real error three times running: the
# ARG query failure, the catalog failure, and the reservationDetails failure all reached the
# user as silence. A check that cannot say what it failed to read cannot be trusted.
$health = @("inventory=$(@($instances).Count) eligible instance(s)",
            [string]("VM reservations used=$(@($reservations).Count); unique reservations found=$($rawRes.Count) via $srcUsed" +
                     " [Capacity ListAll=$(if ($null -ne $listAllCount) { $listAllCount } else { 'ERR' })," +
                     " Capacity orderWalk=$(if ($null -ne $orderWalkCount) { $orderWalkCount } else { 'ERR' })," +
                     " Billing accounts=$(if ($null -ne $billingCount) { $billingCount } else { 'ERR' })]"),
            "flexibility ratios=$(if ($ratioOk) { 'yes' } else { 'NO - comparison withheld' })",
            "families compared=$(@($groups | Where-Object { -not $_.Degraded }).Count)",
            # The purchase advisory is only emitted when something is worth buying, so this
            # line is the only place the "Azure suggested N, none of them actionable" case is
            # recorded at all. Without it, suppressing that item would be a silent cap.
            "purchase recommendations returned=$(@($candidates).Count)",
            ("reservations seen from the API: " + $(if ($seenRes.Count) { [string]($seenRes -join ', ') } else { 'none' })))
if ($skipRes.Count) { $health += [string]('SKIPPED: ' + ($skipRes -join '; ')) }
$health += [string]("savings plans: " + $(if ($spOk) { $(if ($savingsPlans.Count) { ($savingsPlans -join ', ') + ' - NOT counted above; they discount compute spend broadly, so a family shown as unreserved may already be covered by one' } else { 'none' }) } else { 'COULD NOT BE READ' }))
# Always emitted, stable title: a permanent audit line saying what each source returned.
# THREE separate real bugs reached the user as silence before this existed (an invalid ARG
# query, an empty catalog, and a malformed OData filter) — each time the check just quietly
# used worse data. The cost of one low-severity row is trivial against that.
$items += [pscustomobject]@{
    Title    = 'Reservation check: source diagnostics'
    Detail   = (($health -join '; ') + $(if ($gaps.Count) { ' | ISSUES: ' + ($gaps -join ' | ') } else { '' }))
    Severity = 'low'
    ResourceId = $null
}

# Evidence is prefixed onto EVERY failing item by Add-CheckFindings, so a portfolio-wide
# summary here would repeat down the whole list while saying nothing about the row it sits on.
# Each finding below is written to stand alone, so the summary is only worth showing on the
# PASS row — which is exactly the case where there are no findings to carry it.
$evidence = $null
if (-not $items.Count) {
    $evidence = ("$(@($reservations).Count) VM reservation(s) covering $(Format-Units $resUnits) units, " +
                 "$vmCount running instance(s) needing $(Format-Units $runUnits)" +
                 $(if ($deadCnt) { ", $deadCnt deallocated" } else { '' }))
}

[pscustomobject]@{
    Name     = 'Reserved VM instance coverage'
    Severity = 'medium'
    Evidence = $evidence
    Fix      = ('Match reserved units to steady-state running units per region and size-flexibility group: ' +
                'buy where you are short, and for idle units switch the reservation to Shared scope, turn ' +
                'instance size flexibility on, or exchange it for the size/region you actually run.')
    Items    = $items
}

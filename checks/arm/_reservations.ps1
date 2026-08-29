<#
  Reserved VM instance coverage — the math, in one place.

  PURE: no cmdlets, no network, no Az context. vm-reservation-coverage.ps1 does the
  fetching and hands the four shapes below to Get-CoverageGroups / Get-ReservationFindings.
  That split is what makes the logic testable — ps/tests/reservation-coverage.ps1 runs
  every branch against fixtures with no tenant.

  Shapes (every field optional except where noted; the fetcher normalises):
    Instance     @{ Id; Name; Size; Power; Loc; Sub; Count }
    Reservation  @{ Id; Name; Sku; Loc; Quantity; Term; Expiry; ScopeType; Scopes;
                    Isf; Renew; Util; UtilGrain }
    Ratios       hashtable: region(lower) -> hashtable: size(lower) -> @{ Group; Ratio }
    Recommend    @{ Sku; Loc; Sub; Quantity; Savings1Y; Savings3Y; Currency; LookBack; Scope }
#>

# Units are RAW instance-size-flexibility ratios. Microsoft does not normalise them to 1
# for the smallest SKU in a group (Ddsv5 Series starts at 2), but both sides of every
# comparison here use the same scale, so normalising would change nothing. Don't add it.
$script:EPS = 0.01

# VM series that can NEVER draw a reservation discount, so counting them as "uncovered"
# invents a shortfall you cannot buy your way out of. A-series (NOT Av2) and G/GS-series
# per the purchase-restriction list; Spot is handled separately because Azure does not
# offer reservations for Spot VMs at all.
function Test-ReservationEligible {
    param([string]$Size, [string]$Priority)
    if ("$Priority" -match '(?i)spot') { return $false }
    $s = "$Size"
    if ($s -match '(?i)^(Basic|Standard)_A\d+[a-z]*$') { return $false }   # A-series; Av2 ends _v2
    if ($s -match '(?i)^Standard_GS?\d+') { return $false }               # G / GS series
    return $true
}

# Reservations for these series stopped being purchasable or RENEWABLE on 2026-07-01.
# Auto-renew silently does nothing for them, so an expiring reservation on this list drops
# straight to pay-as-you-go with no warning from Azure.
# Explicit patterns, not derived ones: a derived "[a-z]*" swallowed the 's' and made
# D4s_v3 match Dv3. Ordered most-specific first, and the s-variants precede their
# non-s siblings. Term matters — the v3 families lost BOTH terms, the rest only 1-year.
$script:RETIRED_ALL = [ordered]@{      # no purchase or renewal, either term
    'Dsv3' = '^D\d+(-\d+)?s_v3$'; 'Dv3' = '^D\d+(-\d+)?_v3$'
    'Esv3' = '^E\d+(-\d+)?s_v3$'; 'Ev3' = '^E\d+(-\d+)?_v3$'
}
$script:RETIRED_1Y = [ordered]@{       # 1-year term only
    'Dsv2' = '^D\d+(-\d+)?s_v2$';  'Dv2'  = '^D\d+(-\d+)?_v2$'
    'Ds'   = '^DS\d+(-\d+)?$';     'D'    = '^D\d+$'
    'Fsv2' = '^F\d+s_v2$';          'Fs'   = '^F\d+s$';        'F' = '^F\d+$'
    'Amv2' = '^A\d+m_v2$';          'Av2'  = '^A\d+m?_v2$'
    'Bv1'  = '^B\d+m?s$'
    'Gs'   = '^GS\d+$';             'G'    = '^G\d+$'
    'Lsv2' = '^L\d+s_v2$';          'Ls'   = '^L\d+s$'
}

function Get-RetiredSeries {
    <# The retired series name for a SKU, or $null. Since 2026-07-01 these cannot be bought
       or RENEWED — auto-renew stays on and silently does nothing. #>
    param([string]$Sku, [string]$Term)
    $n = "$Sku" -replace '(?i)^(Standard|Basic)_', ''
    foreach ($k in $script:RETIRED_ALL.Keys) {
        if ($n -match ('(?i)' + $script:RETIRED_ALL[$k])) { return $k }
    }
    if ("$Term" -eq 'P1Y') {
        foreach ($k in $script:RETIRED_1Y.Keys) {
            if ($n -match ('(?i)' + $script:RETIRED_1Y[$k])) { return $k }
        }
    }
    return $null
}

function Test-BillablePower {
    <# A VM consumes its reservation unless it is DEALLOCATED. 'stopped' — stopped but not
       deallocated — is still billed for compute and still consumes the reservation; that
       distinction is the whole "machines are turned off" question, and inverting it
       inverts the headline finding. An unknown/blank power state counts as billable: that
       errs toward "no spare capacity", which is the safe direction to be wrong in. #>
    param([string]$Power)
    return ("$Power" -notmatch '(?i)deallocat')
}

function Format-IsfGroup {
    <# The catalog names flexibility groups verbosely and per-OS, e.g. "Virtual Machines
       Dsv6-series Linux". A reservation covers COMPUTE regardless of operating system —
       Windows licensing is billed separately — so the Linux and Windows variants are one
       pool, and keeping them apart would split it and over-report every shortfall. Strip
       both the prefix and the OS suffix: shorter to read, and one pool per family. #>
    param([string]$Group)
    $g = "$Group" -replace '(?i)^virtual machines\s+', ''
    $g = $g -replace '(?i)\s+(linux|windows)$', ''
    return $g.Trim()
}

function Get-SizeIsf {
    <# Flexibility group + ratio for a VM size in a region. #>
    param($Ratios, [string]$Region, [string]$Size)
    $reg = "$Region".ToLower(); $sz = "$Size".ToLower()
    if ($Ratios -and $Ratios.ContainsKey($reg) -and $Ratios[$reg].ContainsKey($sz)) {
        $r = $Ratios[$reg][$sz]
        return [pscustomobject]@{ Group = (Format-IsfGroup $r.Group); Ratio = [double]$r.Ratio; Degraded = $false }
    }
    # No catalog row for this size. Fall back to exact-size matching: the size becomes its
    # own group at ratio 1. Arithmetically sound, but blind to instance size flexibility —
    # so Degraded rides along and the caller MUST say so rather than imply group math ran.
    return [pscustomobject]@{ Group = "$Size"; Ratio = 1.0; Degraded = $true }
}

function Get-CoverageRow {
    <# Fetch-or-create the (region x group) accumulator inside $Map. #>
    param([hashtable]$Map, [string]$Region, [string]$Group)
    $k = "$Region|$Group".ToLower()
    if (-not $Map.ContainsKey($k)) {
        $Map[$k] = [pscustomobject]@{
            Region = "$Region"; Group = "$Group"; Degraded = $false
            ReservedUnits = 0.0; RunningUnits = 0.0; DeallocatedUnits = 0.0
            DeallocatedCount = 0; Reservations = @()
            RunningSizes = @{}; RunningSubs = @{}; SizeRatios = @{}
            # Named rows + an unknown-power tally, so "you are running 9 machines" can be
            # audited against the portal instead of being taken on trust.
            RunningRows = @(); UnknownPower = 0; MissingRatio = @()
        }
    }
    return $Map[$k]
}

function Get-CoverageGroups {
    <# Fold instances + reservations into one row per (region x flexibility group). #>
    param($Instances, $Reservations, $Ratios)
    $groups = @{}

    foreach ($i in @($Instances)) {
        if (-not $i) { continue }
        $isf   = Get-SizeIsf $Ratios $i.Loc $i.Size
        $row   = Get-CoverageRow $groups $i.Loc $isf.Group
        $count = if ($i.Count) { [double]$i.Count } else { 1.0 }
        $units = $isf.Ratio * $count
        if ($isf.Degraded) { $row.Degraded = $true; $row.MissingRatio += "$($i.Size)" }
        if (Test-BillablePower $i.Power) {
            $row.RunningUnits += $units
            $row.RunningSizes["$($i.Size)"] = [double]$row.RunningSizes["$($i.Size)"] + $count
            $row.SizeRatios["$($i.Size)"] = $isf.Ratio
            $row.RunningSubs["$($i.Sub)"]   = [double]$row.RunningSubs["$($i.Sub)"] + $units
            $row.RunningRows += [pscustomobject]@{ Name = "$($i.Name)"; Size = "$($i.Size)"
                                                   Count = $count; Kind = "$($i.Kind)"; Id = "$($i.Id)" }
            if (-not "$($i.Power)") { $row.UnknownPower += [int]$count }
        } else {
            $row.DeallocatedUnits += $units
            $row.DeallocatedCount += [int]$count
        }
    }

    foreach ($r in @($Reservations)) {
        if (-not $r) { continue }
        $isf = Get-SizeIsf $Ratios $r.Loc $r.Sku
        $row = Get-CoverageRow $groups $r.Loc $isf.Group
        if ($isf.Degraded) { $row.Degraded = $true; $row.MissingRatio += "$($r.Sku)" }
        # Copy rather than Add-Member onto the caller's object: the fetcher may hand us
        # hashtables or pscustomobjects, and mutating its inputs is a nasty way to share state.
        $row.ReservedUnits += ($isf.Ratio * [double]$r.Quantity)
        $row.Reservations += [pscustomobject]@{
            Id = $r.Id; Name = $r.Name; Sku = $r.Sku; Loc = $r.Loc; Quantity = $r.Quantity
            Term = $r.Term; Expiry = $r.Expiry; ScopeType = $r.ScopeType; Scopes = @($r.Scopes)
            Isf = $r.Isf; Renew = $r.Renew; Util = $r.Util; UtilGrain = $r.UtilGrain
            Ratio = $isf.Ratio; Units = ($isf.Ratio * [double]$r.Quantity)
        }
    }

    return @($groups.Values)
}

function Format-Units {
    param([double]$N)
    if ([math]::Abs($N - [math]::Round($N)) -lt $script:EPS) { return "$([int][math]::Round($N))" }
    return "$([math]::Round($N, 2))"
}

function Get-BaseSku {
    <# The unit of account for a group's findings. "3 x Standard_D2lds_v5" is something a
       consultant can act on; "6 units" is an internal flexibility-ratio number nobody buys.
       Use the reservation they actually own with the largest quantity — that is the SKU they
       already think in (the user described their own estate as "8 x D2s_v5"). #>
    param($Group)
    $b = @($Group.Reservations | Sort-Object -Property Quantity -Descending | Select-Object -First 1)
    if ($b.Count -and $b[0].Sku) {
        $r = [double]$b[0].Ratio
        return [pscustomobject]@{ Sku = $b[0].Sku; Ratio = $(if ($r -gt 0) { $r } else { 1.0 }) }
    }
    # No reservation here yet — count in the size you run most of, so "short by 12 x
    # Standard_D4as_v5" still reads as something you could go and buy. Its REAL flexibility
    # ratio matters: hardcoding 1.0 reported 3 x D2s_v6 + 1 x D4s_v6 (10 ratio units) as
    # "10 x D2s_v6" instead of 5, inflating every unreserved family by its own ratio.
    $top = @($Group.RunningSizes.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1)
    if (-not $top.Count) { return $null }
    $sz = "$($top[0].Name)"
    $ratio = [double]$Group.SizeRatios[$sz]
    if ($ratio -le 0) { $ratio = 1.0 }
    return [pscustomobject]@{ Sku = $sz; Ratio = $ratio; Approx = $true }
}

function Short-Sku {
    <# "Standard_" is on every size and carries no information; details mention sizes a lot. #>
    param([string]$Sku)
    return ("$Sku" -replace '(?i)^Standard_', '')
}

function Format-Equiv {
    <# Units expressed as a count of the base SKU, e.g. "18 x Standard_D2lds_v5". #>
    param([double]$Units, $Base)
    if (-not $Base) { return "$(Format-Units $Units) units" }
    return "$(Format-Units ($Units / $Base.Ratio)) x $(Short-Sku $Base.Sku)"
}

function Format-Held {
    <# The reserved total in machine-equivalents, marked as an EQUIVALENT when the pool holds
       more than one size. Without that mark "reserved 7 x E2s_v5" reads as an inventory claim
       and is wrong when you actually own 5 x E2s_v5 + 1 x E4s_v5 - the exact confusion this
       check has already caused once. Costs 11 characters, and only when it matters. #>
    param($Group, $Base)
    $txt = Format-Equiv $Group.ReservedUnits $Base
    $skus = @(@($Group.Reservations) | ForEach-Object { "$($_.Sku)".ToLower() } | Sort-Object -Unique)
    if ($skus.Count -gt 1) { return "$txt-equivalent" }
    return $txt
}

function Format-Reserved {
    <# What you actually own in this group, NAMING the reservations.

       The equivalent total is a DERIVED number. Stating it alone ("You reserved 7 x
       Standard_E2s_v5") reads as a literal inventory claim and is flatly wrong whenever the
       group holds mixed SKUs — 5 x E2s_v5 plus 1 x E4s_v5 is also "7 x E2s_v5 equivalent",
       but you own six reservations of two sizes, not seven of one. Always list the real
       rows so the number can be reconciled against the portal. #>
    param($Group, $Base)
    $rs = @($Group.Reservations)
    if (-not $rs.Count) { return 'You have no reservation here' }
    $list = (@($rs | ForEach-Object {
        $n = if ($_.Name) { "$($_.Name): " } else { '' }
        "$n$(Format-Units ([double]$_.Quantity)) x $($_.Sku)" }) -join '; ')
    $skus = @($rs | ForEach-Object { "$($_.Sku)".ToLower() } | Sort-Object -Unique)
    if ($rs.Count -eq 1) { return "You have $list" }
    if ($skus.Count -eq 1) { return "You have $list, $(Format-Equiv $Group.ReservedUnits $Base) in total" }
    return "You have $list - mixed sizes, together the equivalent of $(Format-Equiv $Group.ReservedUnits $Base)"
}

function Get-ReservationFindings {
    <# SIMPLE MATH, deliberately.

       Per region x flexibility group: add up what you RESERVED, add up what you RUN, and
       report the difference. That is the whole model, and it matches how reservations
       actually behave — you buy a D2s_v5 and it becomes a POOL that any machine in that
       family can draw on, sized by the flexibility ratio.

       It is approximate by nature and that is fine: Azure applies the benefit hour by hour,
       first come first served, so no tool can say which individual machine was covered
       without the billing records. Earlier versions tried (per-instance billing attribution,
       measured hour aggregation) and produced answers that were harder to trust, not easier.
       Report the shortfall per family and let the consultant act on it.

       -InventoryOk / the per-group Degraded flag still gate everything: without real
       inventory or real flexibility ratios the comparison is withheld, never guessed. #>
    param($Groups, $Recommendations, [datetime]$Now = [datetime]::UtcNow,
          [bool]$InventoryOk = $true, [int]$MaxBuys = 10, [double]$MinSavings = 50,
          [bool]$SavingsPlansKnown = $true)
    $items = @()

    foreach ($g in @($Groups)) {
        $canCompare = ($InventoryOk -and -not $g.Degraded)
        $base = Get-BaseSku $g
        $where = "$($g.Group) in $($g.Region)"
        $resIds = @($g.Reservations | ForEach-Object { $_.Id } | Where-Object { $_ })
        # THE FAMILY IS THE SUBTASK, so the family is the identity. Not a reservation id —
        # Dsv5 holds two reservations and "the first one" depends on hashtable order, so the
        # key flipped between runs, orphaning the remediation state and minting a phantom
        # "verified remediated" row each time. Not the title either: renaming the group
        # (stripping the catalog's OS suffix) did exactly that to two families. A synthetic
        # key survives both, and survives the verdict changing from short to surplus.
        $famKey = "family:$($g.Region)/$($g.Group)".ToLower()
        $diff = $g.RunningUnits - $g.ReservedUnits           # +ve = short, -ve = surplus
        # Ignore dust: a fractional unit either way is not worth a finding. FLAT, never a
        # percentage of the pool. The old 2% arm scaled the blind spot with the estate, which
        # is backwards — 2% of a 118-unit Dsv5 pool on one customer tenant was 2.36 units, so a whole
        # missing D2s_v5 (59 reserved vs 58 running) went unreported in both directions until
        # the user found it by hand on 2026-08-14. The bigger the pool, the more a relative
        # floor hides, and a missing machine costs the same whatever it sits next to.
        $floor = 0.5
        $sizes = (($g.RunningSizes.GetEnumerator() | Sort-Object Name |
                   ForEach-Object { "$($_.Value)x $(Short-Sku $_.Name)" }) -join ', ')
        # "running 5 x D2s_v6 (5x D2s_v6)" says the same thing twice. The mix only earns its
        # space when it is NOT already the headline number — i.e. more than one size, or one
        # size that differs from the base SKU the sentence counts in.
        $oneSize = @($g.RunningSizes.Keys)
        if ($oneSize.Count -eq 1 -and $base -and "$($oneSize[0])".ToLower() -eq "$($base.Sku)".ToLower()) { $sizes = '' }
        # A savings plan is not a reservation and lives under a different provider. If we
        # could not read them, "nothing is reserved here" might simply be wrong.
        $spCaveat = if (-not $SavingsPlansKnown) {
            ' Savings plans unreadable, so this family may already be covered by one.'
        } else { '' }
        $dealloc = if ($g.DeallocatedCount -gt 0) { ", +$($g.DeallocatedCount) deallocated" } else { '' }

        # VERDICT FIRST, then the two numbers that justify it, then what it costs. The detail
        # shows inside the card, so a 450-character paragraph does not fit — and the reader is
        # scanning, not studying. "Reserved:" / "Running:" as labels beats a flowing sentence
        # for exactly that: the two numbers the verdict rests on are found without reading.
        $nres = @($g.Reservations).Count
        $plural = if ($nres -ne 1) { 's' } else { '' }
        $running = "Running: $(Format-Equiv $g.RunningUnits $base)$(if ($sizes) { " ($sizes)" })$dealloc."
        if ($canCompare -and $diff -gt $floor) {
            $have = if ($nres) { "Reserved: $(Format-Held $g $base) across $nres reservation$plural." }
                    else { 'Reserved: nothing in this family.' }
            # Name the consequence. "Short by 3" is a number; "3 bill at full price" is a reason
            # to act, and it is the sentence the consultant repeats to the customer.
            $costs = if ($nres) { "The $(Format-Equiv $diff $base) not covered bills at full pay-as-you-go price." }
                     else { 'All of it bills at full pay-as-you-go price.' }
            $items += [pscustomobject]@{
                Title    = $(if ($g.ReservedUnits -gt $script:EPS) { "Short on reservations: $($g.Group) in $($g.Region)" }
                             else { "No reservation for $($g.Group) in $($g.Region)" })
                Detail   = ("Buy $(Format-Equiv $diff $base). $have $running $costs" +
                            $(if ($g.ReservedUnits -le $script:EPS) { $spCaveat } else { '' }))
                Severity = 'medium'
                ResourceId = $famKey
            }
        }
        elseif ($canCompare -and $diff -lt (-1 * $floor) -and $g.ReservedUnits -gt $script:EPS) {
            $items += [pscustomobject]@{
                Title    = "Surplus reservation: $($g.Group) in $($g.Region)"
                Detail   = ("You are paying for $(Format-Equiv ([math]::Abs($diff)) $base) that nothing uses. " +
                            "Reserved: $(Format-Held $g $base) across $nres reservation$plural. $running " +
                            'Exchange it for a size or region you do run, or let it expire.')
                Severity = 'high'
                ResourceId = $famKey
            }
        }

        foreach ($r in @($g.Reservations)) {
            $tag = if ($r.Name) { "$($r.Name)" } else { "$($r.Sku) x$($r.Quantity)" }

            # Reservations for these series stopped being sold or RENEWED on 2026-07-01.
            $retired = Get-RetiredSeries $r.Sku $r.Term
            if ($retired) {
                $when = if ($r.Expiry) { " It expires $(([datetime]$r.Expiry).ToString('yyyy-MM-dd'))." } else { '' }
                $renew = if ("$($r.Renew)" -eq 'True') { ' Auto-renew is ON and will NOT work for this series - it fails silently.' } else { '' }
                $items += [pscustomobject]@{
                    Title    = "Reservation '$tag' is for a retired series and cannot be renewed"
                    Detail   = ("Move to a savings plan or a current series before it expires. " +
                                "$(Short-Sku $r.Sku) is in the retired $retired series - since 1 Jul 2026 Azure no " +
                                "longer sells or renews it.$when$renew Plan 6-12 months ahead.")
                    Severity = 'high'
                    ResourceId = $r.Id
                }
            }
            elseif ($r.Expiry) {
                $days = [int]([datetime]$r.Expiry - $Now).TotalDays
                if ($days -le 60 -and "$($r.Renew)" -ne 'True') {
                    $items += [pscustomobject]@{
                        Title    = "Reservation '$tag' expires with auto-renew off"
                        Detail   = ("Turn auto-renew on, or plan the loss. Expires " +
                                    "$(([datetime]$r.Expiry).ToString('yyyy-MM-dd')), in $days days. On that " +
                                    "day $(Format-Equiv $r.Units $base) goes back to full pay-as-you-go price.")
                        Severity = 'high'
                        ResourceId = $r.Id
                    }
                }
            }

            # Both of these break the POOL: the reservation stops being usable by anything
            # other than an exact match, which is the whole premise of the maths above.
            if ($canCompare -and "$($r.Isf)" -eq 'Off') {
                $other = @($g.RunningSizes.Keys | Where-Object { "$_".ToLower() -ne "$($r.Sku)".ToLower() })
                if ($other.Count) {
                    $items += [pscustomobject]@{
                        Title    = "Reservation '$tag' has instance size flexibility off"
                        Detail   = ("Turn instance size flexibility on - free, no redeploy. It only covers " +
                                    "$(Short-Sku $r.Sku) exactly, so $(@($other | ForEach-Object { Short-Sku $_ }) -join ', ') " +
                                    'in the same family cannot draw on it.')
                        Severity = 'medium'
                        ResourceId = $r.Id
                    }
                }
            }
            if ($canCompare -and "$($r.ScopeType)" -eq 'Single') {
                $inScope = 0.0
                foreach ($sc in @($r.Scopes)) {
                    $id = ("$sc" -split '/')[-1]
                    foreach ($k in $g.RunningSubs.Keys) {
                        if ("$k" -and "$id" -and "$k".ToLower() -eq "$id".ToLower()) { $inScope += [double]$g.RunningSubs[$k] }
                    }
                }
                if ($inScope -lt ($r.Units - $script:EPS)) {
                    $items += [pscustomobject]@{
                        Title    = "Reservation '$tag' is locked to one subscription"
                        Detail   = ("Switch it to Shared scope. It is locked to one subscription, and inside " +
                                    "that subscription there is only $(Format-Equiv $inScope $base) for it to " +
                                    "cover out of the $(Format-Equiv $r.Units $base) it holds - while " +
                                    "$(Format-Equiv $g.RunningUnits $base) runs across the family. The rest is " +
                                    'paid for and idle.')
                        Severity = 'high'
                        ResourceId = $r.Id
                    }
                }
            }
        }
    }

    # --- purchase candidates: ONE advisory item, stable title -----------------------------
    $ranked = @(@($Recommendations) | Where-Object { $_ } | ForEach-Object {
        $best = [math]::Max([double]$(if ($_.Savings1Y) { $_.Savings1Y } else { 0 }),
                            [double]$(if ($_.Savings3Y) { $_.Savings3Y } else { 0 }))
        $_ | Add-Member -NotePropertyName Best -NotePropertyValue $best -Force -PassThru
    } | Sort-Object -Property Best -Descending)
    $dead    = @($ranked | Where-Object { $null -ne $_.RegionActive -and -not $_.RegionActive })
    $live    = @($ranked | Where-Object { $null -eq $_.RegionActive -or $_.RegionActive })
    $trivial = @($live | Where-Object { $_.Best -lt $MinSavings })
    $worth   = @($live | Where-Object { $_.Best -ge $MinSavings })
    $shown   = @($worth | Select-Object -First $MaxBuys)

    # ⚠️ ONLY when there is something to buy (2026-08-18, user's call). This used to fire on
    # `$ranked.Count`, i.e. whenever Azure returned ANY recommendation — so a month where every
    # suggestion was filtered out as trivial or dead-region still produced a finding whose whole
    # text was "Azure suggested some purchases, but none are worth acting on. Not shown: 31 for
    # regions you no longer run anything in (...)". That is a finding that says there is no
    # finding: nothing to act on, counted against the tenant's score, and re-created on every
    # run. The drop counts still ride along with a real recommendation (the `Not shown:` tail),
    # and the always-emitted "source diagnostics" item records how many came back either way —
    # so suppressing this is not the silent-cap the check's own doctrine forbids.
    if ($shown.Count) {
        $lines = @()
        foreach ($rec in $shown) {
            $cur  = if ($rec.Currency) { "$($rec.Currency) " } else { '$' }
            $save = @()
            if ($rec.Savings1Y) { $save += "1yr ~$cur$([math]::Round([double]$rec.Savings1Y))" }
            if ($rec.Savings3Y) { $save += "3yr ~$cur$([math]::Round([double]$rec.Savings3Y))" }
            $line = "$($rec.Quantity) x $(Short-Sku $rec.Sku) in $($rec.Loc) ($($save -join ' / '), $($rec.Scope))"
            if ($rec.Savings3Y -and -not $rec.Savings1Y) { $line += ' [3yr only - check it is not temporary]' }
            $lines += $line
        }
        $why = @()
        $overflow = $worth.Count - $shown.Count
        if ($overflow -gt 0)      { $why += "$overflow that save less than these" }
        if ($trivial.Count -gt 0) {
            # Name the currency. "under 50" alone is a bare number the reader has to guess at,
            # and these lists mix currencies by subscription.
            $tcur = @($trivial | ForEach-Object { $_.Currency } | Where-Object { $_ } | Select-Object -First 1)
            $why += "$($trivial.Count) saving less than $(if ($tcur.Count) { "$($tcur[0]) " } else { '$' })$MinSavings over the term"
        }
        if ($dead.Count -gt 0) {
            $why += "$($dead.Count) for regions you no longer run anything in (" +
                    ((@($dead | ForEach-Object { $_.Loc } | Sort-Object -Unique) -join ', ')) + ')'
        }
        $head = 'Buy, best first: ' + ($lines -join '; ') + '.'
        $tail = if ($why.Count) { ' Not shown: ' + ($why -join ', ') + '.' } else { '' }
        $items += [pscustomobject]@{
            Title = 'Reservation purchase opportunities'; Detail = "$head$tail"
            Severity = 'medium'; ResourceId = $null
        }
    }

    return @($items)
}

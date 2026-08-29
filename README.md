# AzPosture

Measure an Azure and Entra ID tenant against a maintained checklist of 130 read-only
checks across security, cost, reliability and governance. It runs on your own machine,
under your own sign-in. Nothing is installed in the tenant and nothing is uploaded: the
output is `findings.json` on your disk, and it is yours to keep.

```powershell
Install-Module AzPosture -Scope CurrentUser -AllowPrerelease
Invoke-AzPosture -TenantId contoso.onmicrosoft.com
```

About fifteen minutes later:

```
AzPosture 0.1.0 · checklist 2026-08-18 · 130 checks selected
read-only · nothing is installed in the tenant · nothing is uploaded

AZPOSTURE::SIGNIN Microsoft Graph · sign in as yourself; every scope requested is read-only
AZPOSTURE::CONNECTED Microsoft Graph as you@contoso.com
AZPOSTURE::SCOPES Application.Read.All, AuditLog.Read.All, Directory.Read.All, Policy.Read.All, ...
AZPOSTURE::SIGNIN Azure · the Reader role on your subscriptions is enough
AZPOSTURE::CONNECTED Azure as you@contoso.com
           3 subscription(s) readable
identity   43 checks
estate     87 checks

7 critical · 53 high · 46 medium · 24 low   (61 controls pass, 66 fail, 3 not assessed)
score      58 / 100   (85+ strong · 60 to 84 fair · under 60 at risk)
AZPOSTURE::DONE
wrote      ./azposture/2026-08-29-1532/findings.json
           ./azposture/2026-08-29-1532/summary.json
next       open the report, then book the readout if you want a second opinion on it
```

The numbers above are illustrative. Yours will differ.

## What it checks

Two planes, two read-only roles.

| Plane | Checks | Runs over | Role needed | Licence |
|---|---|---|---|---|
| Identity (Entra ID) | 43 | Microsoft Graph | Global Reader | 28 run on any tenant · 9 need Entra ID P1 · 6 need P2 |
| Estate (Azure resources, cost, CAF, WAF) | 87 | Azure Resource Graph, a few ARM reads | Reader on subscriptions | none |

A check that cannot run is reported as **not assessed, with the reason**. It is never a
silent pass. That covers a missing licence, a missing role, a missing module, and a check
that threw.

List the checklist without signing in:

```powershell
Get-AzPostureCheck                                   # all 130
Get-AzPostureCheck -Plane Identity -Severity critical, high
Get-AzPostureCheck -Framework cost, caf, waf
```

## Prerequisites

- PowerShell 7.2 or later (Windows, macOS, Linux)
- `Microsoft.Graph.Authentication` (installed automatically as a dependency)
- For the estate plane: `Az.Accounts` and `Az.ResourceGraph`. Without them the 87 estate
  checks are reported as not assessed and the identity plane still runs in full.

```powershell
Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser
```

## Running

```powershell
Invoke-AzPosture -TenantId <tenant id or domain>            # both planes
Invoke-AzPosture -TenantId <tenant> -Plane Identity         # Graph only, no Az modules needed
Invoke-AzPosture -TenantId <tenant> -UseDeviceCode          # headless or remote shells
Invoke-AzPosture -TenantId <tenant> -Check id-long-lived-creds, arm-kv-rbac
Invoke-AzPosture -TenantId <tenant> -OutputFolder ~/reports -PassThru
```

An existing `Connect-MgGraph` or `Connect-AzAccount` session for the same tenant is
reused when it already carries the scopes needed. Sessions the module opens are left in
place afterwards so a re-run next month does not prompt again.

## What leaves your machine

Nothing. Sign-in goes to Microsoft; every request is a read; the findings are written to
the folder you chose. There is no telemetry, no upload endpoint, and no account.

## Output

`findings.json` holds one row per finding with the check key, framework, domain,
severity, status (`pass`, `fail`, `skip`), the measured detail, the fix, the resource id
where one exists, and the check's own reasoning: why it matters and what the target is.
`summary.json` holds the tally, the weighted score (critical 4, high 3, medium 2, low 1)
and which checklist version produced it.

## The checklist

The checklist is versioned and maintained against the platform: checks are added when
Azure ships something new and revised when guidance moves. Every run records which
checklist version it measured against, so two reports six months apart are comparable.
The date in `checks.json` is the checklist's last change.

## Licence

MIT. See `LICENSE`.

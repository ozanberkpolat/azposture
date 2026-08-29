# AzPosture

Measure an Azure and Entra ID tenant against a maintained checklist of 130 read-only
checks across security, cost, reliability and governance. It runs on your own machine,
under your own sign-in. Nothing is installed in the tenant and nothing is uploaded: the
output is `findings.json` on your disk, and it is yours to keep.

```powershell
Install-Module AzPosture -Scope CurrentUser -AllowPrerelease
Invoke-AzPosture
```

That signs you in and runs against the tenant you land in. Pass `-TenantId` to pick one.

About fifteen minutes later:

```
AzPosture 0.1.0 · checklist 2026-08-18 · 130 checks selected
read-only · nothing is installed in the tenant · nothing is uploaded

AZPOSTURE::SIGNIN Azure · Microsoft's own Azure PowerShell app, your identity, read-only use · no consent prompt
AZPOSTURE::CONNECTED Azure as you@contoso.com
           tenant 00000000-0000-0000-0000-000000000000
AZPOSTURE::CONNECTED Microsoft Graph · through the same sign-in
AZPOSTURE::SCOPES as granted to your sign-in
           3 subscription(s) readable
identity   43 checks
estate     87 checks

7 critical · 53 high · 46 medium · 24 low   (61 controls pass, 66 fail, 3 not assessed)
score      58 / 100   (85+ strong · 60 to 84 fair · under 60 at risk)
AZPOSTURE::DONE
wrote      ./azposture/2026-08-29-1532/findings.json
           ./azposture/2026-08-29-1532/summary.json
next       open the report, then get in touch if you want a second opinion on it
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

## Who can run it

A **Global Reader** for the identity checks and **Reader** on the subscriptions for the
estate checks. No administrator consent, no app registration.

Sign-in goes through Microsoft's own **Azure PowerShell** app, which every tenant already
authorises, so there is no approval dialog. The same sign-in yields a Microsoft Graph
token carrying what your account can read; a check that needs more than your account has
is reported as not assessed with the reason.

Some tenants block Azure PowerShell sign-in by policy. `-GraphConsent` switches to
Microsoft Graph Command Line Tools with explicit read-only scopes, which does need an
administrator's consent; the module prints the consent link if that route is refused.

Nothing is installed or registered in the tenant by any of this.

## Prerequisites

- PowerShell 7.2 or later (Windows, macOS, Linux)
- `Az.Accounts` and `Microsoft.Graph.Authentication` (installed automatically as dependencies)
- For the estate plane: `Az.ResourceGraph`. Without it the 87 estate checks are reported
  as not assessed and the identity plane still runs in full.

```powershell
Install-Module Az.ResourceGraph -Scope CurrentUser
```

## Running

```powershell
Invoke-AzPosture                                            # both planes, your home tenant
Invoke-AzPosture -TenantId <tenant id or domain>            # a specific tenant
Invoke-AzPosture -TenantId <tenant> -Plane Identity         # identity checks only
Invoke-AzPosture -GraphConsent                               # explicit Graph scopes; needs admin consent
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

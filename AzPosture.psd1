@{
    RootModule        = 'AzPosture.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '5b9a2b4e-3f7c-4c6b-9c0a-2a6f5d1e8e21'
    Author            = 'AzPosture'
    CompanyName       = 'AzPosture'
    Copyright         = '(c) AzPosture contributors. MIT licence.'
    Description       = 'Measure an Azure and Entra ID tenant against the AzPosture checklist: 130 read-only checks across security, cost, reliability and governance, run on your own machine under your own sign-in. Nothing is installed in the tenant and nothing is uploaded; the output is findings.json on your disk. Checklist 2026-08-30.'
    PowerShellVersion = '7.2'
    CompatiblePSEditions = @('Core')
    RequiredModules   = @(@{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.13.0' }, @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' })
    FunctionsToExport = @('Invoke-AzPosture', 'Get-AzPostureCheck', 'New-AzPostureReport')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    FileList          = @()
    PrivateData       = @{
        PSData = @{
            Tags = @('Azure', 'EntraID', 'Assessment', 'Posture', 'Security', 'Cost', 'Governance', 'Reliability', 'ResourceGraph', 'Graph', 'PSEdition_Core')
            Prerelease = 'preview13'
            ExternalModuleDependencies = @('Az.ResourceGraph')
            ReleaseNotes = 'Public preview. One sign-in through Microsoft Azure PowerShell serves both planes: no consent dialog, a Global Reader is enough for identity, Reader on subscriptions for the estate. Estate checks also need Az.ResourceGraph; without it or a readable subscription they are reported as not assessed, never silently skipped. -GraphConsent selects the explicit-scopes route for tenants that block Azure PowerShell.'
        }
    }
}

# dot-sourced by the CA checks: returns enabled CA policies or $null (loud-skip handled by caller)
function Get-EnabledCaPolicies {
    Get-GraphAll 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' |
        Where-Object { $_.state -eq 'enabled' }
}

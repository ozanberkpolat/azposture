# User consent to apps + admin consent workflow (authorizationPolicy + adminConsentRequestPolicy).
$p = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -OutputType PSObject
$items = @()
$grant = @($p.permissionGrantPolicyIdsAssignedToDefaultUserRole)
# empty = users cannot consent (best); the legacy/enabled policy ids mean users CAN consent
if ($grant | Where-Object { $_ -like '*ManagePermissionGrantsForSelf*' -and $_ -notlike '*low*' }) {
    $items += [pscustomobject]@{ Title = 'Users can consent to apps beyond low-risk permissions'; Detail = "permissionGrantPolicy: $($grant -join ', ')" }
} elseif ($grant.Count -gt 0 -and -not ($grant | Where-Object { $_ -like '*low*' })) {
    $items += [pscustomobject]@{ Title = 'User consent is not limited to verified/low-risk apps'; Detail = "permissionGrantPolicy: $($grant -join ', ')" }
}
try {
    $acr = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' -OutputType PSObject
    if (-not $acr.isEnabled) { $items += [pscustomobject]@{ Title = 'Admin consent request workflow is disabled'; Detail = 'Users blocked from consenting have no route to request admin approval' } }
} catch {}
[pscustomobject]@{
    Name = 'User app-consent settings'
    Severity = 'high'
    Evidence = "user consent policy: $(if ($grant.Count) { $grant -join ', ' } else { 'none (users cannot consent)' })"
    Fix = 'Limit user consent to verified publishers / low-risk permissions and enable the admin consent request workflow.'
    Items = $items
}

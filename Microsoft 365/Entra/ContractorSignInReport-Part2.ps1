# Connect to Azure Account
Connect-AzAccount -Tenant XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX -SubscriptionId XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX -AccountId "michael.valdes@cozyadmin.com"

# Sentinel Workspace Info
$WorkspaceName = "cozy-sentinel"
$WorkspaceRG = "cozy-sentinel"
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $WorkspaceRG -Name $WorkspaceName
$WorkspaceId = $workspace.CustomerId

# Connect to Microsoft Graph
Connect-MgGraph -Scopes AuditLog.Read.All, Organization.Read.All, Group.Read.All, User.Read.All, Directory.Read.All -NoWelcome

# Contractors from the group
$Contractors = Get-MgGroupMember -GroupId XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX -All

$UserLocations = ForEach ($Contractor in $Contractors){

        $Id = $Contractor.Id

    # --- Pull latest sign-in for this user from Log Analytics (SigninLogs) ---
    # Optional: limit to last 90 days for performance
    $query = @"
SigninLogs
| where TimeGenerated > ago(90d)
| where UserId == '$Id'
| order by TimeGenerated desc
| take 1
| project TimeGenerated,
          City    = tostring(LocationDetails.city),
          Country = tostring(LocationDetails.countryOrRegion)
"@

    $laResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query

    # Default values if user never signed in / no data
    $City = $null
    $Country = $null
    $LastSignInDateTime = $null

    if ($laResult.Results.Count -gt 0) {
        $row = $laResult.Results[0]
        $City = $row.City
        $Country = $row.Country
        $LastSignInDateTime = $row.TimeGenerated
    }
        # --- Get sponsor and user details from Graph ---
        $SponsorId = (Get-MGBetaUser -UserId $Id -ExpandProperty "Sponsors").Sponsors.Id


    Get-MGBetaUser -UserId $Id | Select-Object `
        GivenName,
        Surname,
        UserPrincipalName,
        DisplayName,
        @{ Name = "Division"; Expression = { $_.OnPremisesExtensionAttributes.ExtensionAttribute1 } },
        @{ Name = "Sponsor";  Expression = { (Get-MgUser -UserId $SponsorId).DisplayName } },
        @{ Name = "Group";    Expression = { $_.OnPremisesExtensionAttributes.ExtensionAttribute2 } },
        @{ Name = "City";     Expression = { $City } },
        @{ Name = "Country";  Expression = { $Country } },
        @{ Name = "Time and Date"; Expression = { $LastSignInDateTime } }
}

$Date = Get-Date -Format "MM-dd-yyy"
$UserLocations | Export-Csv "ContractorsSignInLocations - $Date.csv"
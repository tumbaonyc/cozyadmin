Connect-MgGraph -Scopes AuditLog.Read.All, Organization.Read.All, Group.Read.All, User.Read.All, Directory.Read.All -NoWelcome

$Contractors = Get-MgGroupMember -GroupId XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX -All

$UserLocations = ForEach ($Contractor in $Contractors){

        $Id = $Contractor.Id
        $AuditLog = (Get-MgAuditLogSignIn -Filter "userId eq '$Id'" -Top 1)
        $Location = $AuditLog.Location
        $LastSignInDateTime = $AuditLog.CreatedDateTime
        $SponsorId = (Get-MGBetaUser -UserId $Id -ExpandProperty "Sponsors").Sponsors.Id
        Get-MGBetaUser -UserId $Id | Select-Object `
                                                GivenName, 
                                                Surname, 
                                                UserPrincipalName, 
                                                DisplayName,
                                                @{ Name="Division"; Expression={$_.OnPremisesExtensionAttributes.ExtensionAttribute1}},
                                                @{ Name="Sponsor"; Expression={(Get-MgUser -UserId $SponsorId).DisplayName}},
                                                @{ Name="Group"; Expression={$_.OnPremisesExtensionAttributes.ExtensionAttribute2}},
                                                @{ Name="City"; Expression={$Location.City}}, 
                                                @{ Name="Country"; Expression={$Location.Country}}, 
                                                @{ Name="Time and Date"; Expression={$LastSignInDateTime}}
}

$Date = Get-Date -Format "MM-dd-yyy"
$UserLocations | Export-Csv "ContractorsSignInLocations - $Date.csv"
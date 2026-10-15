#Requires -Version 5.1
<#
.SYNOPSIS
    Reports the DEFAULT SIGN-IN METHOD of every ENABLED Entra ID account, one CSV per population.

.DESCRIPTION
    Read-only. Uses Microsoft Graph (beta) GET /users/{id}/authentication/signInPreferences, which returns
    userPreferredMethodForSecondaryAuthentication (the "Default sign-in method (Preview)" shown on a
    user's Authentication methods blade in the Entra admin center).

    Populations (mutually exclusive, evaluated in this order):
      1. Entra Admin Roles     - any enabled user with an active or PIM-eligible directory role
                                 (including via role-assignable group membership)
      2. Guests                - userType = Guest
      3. Your own populations  - OPTIONAL. The first -PopulationRules entry whose regex matches the
                                 user's -MatchProperty value wins (for example one rule per AD forest,
                                 per company name, or per UPN suffix)
      4. Synced - <domain>     - remaining directory-synced accounts, grouped by onPremisesDomainName
      5. Cloud-only members    - every remaining member account that is not directory-synced

    With no -PopulationRules the script still gives a sensible split (admins / guests / one group per
    synced AD domain / cloud-only), so it runs as-is in any tenant.

    "Enabled" = accountEnabled eq true. Licensing is NOT used to filter (a Licensed column is included).

    IMPORTANT: when system-preferred MFA is enabled for a user (SystemPreferredMfaEnabled = True), Entra
    ignores the stored default and prompts for the most secure registered method. The stored default
    still tells you what the user picked, and what they fall back to in NPS extension / AD FS flows.

.PARAMETER OutputFolder
    Folder for the CSV files (created if missing).

.PARAMETER PopulationRules
    Ordered dictionary of  'Population name' = 'regex'.  Evaluated top to bottom; first match wins.
    Use [ordered]@{...} so the evaluation order is predictable.

.PARAMETER MatchProperty
    The user property the -PopulationRules regexes are matched against.
    Default: onPremisesDistinguishedName (useful for multi-forest / multi-domain tenants).

.PARAMETER TenantId
    Optional tenant ID or domain to sign in to.

.PARAMETER CombinedFile
    Also write one combined CSV with a Group column.

.PARAMETER ShowSample
    Prints the first few users' classification inputs and stops before the per-user lookups.
    Use this first to decide what your -PopulationRules should look like.

.EXAMPLE
    .\Get-EntraDefaultSignInMethod.ps1 -ShowSample
    Look at real attribute values before deciding how to group.

.EXAMPLE
    .\Get-EntraDefaultSignInMethod.ps1 -CombinedFile
    No rules: admins, guests, one group per synced AD domain, and cloud-only members.

.EXAMPLE
    $rules = [ordered]@{
        'Fabrikam (acquired)' = 'DC=fabrikam,DC=local$'
        'Contoso HQ'          = 'DC=corp,DC=contoso,DC=com$'
    }
    .\Get-EntraDefaultSignInMethod.ps1 -PopulationRules $rules
    Split synced users by AD forest using the distinguished name.

.EXAMPLE
    .\Get-EntraDefaultSignInMethod.ps1 -MatchProperty companyName -PopulationRules ([ordered]@{
        'Fabrikam' = '^Fabrikam'
        'Contoso'  = '^Contoso'
    })
    Split by the companyName attribute instead.

.NOTES
    Delegated scopes requested (all read-only):
      User.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory,
      RoleEligibilitySchedule.Read.Directory, GroupMember.Read.All
    Sign in as at least Global Reader (or an equivalent role that can read users' authentication methods).
    Requires Microsoft.Graph.Authentication v2+ (Install-Module Microsoft.Graph.Authentication).
    The signInPreferences endpoint is BETA - Microsoft does not support beta APIs in production apps;
    this is a one-off read-only report.

    Not covered: users who are only ELIGIBLE members of a role-assignable group (PIM for Groups).
#>
[CmdletBinding()]
param(
    [string]$OutputFolder = (Join-Path $PWD 'EntraDefaultMethodReport'),
    [System.Collections.IDictionary]$PopulationRules,
    [ValidateSet('onPremisesDistinguishedName', 'onPremisesDomainName', 'companyName',
                 'department', 'officeLocation', 'userPrincipalName')]
    [string]$MatchProperty = 'onPremisesDistinguishedName',
    [string]$TenantId,
    [switch]$CombinedFile,
    [switch]$ShowSample
)

$ErrorActionPreference = 'Stop'
$g1 = 'https://graph.microsoft.com/v1.0'
$GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'   # built-in role template ID, same in every tenant

if ($PopulationRules -and $PopulationRules.Count -gt 1 -and
    $PopulationRules -isnot [System.Collections.Specialized.OrderedDictionary]) {
    Write-Warning 'PopulationRules is a plain hashtable, so rule order is not guaranteed. Use [ordered]@{...} if a user could match more than one rule.'
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Install the Graph auth module first: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication

$connect = @{
    NoWelcome = $true
    Scopes    = @(
        'User.Read.All',
        'UserAuthenticationMethod.Read.All',
        'RoleManagement.Read.Directory',
        'RoleEligibilitySchedule.Read.Directory',
        'GroupMember.Read.All'
    )
}
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect

function Invoke-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri)
    $items = New-Object System.Collections.Generic.List[object]
    while ($Uri) {
        $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($null -ne $r.value) { foreach ($v in $r.value) { $items.Add($v) } }
        $Uri = $r.'@odata.nextLink'
    }
    return $items
}

# ---------------------------------------------------------------- 1. Enabled users
Write-Host 'Reading enabled users...' -ForegroundColor Cyan
$select = 'id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,' +
          'onPremisesDistinguishedName,onPremisesDomainName,companyName,department,officeLocation,' +
          'assignedLicenses,externalUserState'
$users = @(Invoke-GraphPaged "$g1/users?`$filter=accountEnabled eq true&`$select=$select&`$top=999")
Write-Host ("  {0} enabled accounts" -f $users.Count)

$userById = @{}
foreach ($u in $users) { $userById[$u.id] = $u }

if ($ShowSample) {
    $users | Select-Object -First 15 userPrincipalName, userType, onPremisesSyncEnabled,
        onPremisesDomainName, onPremisesDistinguishedName, companyName, officeLocation | Format-Table -AutoSize | Out-Host
    Write-Host 'ShowSample set - stopping before per-user lookups.' -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------- 2. Directory roles (active + PIM-eligible)
Write-Host 'Reading directory role assignments...' -ForegroundColor Cyan
$roleDefs = @{}
foreach ($d in (Invoke-GraphPaged "$g1/roleManagement/directory/roleDefinitions")) { $roleDefs[$d.id] = $d }

$adminRoles        = @{}   # userId -> list of "Role (Active|Eligible[, scoped][, custom])"
$builtInTenantWide = @{}   # userId -> $true when at least one role is built-in AND tenant-wide
$activeGlobalAdmin = @{}   # userId -> $true when Global Administrator is ACTIVE at tenant scope

function Add-AdminRole {
    param([string]$UserId, [string]$RoleDefinitionId, [string]$ScopeId, [string]$Kind)
    $def        = $roleDefs[$RoleDefinitionId]
    $name       = if ($def) { $def.displayName } else { $RoleDefinitionId }
    $tenantWide = ([string]::IsNullOrEmpty($ScopeId) -or $ScopeId -eq '/')
    $builtIn    = ($def -and $def.isBuiltIn -eq $true)

    $tags = @($Kind)
    if (-not $tenantWide) { $tags += 'scoped' }   # administrative-unit or resource scoped
    if (-not $builtIn)    { $tags += 'custom' }

    if (-not $adminRoles.ContainsKey($UserId)) { $adminRoles[$UserId] = New-Object System.Collections.Generic.List[string] }
    $adminRoles[$UserId].Add("$name ($($tags -join ', '))")

    if ($tenantWide -and $builtIn) { $builtInTenantWide[$UserId] = $true }
    if ($tenantWide -and $Kind -eq 'Active' -and $RoleDefinitionId -eq $GlobalAdminRoleId) { $activeGlobalAdmin[$UserId] = $true }
}

$groupMemberCache = @{}
function Resolve-PrincipalToUserIds {
    param([string]$PrincipalId)
    if ($userById.ContainsKey($PrincipalId)) { return @($PrincipalId) }
    if (-not $groupMemberCache.ContainsKey($PrincipalId)) {
        try {
            $m = Invoke-GraphPaged "$g1/groups/$PrincipalId/transitiveMembers/microsoft.graph.user?`$select=id"
            $groupMemberCache[$PrincipalId] = @($m | ForEach-Object { $_.id })
        } catch {
            # Not a group (service principal / disabled user) - nothing to expand
            $groupMemberCache[$PrincipalId] = @()
        }
    }
    return @($groupMemberCache[$PrincipalId])
}

foreach ($a in (Invoke-GraphPaged "$g1/roleManagement/directory/roleAssignments")) {
    foreach ($uid in (Resolve-PrincipalToUserIds $a.principalId)) {
        if ($userById.ContainsKey($uid)) { Add-AdminRole $uid $a.roleDefinitionId $a.directoryScopeId 'Active' }
    }
}
try {
    foreach ($e in (Invoke-GraphPaged "$g1/roleManagement/directory/roleEligibilitySchedules")) {
        foreach ($uid in (Resolve-PrincipalToUserIds $e.principalId)) {
            if ($userById.ContainsKey($uid)) { Add-AdminRole $uid $e.roleDefinitionId $e.directoryScopeId 'Eligible' }
        }
    }
} catch {
    Write-Warning "Could not read PIM-eligible role assignments (needs licensing/permission): $($_.Exception.Message). Active assignments only."
}
Write-Host ("  {0} enabled users hold at least one directory role" -f $adminRoles.Count)

# ---------------------------------------------------------------- 3. Default sign-in method (batched, 20 per call)
Write-Host 'Reading default sign-in methods (batched)...' -ForegroundColor Cyan
$ids   = @($users | ForEach-Object { $_.id })
$prefs = @{}
$errs  = @{}
for ($i = 0; $i -lt $ids.Count; $i += 20) {
    $chunk = @($ids[$i..([Math]::Min($i + 19, $ids.Count - 1))])
    $todo  = $chunk
    for ($try = 1; $try -le 5 -and $todo.Count -gt 0; $try++) {
        $body = @{ requests = @($todo | ForEach-Object {
            @{ id = $_; method = 'GET'; url = "/users/$_/authentication/signInPreferences" } }) } | ConvertTo-Json -Depth 5
        $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/$batch' `
                    -Body $body -ContentType 'application/json' -OutputType PSObject
        $retry = @(); $wait = 0
        foreach ($r in $resp.responses) {
            if ($r.status -eq 200) { $prefs[$r.id] = $r.body }
            elseif ($r.status -in 429, 503, 504) {
                $retry += $r.id
                $w = 0; [void][int]::TryParse("$($r.headers.'Retry-After')", [ref]$w)
                if ($w -gt $wait) { $wait = $w }
            }
            else { $errs[$r.id] = "HTTP $($r.status): $($r.body.error.message)" }
        }
        $todo = @($retry)
        if ($todo.Count -gt 0) { Start-Sleep -Seconds ([Math]::Max($wait, 2)) }
    }
    foreach ($id in $todo) { $errs[$id] = 'Throttled - gave up after 5 attempts' }
    Write-Progress -Activity 'Reading sign-in preferences' -Status "$([Math]::Min($i + 20, $ids.Count)) / $($ids.Count)" `
        -PercentComplete (100 * [Math]::Min($i + 20, $ids.Count) / $ids.Count)
}
Write-Progress -Activity 'Reading sign-in preferences' -Completed

# ---------------------------------------------------------------- 4. Classify + build rows
$methodLabels = @{
    'sms'                 = 'SMS'
    'voiceMobile'         = 'Voice call (mobile)'
    'voiceAlternateMobile'= 'Voice call (alternate mobile)'
    'voiceOffice'         = 'Voice call (office)'
    'push'                = 'Authenticator push'
    'oath'                = 'OATH verification code'
}

function Get-Population {
    param($U)
    if ($U.userType -eq 'Guest') { return 'Guests' }
    if ($PopulationRules) {
        $value = "$($U.$MatchProperty)"
        foreach ($label in $PopulationRules.Keys) {
            if ($value -match $PopulationRules[$label]) { return "$label" }
        }
    }
    if ($U.onPremisesSyncEnabled -eq $true) {
        if ($U.onPremisesDomainName) { return "Synced - $($U.onPremisesDomainName)" }
        return 'Synced - (domain unknown)'
    }
    return 'Cloud-only members'
}

$rows = foreach ($u in $users) {
    $population = Get-Population $u
    $roles      = if ($adminRoles.ContainsKey($u.id)) { ($adminRoles[$u.id] | Sort-Object -Unique) -join '; ' } else { '' }
    $group      = if ($roles) { 'Entra Admin Roles' } else { $population }

    $raw = $null; $sysPref = $null; $err = $errs[$u.id]
    if ($prefs.ContainsKey($u.id)) {
        $raw     = $prefs[$u.id].userPreferredMethodForSecondaryAuthentication
        $sysPref = $prefs[$u.id].isSystemPreferredAuthenticationMethodEnabled
    }
    $label = if ($err) { '(lookup failed)' }
             elseif ([string]::IsNullOrWhiteSpace($raw) -or $raw -eq 'none') { '(not set)' }
             elseif ($methodLabels.ContainsKey($raw)) { $methodLabels[$raw] }
             else { "$raw" }

    # Retirement dates per Microsoft Learn (concept-sms-voice-retirement):
    #   2027-02-01  everyone, INCLUDING internal guests
    #   2027-07-01  Global Administrators and external users
    # "External" here = the account has an externalUserState or an #EXT# UPN (B2B invite/redemption).
    # Microsoft does not say whether a PIM-ELIGIBLE Global Administrator gets the later date, so only
    # ACTIVE tenant-wide Global Administrators are given July; eligible-only GAs get the earlier date.
    $isExternal = (-not [string]::IsNullOrEmpty($u.externalUserState)) -or ($u.userPrincipalName -like '*#EXT#*')
    $retire     = if ($activeGlobalAdmin.ContainsKey($u.id) -or $isExternal) { '2027-07-01' } else { '2027-02-01' }

    [pscustomobject]@{
        Group                        = $group
        DisplayName                  = $u.displayName
        UserPrincipalName            = $u.userPrincipalName
        UserType                     = $u.userType
        ExternalUser                 = if ($isExternal) { 'Yes' } else { 'No' }
        Population                   = $population
        DefaultSignInMethod          = $label
        DefaultMethodRaw             = $raw
        PhoneBasedDefault            = if ($raw -match '^(sms|voice)') { 'Yes' } else { 'No' }
        SystemPreferredMfaEnabled    = $sysPref
        AdminRoles                   = $roles
        # Conditional Access "Directory roles" targeting only works for built-in roles assigned tenant-wide.
        BuiltInTenantWideRole        = if ($builtInTenantWide.ContainsKey($u.id)) { 'Yes' } elseif ($roles) { 'No' } else { '' }
        Licensed                     = if (@($u.assignedLicenses).Count -gt 0) { 'Yes' } else { 'No' }
        OnPremSynced                 = [bool]($u.onPremisesSyncEnabled -eq $true)
        OnPremDomain                 = $u.onPremisesDomainName
        CompanyName                  = $u.companyName
        Department                   = $u.department
        OfficeLocation               = $u.officeLocation
        MsSmsVoiceRetirementDate     = $retire
        LookupError                  = $err
    }
}
$rows = @($rows)

# ---------------------------------------------------------------- 5. Export (one CSV per group that has users)
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'

# Fixed groups first, then your own / auto-detected populations alphabetically
$groupOrder = @('Entra Admin Roles', 'Guests') +
              @($rows | Select-Object -ExpandProperty Group -Unique | Where-Object { $_ -notin 'Entra Admin Roles', 'Guests' } | Sort-Object)
$usedNames = @{}
foreach ($g in $groupOrder) {
    $subset = @($rows | Where-Object { $_.Group -eq $g } | Sort-Object PhoneBasedDefault -Descending)
    if ($subset.Count -eq 0) { continue }
    $safe = ($g -replace '[^\w\-]+', '-').Trim('-')
    if (-not $safe) { $safe = 'Group' }
    if ($usedNames.ContainsKey($safe)) { $usedNames[$safe]++; $safe = "$safe-$($usedNames[$safe])" } else { $usedNames[$safe] = 1 }
    $path = Join-Path $OutputFolder ("{0}_{1}.csv" -f $stamp, $safe)
    $subset | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Host ("  {0,-45} {1,5} users -> {2}" -f $g, $subset.Count, $path)
}
if ($CombinedFile) {
    $rows | Export-Csv -Path (Join-Path $OutputFolder "$($stamp)_All-Groups.csv") -NoTypeInformation -Encoding UTF8
}

# ---------------------------------------------------------------- 6. Summary
Write-Host "`nDefault sign-in method by group:" -ForegroundColor Cyan
$rows | Group-Object Group, DefaultSignInMethod | Sort-Object Name |
    Select-Object @{n='Group / Default method'; e={ $_.Name }}, Count | Format-Table -AutoSize | Out-Host

$phone = @($rows | Where-Object PhoneBasedDefault -eq 'Yes').Count
Write-Host ("Enabled accounts with SMS/voice as the stored default: {0} of {1}" -f $phone, $rows.Count) -ForegroundColor Yellow

$adminPhone = @($rows | Where-Object { $_.Group -eq 'Entra Admin Roles' -and $_.PhoneBasedDefault -eq 'Yes' }).Count
if ($adminPhone) { Write-Warning "$adminPhone account(s) holding an Entra role have SMS/voice as their stored default." }

$unseen = @($rows | Where-Object { $_.DefaultMethodRaw -and -not $methodLabels.ContainsKey($_.DefaultMethodRaw) -and $_.DefaultMethodRaw -ne 'none' } |
           Select-Object -ExpandProperty DefaultMethodRaw -Unique)
if ($unseen.Count) { Write-Warning ("Unrecognised raw method value(s) passed through as-is: {0}" -f ($unseen -join ', ')) }
$failed = @($rows | Where-Object LookupError).Count
if ($failed) { Write-Warning "$failed account(s) failed lookup - see the LookupError column." }
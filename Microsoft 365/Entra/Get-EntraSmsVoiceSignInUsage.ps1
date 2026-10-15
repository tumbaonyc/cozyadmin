#Requires -Version 5.1
<#
.SYNOPSIS
    Finds the users who are actually completing sign-ins with SMS or voice call, from the Entra sign-in logs.

.DESCRIPTION
    Read-only. Walks the interactive sign-in logs (Microsoft Graph beta GET /auditLogs/signIns) for the
    last N days, reads the authenticationDetails of every sign-in, and counts per user how often each
    kind of method was used: SMS, voice call, an authenticator app, or anything else.

    It then joins the result with the user registration details report so you can tell two very
    different groups apart:
      * users whose phone is the only thing they have registered (they need to register something), and
      * users who already have an authenticator app or passkey registered and pick SMS/voice anyway.

    Output (in -OutputFolder):
      <stamp>_SmsVoice-Users.csv     one row per user who used SMS or voice in the window
      <stamp>_Methods-Seen.csv       every distinct authenticationMethod string found and how it was classified
      <stamp>_SmsVoice-Events.csv    one row per SMS/voice authentication step (only with -IncludeEvents)

.PARAMETER Days
    How far back to look (1-30). Entra keeps sign-in logs for 30 days with Entra ID P1/P2 and 7 days on
    Entra ID Free, so asking for more than your tenant retains simply returns less.

.PARAMETER OutputFolder
    Folder for the CSV files (created if missing).

.PARAMETER SliceHours
    Size of each query window (1-24). Lower it if a busy tenant times out on a full day at a time.

.PARAMETER SmsPattern / VoicePattern / AuthenticatorPattern
    Regexes matched against signIn.authenticationDetails[].authenticationMethod. The Graph reference
    lists the values as "SMS" and "Voice"; real logs commonly show longer strings such as
    "Text message" and "Phone call approval (Authentication phone)". The defaults cover both, and the
    Methods-Seen CSV shows every value found in YOUR tenant so you can confirm nothing was missed.

.PARAMETER IncludeEvents
    Also export one row per SMS/voice authentication step. The detail column can contain a (masked)
    phone number, so treat that file accordingly.

.PARAMETER SkipRegistrationDetails
    Do not read the user registration details report (use if it is unavailable in your tenant).

.PARAMETER TenantId
    Optional tenant ID or domain to sign in to.

.EXAMPLE
    .\Get-EntraSmsVoiceSignInUsage.ps1 -Days 7
    Quick first pass over the last week.

.EXAMPLE
    .\Get-EntraSmsVoiceSignInUsage.ps1 -Days 30 -IncludeEvents
    Full retention window, plus the per-event detail.

.NOTES
    Delegated scope requested (read-only): AuditLog.Read.All
    Sign in as at least Reports Reader, Security Reader or Global Reader.
    Requires Microsoft.Graph.Authentication v2+ (Install-Module Microsoft.Graph.Authentication).

    Things this report cannot see:
      * Only INTERACTIVE sign-ins are read. That is where a user chooses a method.
      * A sign-in whose MFA requirement was met by a claim already in the token shows as
        "Previously satisfied" and does not say which method was originally used. Those are ignored.
      * Self-service password reset verifications are not sign-ins and are not in this log.
      * /beta APIs can change and are not supported by Microsoft for production apps. This is a
        one-off, read-only report.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 30)][int]$Days = 30,
    [string]$OutputFolder         = (Join-Path $PWD 'EntraSmsVoiceSignInReport'),
    [ValidateRange(1, 24)][int]$SliceHours = 24,
    [string]$SmsPattern           = '^(SMS|Text message)',
    [string]$VoicePattern         = '(Voice|Phone call)',
    [string]$AuthenticatorPattern = '(Authenticator|Mobile app|Passwordless phone sign-in)',
    [string]$TenantId,
    [switch]$IncludeEvents,
    [switch]$SkipRegistrationDetails
)

$ErrorActionPreference = 'Stop'
$g1   = 'https://graph.microsoft.com/v1.0'
$beta = 'https://graph.microsoft.com/beta'

# Steps that are not a method the user chose
$ignorePattern = '^(Password|Previously satisfied|Satisfied by token)$'

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Install the Graph auth module first: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication

$connect = @{ NoWelcome = $true; Scopes = @('AuditLog.Read.All') }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect

function Get-HttpStatus {
    param($ErrorRecord)
    $code = 0
    try { $code = [int]$ErrorRecord.Exception.Response.StatusCode } catch { $code = 0 }
    return $code
}

function Invoke-GraphGet {
    # GET with a small retry loop for throttling and transient gateway errors
    param([Parameter(Mandatory)][string]$Uri)
    for ($attempt = 1; ; $attempt++) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        } catch {
            $code      = Get-HttpStatus $_
            $transient = ($code -in 429, 500, 502, 503, 504) -or
                         ($_.Exception.Message -match 'TooManyRequests|throttl|timed out|timeout|GatewayTimeout')
            if (-not $transient -or $attempt -ge 6) { throw }
            Start-Sleep -Seconds ([Math]::Min(60, 5 * $attempt))
        }
    }
}

function Get-MethodCategory {
    param([string]$Method)
    if ([string]::IsNullOrWhiteSpace($Method)) { return $null }
    if ($Method -match $SmsPattern)           { return 'SMS' }
    if ($Method -match $VoicePattern)         { return 'Voice' }
    if ($Method -match $AuthenticatorPattern) { return 'AuthenticatorApp' }
    if ($Method -match $ignorePattern)        { return $null }
    return 'Other'
}

function ConvertTo-UtcDateTime {
    # createdDateTime can arrive as a string or as an already-converted DateTime, depending on the
    # PowerShell / SDK version. Either way, hand back a UTC DateTime.
    param($Value)
    if ($Value -is [datetime])       { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse("$Value", [cultureinfo]::InvariantCulture, $styles)
}

# ---------------------------------------------------------------- 1. Walk the sign-in logs
$now   = (Get-Date).ToUniversalTime()
$end   = New-Object datetime ($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, $now.Second, [System.DateTimeKind]::Utc)
$start = $end.AddDays(-$Days)
Write-Host ("Reading interactive sign-ins from {0:u} to {1:u} ..." -f $start, $end) -ForegroundColor Cyan

$select    = 'id,createdDateTime,userId,userPrincipalName,userDisplayName,userType,appDisplayName,status,authenticationDetails'
$useSelect = $true

$stats       = @{}   # userId -> running totals
$methodsSeen = @{}   # authenticationMethod string -> step count
$events      = New-Object System.Collections.Generic.List[object]
$boundaryIds = New-Object 'System.Collections.Generic.HashSet[string]'   # sign-ins on the previous window's closing second
$totalRead   = 0

$sliceCount = [int][Math]::Ceiling(($end - $start).TotalHours / $SliceHours)
for ($s = 0; $s -lt $sliceCount; $s++) {
    $from = $start.AddHours($s * $SliceHours)
    $to   = $from.AddHours($SliceHours)
    if ($to -gt $end) { $to = $end }
    $filter = "createdDateTime ge {0:yyyy-MM-ddTHH:mm:ssZ} and createdDateTime le {1:yyyy-MM-ddTHH:mm:ssZ}" -f $from, $to

    Write-Progress -Activity 'Reading sign-in logs' -Status ("{0:yyyy-MM-dd HH:mm} UTC  ({1} sign-ins read)" -f $from, $totalRead) `
        -PercentComplete (100 * $s / $sliceCount)

    $uri = "$beta/auditLogs/signIns?`$filter=$filter&`$top=1000"
    if ($useSelect) { $uri += "&`$select=$select" }

    # Consecutive windows share one second ("le" this window's end, "ge" the next window's start), so
    # remember which sign-ins sat on that second and skip them when the next window returns them again.
    $nextBoundaryIds = New-Object 'System.Collections.Generic.HashSet[string]'

    while ($uri) {
        try {
            $page = Invoke-GraphGet $uri
        } catch {
            # If the service rejects $select, fall back to full objects once and carry on
            if ($useSelect -and (Get-HttpStatus $_) -eq 400) {
                Write-Warning 'The service rejected $select on sign-ins; retrying without it (slower, same result).'
                $useSelect = $false
                $uri = "$beta/auditLogs/signIns?`$filter=$filter&`$top=1000"
                continue
            }
            throw
        }

        foreach ($si in @($page.value)) {
            $id = "$($si.id)"
            if ($boundaryIds.Contains($id)) { continue }
            $when = ConvertTo-UtcDateTime $si.createdDateTime
            if ($when -ge $to) { [void]$nextBoundaryIds.Add($id) }
            $totalRead++
            $details = @($si.authenticationDetails)
            if ($details.Count -eq 0 -or [string]::IsNullOrEmpty($si.userId)) { continue }

            # Which categories appear in this sign-in, and did the phone step succeed?
            $cats = @{}
            $phoneSucceeded = $false
            $phoneSteps = @()
            foreach ($d in $details) {
                $m = "$($d.authenticationMethod)"
                if ($m) { $methodsSeen[$m] = 1 + [int]$methodsSeen[$m] }
                $cat = Get-MethodCategory $m
                if (-not $cat) { continue }
                $cats[$cat] = $true
                if ($cat -in 'SMS', 'Voice') {
                    $phoneSteps += $d
                    if ($d.succeeded -eq $true) { $phoneSucceeded = $true }
                }
            }
            if ($cats.Count -eq 0) { continue }

            if (-not $stats.ContainsKey($si.userId)) {
                $stats[$si.userId] = [pscustomobject]@{
                    UserId            = $si.userId
                    UserPrincipalName = $si.userPrincipalName
                    DisplayName       = $si.userDisplayName
                    UserType          = $si.userType
                    Sms               = 0
                    Voice             = 0
                    Authenticator     = 0
                    Other             = 0
                    PhoneSucceeded    = 0
                    PhoneFailed       = 0
                    FirstPhone        = $null
                    LastPhone         = $null
                    PhoneDays         = New-Object 'System.Collections.Generic.HashSet[string]'
                    PhoneApps         = @{}
                }
            }
            $u = $stats[$si.userId]
            if ($cats.ContainsKey('SMS'))              { $u.Sms++ }
            if ($cats.ContainsKey('Voice'))            { $u.Voice++ }
            if ($cats.ContainsKey('AuthenticatorApp')) { $u.Authenticator++ }
            if ($cats.ContainsKey('Other'))            { $u.Other++ }

            if ($phoneSteps.Count -gt 0) {
                if ($phoneSucceeded) { $u.PhoneSucceeded++ } else { $u.PhoneFailed++ }
                if ($null -eq $u.FirstPhone -or $when -lt $u.FirstPhone) { $u.FirstPhone = $when }
                if ($null -eq $u.LastPhone  -or $when -gt $u.LastPhone)  { $u.LastPhone  = $when }
                [void]$u.PhoneDays.Add($when.ToString('yyyy-MM-dd'))
                $app = "$($si.appDisplayName)"
                if ($app) { $u.PhoneApps[$app] = 1 + [int]$u.PhoneApps[$app] }

                if ($IncludeEvents) {
                    foreach ($d in $phoneSteps) {
                        $events.Add([pscustomobject]@{
                            CreatedDateTimeUtc = $when.ToString('yyyy-MM-dd HH:mm:ss')
                            UserPrincipalName  = $si.userPrincipalName
                            DisplayName        = $si.userDisplayName
                            App                = $si.appDisplayName
                            Method             = $d.authenticationMethod
                            MethodDetail       = $d.authenticationMethodDetail
                            StepRequirement    = $d.authenticationStepRequirement
                            Succeeded          = $d.succeeded
                            ResultDetail       = $d.authenticationStepResultDetail
                            SignInErrorCode    = $si.status.errorCode
                            SignInId           = $si.id
                        })
                    }
                }
            }
        }
        $uri = $page.'@odata.nextLink'
    }
    $boundaryIds = $nextBoundaryIds
}
Write-Progress -Activity 'Reading sign-in logs' -Completed
Write-Host ("  {0} interactive sign-ins read" -f $totalRead)

# ---------------------------------------------------------------- 2. What does each user have registered?
$reg = @{}
if (-not $SkipRegistrationDetails) {
    Write-Host 'Reading user registration details...' -ForegroundColor Cyan
    try {
        $uri = "$g1/reports/authenticationMethods/userRegistrationDetails?`$top=999"
        while ($uri) {
            $page = Invoke-GraphGet $uri
            foreach ($r in @($page.value)) { $reg[$r.id] = $r }
            $uri = $page.'@odata.nextLink'
        }
        Write-Host ("  {0} users in the registration report" -f $reg.Count)
    } catch {
        Write-Warning "Could not read user registration details: $($_.Exception.Message). Continuing without them."
    }
}

# ---------------------------------------------------------------- 3. Build the per-user report
$rows = foreach ($u in $stats.Values) {
    $phone = $u.Sms + $u.Voice
    if ($phone -eq 0) { continue }

    $r          = $reg[$u.UserId]
    $registered = if ($r) { @($r.methodsRegistered) } else { @() }
    $regText    = $registered -join '; '
    $hasApp     = [bool]($regText -match 'microsoftAuthenticator|softwareOneTimePasscode')
    $hasPasskey = [bool]($regText -match 'passKey|fido2|windowsHelloForBusiness')

    $finding = if (-not $r)                     { 'Used SMS/voice (registration details unavailable)' }
               elseif ($hasApp -or $hasPasskey) { 'Stronger method registered - still uses SMS/voice' }
               else                             { 'No authenticator app or passkey registered' }

    $totalMfa = $phone + $u.Authenticator + $u.Other
    $topApps  = ($u.PhoneApps.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 |
                 ForEach-Object { "$($_.Key) ($($_.Value))" }) -join '; '

    [pscustomobject]@{
        UserPrincipalName         = $u.UserPrincipalName
        DisplayName               = $u.DisplayName
        UserType                  = $u.UserType
        Finding                   = $finding
        SmsSignIns                = $u.Sms
        VoiceSignIns              = $u.Voice
        AuthenticatorAppSignIns   = $u.Authenticator
        OtherMethodSignIns        = $u.Other
        PhoneSharePercent         = [int][Math]::Round(100 * $phone / $totalMfa, 0)
        PhoneSignInsSucceeded     = $u.PhoneSucceeded
        PhoneSignInsFailed        = $u.PhoneFailed
        DaysWithPhoneSignIn       = $u.PhoneDays.Count
        FirstPhoneSignInUtc       = $u.FirstPhone.ToString('yyyy-MM-dd HH:mm')
        LastPhoneSignInUtc        = $u.LastPhone.ToString('yyyy-MM-dd HH:mm')
        TopAppsWithPhoneSignIn    = $topApps
        AuthenticatorRegistered   = if ($r) { $hasApp } else { $null }
        PasskeyOrWhfbRegistered   = if ($r) { $hasPasskey } else { $null }
        MethodsRegistered         = $regText
        StoredDefaultMethod       = if ($r) { $r.userPreferredMethodForSecondaryAuthentication } else { $null }
        SystemPreferredMfaEnabled = if ($r) { $r.isSystemPreferredAuthenticationMethodEnabled } else { $null }
        IsAdmin                   = if ($r) { $r.isAdmin } else { $null }
    }
}
$rows = @($rows | Sort-Object @{ e = { $_.SmsSignIns + $_.VoiceSignIns }; Descending = $true }, UserPrincipalName)

$methodRows = @($methodsSeen.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
    $cat = Get-MethodCategory $_.Key
    [pscustomobject]@{
        AuthenticationMethod = $_.Key
        Steps                = $_.Value
        ClassifiedAs         = if ($cat) { $cat } else { '(ignored)' }
    }
})

# ---------------------------------------------------------------- 4. Export
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'

$usersPath   = Join-Path $OutputFolder "$($stamp)_SmsVoice-Users.csv"
$methodsPath = Join-Path $OutputFolder "$($stamp)_Methods-Seen.csv"
$rows       | Export-Csv -Path $usersPath   -NoTypeInformation -Encoding UTF8
$methodRows | Export-Csv -Path $methodsPath -NoTypeInformation -Encoding UTF8
Write-Host "  Users   -> $usersPath"
Write-Host "  Methods -> $methodsPath"
if ($IncludeEvents) {
    $eventsPath = Join-Path $OutputFolder "$($stamp)_SmsVoice-Events.csv"
    $events | Export-Csv -Path $eventsPath -NoTypeInformation -Encoding UTF8
    Write-Host "  Events  -> $eventsPath"
}

# ---------------------------------------------------------------- 5. Summary
Write-Host "`nAuthentication methods seen in the last $Days day(s):" -ForegroundColor Cyan
$methodRows | Format-Table -AutoSize | Out-Host

Write-Host ("Users who signed in with SMS or voice: {0}" -f $rows.Count) -ForegroundColor Yellow
if ($rows.Count -gt 0) {
    $rows | Group-Object Finding | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize | Out-Host
    Write-Host 'Heaviest SMS/voice users:' -ForegroundColor Cyan
    $rows | Select-Object -First 15 UserPrincipalName, SmsSignIns, VoiceSignIns, AuthenticatorAppSignIns,
        PhoneSharePercent, Finding | Format-Table -AutoSize | Out-Host
}

if (@($methodRows | Where-Object ClassifiedAs -eq 'Other').Count -gt 0) {
    Write-Host "Check the 'Other' rows above. If one of them is a phone method in your tenant, widen -SmsPattern or -VoicePattern and run again." -ForegroundColor DarkYellow
}
if ($totalRead -eq 0) {
    Write-Warning 'No sign-ins were returned. Check the role you signed in with and your sign-in log retention.'
}
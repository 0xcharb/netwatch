<#
.SYNOPSIS
    Checks the reputation of remote IPs from active TCP connections using AbuseIPDB.

.DESCRIPTION
    This script fetches remote IPs from active TCP connections on the local machine,
    then queries AbuseIPDB to get reputation scores for each IP. It displays results
    sorted by the abuse confidence score.

.EXAMPLE
    .\Check-TCP-IPReputation.ps1 -ApiKey <your_abuseipdb_apikey>
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ApiKey
)

$results = @()

# --- Get unique remote IPs, excluding local addresses and loopbacks ---
$ipToCheck = Get-NetTCPConnection |
    Where-Object { $_.RemoteAddress -notmatch "^0\.|::|127\.0\.0\.1" } |
    Select-Object -ExpandProperty RemoteAddress -Unique

# --- Check IPs against AbuseIPDB ---
$ipToCheck | ForEach-Object {
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$($_)&maxAgeInDays=90"
    try {
        $ipReputation = Invoke-RestMethod -Uri $url -Headers @{
            Key    = $ApiKey
            Accept = 'application/json'
        }

        $results += [PSCustomObject]@{
            ipAddress            = $ipReputation.data.ipAddress
            abuseConfidenceScore = [int]$ipReputation.data.abuseConfidenceScore
            countryCode          = $ipReputation.data.countryCode
            totalReports         = $ipReputation.data.totalReports
        }
    }
    catch {
        Write-Warning "Could not resolve or fetch IP data for: $_"
    }
}

# --- Output results sorted by abuse score ---
$results | Sort-Object abuseConfidenceScore -Descending | Format-Table -AutoSize

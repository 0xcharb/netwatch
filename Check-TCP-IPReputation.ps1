<#
.SYNOPSIS
    Checks the reputation of remote IPs from active TCP connections using AbuseIPDB.

.DESCRIPTION
    This script fetches remote IPs from active TCP connections on the local machine,
    then queries AbuseIPDB to get reputation scores for each IP. It displays results
    sorted by the abuse confidence score.

.PARAMETER MinScore
    Minimum abuse confidence score to treat an IP as suspicious (default is 1).

.EXAMPLE
    .\Check-TCP-IPReputation.ps1 -ApiKey "your_api_key" -MinScore 10
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [int]$MinScore = 1
)

$results = @()
$filteredResults = @()

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

# --- Filter high-risk IPs ---
$filteredResults = $results | Where-Object {$_.abuseConfidenceScore -ge $MinScore} | Select-Object -ExpandProperty ipAddress

# --- Output results sorted by abuse score ---
Write-Host "`n=== AbuseIPDB Reputation Results ===" -ForegroundColor Cyan
$results | Sort-Object abuseConfidenceScore -Descending | Format-Table -AutoSize

# --- Map suspicious IPs to local processes ---
Write-Host "`n=== Local Processes Communicating with Suspicious IPs ===" -ForegroundColor Red
foreach ($malicious in $filteredResults) {
    $TCPmaliciousInfo = Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq $malicious}


foreach ($conn in $TCPmaliciousInfo) {
    $MaliciousProcess = Get-Process -Id $conn.OwningProcess
    "Suspicious IP $($malicious) on process $($MaliciousProcess.ProcessName) : PID $($MaliciousProcess.Id) - Port $($conn.LocalPort) - State $($conn.State) - LocalAddress $($conn.LocalAddress)"
}
}

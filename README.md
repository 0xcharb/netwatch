# Check-TCP-IPReputation.ps1

Simple PowerShell script to check the reputation of active remote TCP IPs using AbuseIPDB and identify associated local processes.

## Description

This PowerShell script collects all active remote TCP connections on a Windows machine, and queries AbuseIPDB for reputation data. It helps system administrators or security analysts identify potentially malicious IP addresses communicating with their system and maps those IPs to the associated local processes. This can aid in incident response, network monitoring, or threat hunting tasks.

## Getting Started

### Dependencies

* PowerShell 5.1 or newer

* Windows 10 or later

* Internet connection

* AbuseIPDB API key (free signup at abuseipdb.com)

### Executing program

1. Open PowerShell as Administrator

2. Run the script by providing your AbuseIPDB API key:
```
.\Check-TCP-IPReputation.ps1 -ApiKey 'your_api_key_here'
```
(Optional) Adjust the minimum abuse confidence score to filter threats (score 1 by default):
```
.\Check-TCP-IPReputation.ps1 -ApiKey 'your_api_key_here' -MinScore 5
```

## License

This project is licensed under the MIT License - see the LICENSE.md file for details

## Acknowledgments

Inspiration, code snippets, etc.
* [AbuseIPDB](https://abuseipdb.com/) for the IP reputation API

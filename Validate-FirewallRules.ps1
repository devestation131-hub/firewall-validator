<#
.SYNOPSIS
    Validate-FirewallRules.ps1 — Windows Firewall Rule Auditor
.DESCRIPTION
    Audits Windows Firewall rules against a least-privilege baseline.
    Flags overly permissive rules, disabled rules, any-any rules,
    and rules with broad port ranges.
.AUTHOR
    Zachari Higgins
.USAGE
    .\Validate-FirewallRules.ps1
    .\Validate-FirewallRules.ps1 -Profile Domain -Output report.csv
    .\Validate-FirewallRules.ps1 -ShowPassingRules
#>

param(
    [ValidateSet("Domain","Private","Public","Any")]
    [string]$Profile = "Any",
    [string]$Output,
    [switch]$ShowPassingRules
)

$ErrorActionPreference = "SilentlyContinue"

# ─── Severity Levels ─────────────────────────────────────────────────────
$CRITICAL_PORTS = @(21, 23, 69, 135, 137, 138, 139, 445, 1433, 1434, 3389, 5900, 5985, 5986)
$HIGH_RISK_PORTS = @(22, 25, 53, 80, 110, 143, 389, 443, 636, 993, 995, 3306, 5432, 8080, 8443, 9200)

function Get-RiskLevel {
    param([string]$LocalPort, [string]$RemoteAddress, [string]$Direction, [string]$Action, [bool]$Enabled)
    
    $findings = @()
    
    if (-not $Enabled) {
        $findings += @{Level="INFO"; Finding="Rule is disabled"}
        return $findings
    }
    
    if ($Action -eq "Allow" -and $Direction -eq "Inbound") {
        # Any-Any inbound allow = critical
        if ($LocalPort -eq "Any" -and ($RemoteAddress -eq "Any" -or $RemoteAddress -eq "*")) {
            $findings += @{Level="CRITICAL"; Finding="Inbound ANY port from ANY source — wide open"}
        }
        
        # Check for critical ports
        if ($LocalPort -ne "Any") {
            $ports = $LocalPort -split "," | ForEach-Object { $_.Trim() }
            foreach ($p in $ports) {
                if ($p -match "^\d+$") {
                    $portNum = [int]$p
                    if ($portNum -in $CRITICAL_PORTS) {
                        $findings += @{Level="CRITICAL"; Finding="Critical port $portNum open inbound (e.g. RDP, SMB, Telnet)"}
                    } elseif ($portNum -in $HIGH_RISK_PORTS) {
                        $findings += @{Level="HIGH"; Finding="High-risk port $portNum open inbound"}
                    }
                }
                if ($p -match "(\d+)-(\d+)") {
                    $range = [int]$Matches[2] - [int]$Matches[1]
                    if ($range -gt 100) {
                        $findings += @{Level="HIGH"; Finding="Broad port range: $p ($range ports)"}
                    }
                }
            }
        }
        
        # Any remote address
        if ($RemoteAddress -eq "Any" -or $RemoteAddress -eq "*" -or $RemoteAddress -eq "0.0.0.0/0") {
            if ($LocalPort -ne "Any") {
                $findings += @{Level="MEDIUM"; Finding="Allows ANY source IP — consider restricting to known subnets"}
            }
        }
    }
    
    if ($Action -eq "Allow" -and $Direction -eq "Outbound") {
        if ($LocalPort -eq "Any" -and ($RemoteAddress -eq "Any" -or $RemoteAddress -eq "*")) {
            $findings += @{Level="LOW"; Finding="Outbound any-any — normal but monitor for exfil"}
        }
    }
    
    if ($findings.Count -eq 0 -and $Action -eq "Allow") {
        $findings += @{Level="PASS"; Finding="Rule appears properly scoped"}
    }
    
    return $findings
}

# ─── Main ─────────────────────────────────────────────────────────────────
Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "  Windows Firewall Rule Validator" -ForegroundColor Cyan
Write-Host "  Profile: $Profile" -ForegroundColor Gray
Write-Host "=============================================`n" -ForegroundColor Cyan

# Get firewall rules
$rules = Get-NetFirewallRule | Where-Object {
    $Profile -eq "Any" -or $_.Profile -match $Profile
}

$portFilters = Get-NetFirewallPortFilter
$addressFilters = Get-NetFirewallAddressFilter

Write-Host "[*] Analyzing $($rules.Count) firewall rules...`n" -ForegroundColor Cyan

$results = @()
$stats = @{CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO=0; PASS=0}

foreach ($rule in $rules) {
    $port = $portFilters | Where-Object { $_.InstanceID -eq $rule.InstanceID }
    $addr = $addressFilters | Where-Object { $_.InstanceID -eq $rule.InstanceID }
    
    $localPort = if ($port.LocalPort) { $port.LocalPort -join "," } else { "Any" }
    $remoteAddr = if ($addr.RemoteAddress) { $addr.RemoteAddress -join "," } else { "Any" }
    
    $findings = Get-RiskLevel -LocalPort $localPort -RemoteAddress $remoteAddr `
        -Direction $rule.Direction -Action $rule.Action -Enabled $rule.Enabled
    
    foreach ($f in $findings) {
        $stats[$f.Level]++
        
        $result = [PSCustomObject]@{
            RuleName    = $rule.DisplayName
            Direction   = $rule.Direction
            Action      = $rule.Action
            LocalPort   = $localPort
            RemoteAddr  = ($remoteAddr -replace ",", "; ")[0..60] -join ""
            Enabled     = $rule.Enabled
            Level       = $f.Level
            Finding     = $f.Finding
        }
        $results += $result
        
        if ($f.Level -ne "PASS" -or $ShowPassingRules) {
            $color = switch ($f.Level) {
                "CRITICAL" { "Red" }
                "HIGH"     { "Red" }
                "MEDIUM"   { "Yellow" }
                "LOW"      { "DarkYellow" }
                "INFO"     { "Gray" }
                "PASS"     { "Green" }
            }
            
            if ($f.Level -in @("CRITICAL", "HIGH", "MEDIUM")) {
                Write-Host "  [$($f.Level)] $($rule.DisplayName)" -ForegroundColor $color
                Write-Host "         $($f.Finding)" -ForegroundColor Gray
                Write-Host "         Port: $localPort | Remote: $($remoteAddr.Substring(0, [Math]::Min(50, $remoteAddr.Length)))" -ForegroundColor DarkGray
            }
        }
    }
}

# ─── Summary ──────────────────────────────────────────────────────────────
Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "  AUDIT SUMMARY" -ForegroundColor White
Write-Host "  Total Rules: $($rules.Count)" -ForegroundColor Gray
Write-Host "  CRITICAL: $($stats.CRITICAL)" -ForegroundColor Red
Write-Host "  HIGH:     $($stats.HIGH)" -ForegroundColor Red
Write-Host "  MEDIUM:   $($stats.MEDIUM)" -ForegroundColor Yellow
Write-Host "  LOW:      $($stats.LOW)" -ForegroundColor DarkYellow
Write-Host "  PASS:     $($stats.PASS)" -ForegroundColor Green
Write-Host "=============================================`n" -ForegroundColor Cyan

# ─── Output ───────────────────────────────────────────────────────────────
if ($Output) {
    $results | Export-Csv -Path $Output -NoTypeInformation
    Write-Host "[+] Report saved: $Output" -ForegroundColor Green
}

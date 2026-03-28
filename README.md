# 🔥 Windows Firewall Rule Validator
**Language:** PowerShell 5.1+ | **Author:** Zachari Higgins

Audits Windows Firewall rules against a least-privilege baseline. Flags overly permissive rules, any-any rules, critical port exposure, and broad port ranges.

## Risk Detection
- **CRITICAL:** Inbound any-any allow, critical ports open (RDP, SMB, Telnet)
- **HIGH:** Broad port ranges, high-risk ports exposed
- **MEDIUM:** Unrestricted source IPs on specific ports
- **LOW:** Outbound any-any (normal but noted)

## Usage
```powershell
.\Validate-FirewallRules.ps1
.\Validate-FirewallRules.ps1 -Profile Domain -Output report.csv
.\Validate-FirewallRules.ps1 -ShowPassingRules
```
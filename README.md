# BusinessNetworkAuditor

PowerShell-based IT assessment tool for Windows workstations and servers. Performs comprehensive discovery and inventory of IT infrastructure with detailed reporting for business technology management.

## Overview

BusinessNetworkAuditor is an internal IT assessment tool designed for understanding and documenting Windows IT environments. It collects system configurations, software inventory, and IT management settings to provide visibility into business technology infrastructure.

## Features

### System Discovery
- **System Information**: OS details, hardware specs, domain status, Azure AD enrollment
- **User Account Analysis**: Administrator accounts, account policies, Active Directory analysis
- **Software Inventory**: Complete application catalog with remote access and management tools
- **IT Management Tools**: Antivirus status, patch management, BitLocker encryption
- **Network Configuration**: Network shares, adapter settings, DNS configuration
- **Infrastructure Analysis**: Process analysis, event logs, storage utilization

### Server-Specific Analysis
- **Server Role Detection**: Domain Controller, DNS, DHCP, File Services
- **Active Directory Health**: DC diagnostics, replication status, FSMO roles
- **Stale Account Detection**: User and computer account cleanup recommendations
- **Group Policy Analysis**: Domain-wide policy visibility and configuration

### Reporting
- **Technical Reports**: Markdown format organized by category with recommendations
- **Raw Data Export**: Complete JSON export for analysis tools and documentation
- **Risk Assessment**: Flagged items requiring IT attention (HIGH/MEDIUM/LOW/INFO)
- **IT Management Insights**: Remote access tools, RMM platforms, management gaps

## Deployment Options

### Local Execution
```powershell
# Clone repository
git clone https://github.com/jeremyroe/BusinessNetworkAuditor.git
cd BusinessNetworkAuditor

# Run workstation assessment
.\src\WindowsWorkstationAuditor.ps1

# Run server assessment  
.\src\WindowsServerAuditor.ps1

# Custom output location
.\src\WindowsWorkstationAuditor.ps1 -OutputPath "C:\ITAssessments"
```

### Web Deployment
For remote assessment without local installation:

```powershell
# Workstation assessment
iex (irm https://your-url/WindowsWorkstationAuditor-Web.ps1)

# Server assessment
iex (irm https://your-url/WindowsServerAuditor-Web.ps1)

# Custom output path
$OutputPath = "C:\RemoteAssessments"; iex (irm https://your-url/WindowsWorkstationAuditor-Web.ps1)
```

## Requirements
- Windows 10/11 (workstations) or Windows Server 2016+ (servers)
- PowerShell 5.0 or later
- Local Administrator rights recommended for complete analysis

## Output Files

```
output/
├── logs/
│   └── COMPUTERNAME_YYYYMMDD_HHMMSS_audit.log
├── COMPUTERNAME_YYYYMMDD_HHMMSS_technician_report.md
└── COMPUTERNAME_YYYYMMDD_HHMMSS_raw_data.json
```

### Technical Report (Markdown)
- Findings breakdown by category
- Recommendations organized by priority
- Detailed findings with actionable guidance
- Clean format for technical review

### Raw Data Export (JSON)
- Complete assessment results
- Full software inventory with metadata  
- Network and system configuration details
- Structured format for documentation systems

## Configuration

Customize assessment behavior using configuration files:

**Workstations**: `config/workstation-audit-config.json`
**Servers**: `config/server-audit-config.json`

### Event Log Analysis Configuration

Configure event log analysis timeframes and performance settings:

```json
{
  "settings": {
    "eventlog": {
      "analysis_days": 7,
      "max_events_per_query": 1000,
      "server_analysis_days": 3,
      "server_max_events": 500,
      "domain_controller_analysis_days": 30,
      "domain_controller_max_events": 500
    }
  }
}
```

**Settings:**
- `analysis_days`: Default analysis window for workstations
- `server_analysis_days`: Analysis window for member servers
- `domain_controller_analysis_days`: Analysis window for Domain Controllers
- `max_events_per_query`: Maximum events to retrieve per query for performance

### Other Configuration Options
- Software collection preferences
- Module execution timeouts
- Output format selection

## Architecture

Modular design for maintainability:

```
src/
├── WindowsWorkstationAuditor.ps1    # Workstation orchestrator
├── WindowsServerAuditor.ps1          # Server orchestrator
├── core/                             # Core functions
└── modules/                          # Assessment modules
```

Each module returns standardized result objects:

```powershell
[PSCustomObject]@{
    Category = "System"               # Grouping category
    Item = "Operating System"         # Specific finding
    Value = "Windows Server 2022"     # Primary value
    Details = "Build: 20348.1547"     # Additional details
    RiskLevel = "INFO"               # HIGH/MEDIUM/LOW/INFO
    Recommendation = "..."           # IT management guidance
}
```


## Performance Notes

### Domain Controllers
- Event log analysis on DCs takes 20-30 minutes due to authentication volume
- Domain admin login provides better performance than SYSTEM context

### Web Versions
- Self-contained files with embedded configuration
- No runtime dependencies or external file requirements
- Workstation version: ~200KB, Server version: ~290KB

---

**Internal Use Tool**: Designed for internal IT assessment and infrastructure management.
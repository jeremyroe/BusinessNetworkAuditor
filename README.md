# BusinessNetworkAuditor

A comprehensive PowerShell-based security audit tool for Windows workstations and servers. Performs detailed security assessments with professional reporting focused on actionable security findings and investigation points.

## Features

### **Comprehensive Security Analysis**
- **System Information**: OS details, hardware specs, domain status, Azure AD/MDM enrollment detection
- **User Account Analysis**: Local administrators, account policies, dormant accounts, privilege risks
- **Software Inventory**: Complete application catalog with remote access and RMM tool detection
- **Security Settings**: Multi-AV detection, firewall status, BitLocker encryption analysis
- **Patch Management**: Update status, available patches, security update compliance
- **Policy Analysis**: Domain GPO vs MDM vs Local policy separation with actual setting values
- **Network Security**: Risky open ports, network shares, adapter configuration, DNS settings
- **Process Analysis**: High CPU processes, running services, memory analysis
- **Event Log Analysis**: Security events, PowerShell execution patterns, threat indicators
- **Storage Analysis**: Disk usage, health status, capacity planning

### **Enhanced Security Detection**

**Multi-AV Environment Analysis**: Detects and analyzes 20+ antivirus solutions with proper Windows Defender logic for multi-AV environments.

**Remote Access Software Detection (27+ tools)**:
- TeamViewer, AnyDesk, VNC variants, Chrome Remote Desktop
- ScreenConnect/ConnectWise Control, BeyondTrust, Jump Desktop
- LogMeIn, Splashtop, Parsec, GoToMyPC and more

**RMM/Monitoring Platform Detection (19+ platforms)**:  
- ConnectWise Automate, NinjaRMM, Kaseya VSA, Datto RMM
- N-able, Atera, Syncro, Pulseway, ManageEngine
- Security platforms: CrowdStrike, SentinelOne, Huntress

**BitLocker Encryption Analysis**:
- Drive encryption status per volume
- Key escrow detection (Azure AD vs Active Directory)
- Recovery key backup verification

### **Professional Reporting**
- **Technician Reports**: Clean markdown format with header+detail organization to prevent duplication
- **Raw Data Export**: Comprehensive JSON with detailed software inventories and investigation points
- **Risk Assessment**: HIGH/MEDIUM/LOW/INFO risk levels with actionable compliance recommendations
- **Executive Summary**: At-a-glance security posture with risk counts and priority actions
- **Investigation Points**: Flagged items requiring security team review (remote access tools, RMM, etc.)

### **Flexible Deployment**
- **Local Execution**: Full modular architecture with configuration management
- **Web Execution**: Single-file deployment via PowerShell one-liner for rapid assessment
- **System Context**: Handles both user and SYSTEM execution contexts appropriately
- **Enterprise Ready**: Git workflow integration, comprehensive logging, error handling

## Quick Start

### Prerequisites
- Windows 10/11 workstations (for Windows Server, use WindowsServerAuditor.ps1)
- PowerShell 5.0 or later
- Local Administrator rights (recommended for complete analysis)

### Basic Usage

```powershell
# Clone the repository
git clone https://github.com/jeremyroe/BusinessNetworkAuditor.git
cd BusinessNetworkAuditor

# Run the audit
.\src\WindowsWorkstationAuditor.ps1

# Custom output location
.\src\WindowsWorkstationAuditor.ps1 -OutputPath "C:\SecurityAudits"

# Verbose logging
.\src\WindowsWorkstationAuditor.ps1 -Verbose
```

### Web Execution
For rapid deployment across multiple systems without cloning the repository:

```powershell
# Build self-contained web version
.\Build-WebVersion.ps1 -OutputFile "WindowsWorkstationAuditor-Complete.ps1"

# Execute directly from GitHub (after pushing the generated file):
iex (irm https://raw.githubusercontent.com/jeremyroe/BusinessNetworkAuditor/main/WindowsWorkstationAuditor-Complete.ps1)

# Or execute with custom parameters:
$OutputPath = "C:\RemoteAudits"; iex (irm https://raw.githubusercontent.com/jeremyroe/BusinessNetworkAuditor/main/WindowsWorkstationAuditor-Complete.ps1)

# For testing/development branch:
iex (irm https://raw.githubusercontent.com/jeremyroe/BusinessNetworkAuditor/develop/WindowsWorkstationAuditor-Complete.ps1)
```

**Web Execution Benefits**:
- Execute directly from GitHub - no separate hosting required
- Single PowerShell command deployment
- No local file storage required
- Embeds all modules and functionality
- Version control integration
- Perfect for one-off assessments or emergency response

## Output Files

The audit generates several output files in the specified directory:

```
output/
├── logs/
│   └── COMPUTERNAME_YYYYMMDD_HHMMSS_audit.log
├── COMPUTERNAME_YYYYMMDD_HHMMSS_technician_report.md
└── COMPUTERNAME_YYYYMMDD_HHMMSS_raw_data.json
```

### Technician Report (Markdown)
- Executive summary with risk breakdown
- Prioritized action items (HIGH/MEDIUM priority)
- Detailed findings organized by category
- Compliance recommendations
- Clean, readable format for technical staff

### Raw Data Export (JSON)
- Complete audit results with unique IDs
- Full software inventory with detailed metadata
- Network configuration details
- Event log analysis with suspicious activity patterns
- Structured format for aggregation tools and dashboards

## Configuration

### Audit Configuration
Customize the audit behavior using `config/audit-config.json`:

```json
{
  "version": "1.3.0",
  "modules": {
    "system": { "enabled": true, "timeout": 30 },
    "security": { "enabled": true, "timeout": 20 },
    "network": { "enabled": true, "timeout": 30 }
  },
  "output": {
    "formats": ["markdown", "rawjson"],
    "path": "./output"
  }
}
```

### Output Formats
- `markdown`: Technician-friendly report with action items
- `rawjson`: Comprehensive data for aggregation tools
- `csv`: Legacy tabular format (basic summary)
- `json`: Legacy simple JSON format (basic summary)

## Architecture

### Modular Design
The tool uses a modular architecture for maintainability and extensibility:

```
src/
├── WindowsWorkstationAuditor.ps1    # Main orchestrator
├── core/                            # Core functions
│   ├── Write-LogMessage.ps1         # Logging system
│   ├── Initialize-Logging.ps1       # Log initialization
│   ├── Export-MarkdownReport.ps1    # Technician reports
│   └── Export-RawDataJSON.ps1       # Raw data export
└── modules/                         # Audit modules
    ├── Get-SystemInformation.ps1    # System analysis
    ├── Get-SecuritySettings.ps1     # Security configuration
    ├── Get-NetworkAnalysis.ps1      # Network assessment
    └── ...                          # Additional modules
```

### Adding Custom Modules
1. Create new module in `src/modules/`
2. Implement function returning standardized result objects
3. Add module to the orchestrator's module list
4. Update configuration file if needed

### Result Object Format
```powershell
[PSCustomObject]@{
    Category = "Security"           # Grouping category
    Item = "Antivirus Status"       # Specific finding
    Value = "Windows Defender"      # Primary value
    Details = "Version: 1.0..."     # Additional details
    RiskLevel = "LOW"              # HIGH/MEDIUM/LOW/INFO
    Compliance = "NIST: ..."       # Compliance notes
}
```

## Use Cases

### IT Security Teams
- **Workstation Assessment**: Comprehensive security posture evaluation
- **Compliance Audits**: NIST, HIPAA, and custom framework compliance
- **Incident Response**: Security configuration verification during investigations
- **Baseline Documentation**: Establish security baselines for comparison

### Managed Service Providers (MSPs)
- **Client Onboarding**: Initial security assessment of new client environments
- **Regular Reviews**: Scheduled security health checks
- **Compliance Reporting**: Automated compliance documentation
- **Issue Identification**: Proactive security issue detection

### Enterprise IT
- **Security Monitoring**: Regular workstation security validation
- **Patch Management**: Update status tracking and compliance
- **Policy Enforcement**: Group Policy and security setting verification
- **Risk Assessment**: Quantified risk analysis across the enterprise

## Security Considerations

### Data Collection
- Tool collects system configuration data only
- No sensitive user data (passwords, files, etc.) is captured
- All data remains local unless explicitly exported
- Raw data exports can be sanitized before external sharing

### Execution Requirements
- Administrator privileges recommended for complete analysis
- Some modules work with standard user rights (limited functionality)
- Network access not required (offline capable)
- No external dependencies or internet connectivity needed

### Output Security
- Audit logs contain system configuration details
- Raw JSON exports may contain network topology information
- Consider data classification before sharing reports externally
- Reports include computer names and network details

## Troubleshooting

### Common Issues

**PowerShell Execution Policy**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Module Loading Errors**
- Ensure all files are present in the correct directory structure
- Check PowerShell version (5.0+ required)
- Verify file permissions and unblock downloaded files

**Incomplete Results**
- Run as Administrator for full access to system information
- Check Windows Defender settings (may block WMI access)
- Review audit logs for specific module errors

**Large Output Files**
- Raw JSON exports can be large on systems with many installed programs
- Use selective module execution for focused assessments
- Compress output files for storage or transmission

## Development

### Requirements
- PowerShell 5.0+
- Git for version control
- Text editor with PowerShell syntax support

### Contributing
1. Fork the repository
2. Create a feature branch
3. Implement changes with appropriate testing
4. Update documentation as needed
5. Submit a pull request

### Testing
```powershell
# Test individual modules
.\src\modules\Get-SystemInformation.ps1

# Test full audit
.\src\WindowsWorkstationAuditor.ps1 -Verbose

# Validate output formats
# Check generated markdown and JSON files
```

## Recent Enhancements

### Software Detection & Investigation Points
- **Remote Access Software**: 27+ tools including TeamViewer, AnyDesk, ScreenConnect/ConnectWise Control
- **RMM/Monitoring Platforms**: 19+ platforms including ConnectWise Automate, NinjaRMM, Kaseya
- **Risk Classification**: Automatic MEDIUM risk flagging for investigation by security teams
- **Detailed Metadata**: Install dates, versions, publishers for compliance tracking

### Policy Management Analysis
- **Domain Group Policy**: Traditional AD-based policy detection and enumeration
- **MDM/Intune Policies**: Azure AD enrolled device policy analysis with actual setting values
- **Local Security Policy**: Standalone system policy configuration detection
- **Clean Reporting**: Filtered technical metadata for readable technician reports

### BitLocker & Encryption
- **Encryption Status**: Per-volume BitLocker encryption analysis
- **Key Escrow**: Automatic detection of Azure AD vs Active Directory key backup
- **Recovery Methods**: PIN, password, TPM, and USB key protector analysis
- **Compliance Tracking**: Encryption policy adherence and recommendations

### Multi-AV Environment Support
- **Intelligent Detection**: Proper Windows Defender status in multi-AV environments
- **20+ AV Products**: Enterprise EDR, traditional AV, and consumer products
- **Risk Assessment**: Contextual risk levels based on actual protection status

### System Context Handling
- **User vs SYSTEM**: Appropriate checks for execution context (user profile vs system-wide)
- **Permission Awareness**: Graceful handling of access denied scenarios
- **Encoding Fixes**: Resolved Unicode character issues in SYSTEM context

## Support

For issues or questions, refer to:
- The troubleshooting section above
- Check the audit logs for detailed error information
- Review the testing guide in `docs/TESTING.md`

---

**Note**: This tool is designed for legitimate security assessment purposes. Ensure you have proper authorization before running audits on systems you do not own or administer.
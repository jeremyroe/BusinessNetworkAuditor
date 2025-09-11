# WindowsWorkstationAuditor

A comprehensive PowerShell-based security audit tool for Windows workstations and servers. Performs detailed security assessments with professional reporting and compliance mapping.

## Features

### 🔍 **Comprehensive Security Analysis**
- **System Information**: OS details, hardware specs, domain status, Azure AD/MDM enrollment
- **User Account Analysis**: Local administrators, account policies, privilege escalation risks
- **Software Inventory**: Complete application catalog with versions, publishers, and install dates
- **Security Settings**: Antivirus detection, firewall status, Windows Defender configuration
- **Patch Management**: Update status, available patches, security update compliance
- **Policy Analysis**: Password policies, audit settings, Group Policy configuration
- **Network Security**: Open ports, network shares, adapter configuration, DNS settings
- **Process Analysis**: Running processes, services, startup programs, resource usage
- **Event Log Analysis**: Security events, PowerShell execution patterns, threat indicators
- **Storage Analysis**: Disk usage, health status, capacity planning

### 🛡️ **Enhanced Antivirus Detection**
Detects and analyzes multiple antivirus solutions:
- **Enterprise EDR**: SentinelOne, CrowdStrike, Carbon Black, Cortex XDR
- **Traditional AV**: McAfee, Symantec/Norton, Trend Micro, Kaspersky, Bitdefender
- **Consumer Products**: Avast, AVG, Webroot, Malwarebytes, F-Secure
- **Built-in Protection**: Windows Defender with detailed status and configuration

### 📊 **Professional Reporting**
- **Technician Reports**: Clean markdown format with prioritized action items
- **Raw Data Export**: Comprehensive JSON for aggregation tools and analytics
- **Risk Assessment**: HIGH/MEDIUM/LOW/INFO risk levels with compliance mapping
- **Executive Summary**: At-a-glance security posture with risk counts

### 🏛️ **Compliance Framework Support**
- **NIST**: Cybersecurity Framework mapping for security controls
- **HIPAA**: Healthcare compliance requirements where applicable
- **Custom**: Extensible framework for additional compliance standards

## Quick Start

### Prerequisites
- Windows 10/11 workstations (for Windows Server, use WindowsServerAuditor.ps1)
- PowerShell 5.0 or later
- Local Administrator rights (recommended for complete analysis)

### Basic Usage

```powershell
# Clone the repository
git clone https://github.com/your-org/BusinessNetworkAuditor.git
cd BusinessNetworkAuditor

# Run the audit
.\src\WindowsWorkstationAuditor.ps1

# Custom output location
.\src\WindowsWorkstationAuditor.ps1 -OutputPath "C:\SecurityAudits"

# Force run on Windows Server (not recommended)
.\src\WindowsWorkstationAuditor.ps1 -Force
```

### Web Execution (Future)
For rapid deployment across multiple systems:
```powershell
# Build web-compatible version
.\Build-WebVersion.ps1

# Execute remotely (after uploading to web server)
iex (irm https://your-url/WindowsWorkstationAuditor-Complete.ps1)
```

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

## Version History

### v1.3.0 (Current)
- ✅ Modular architecture implementation
- ✅ Enhanced antivirus detection (multi-method)
- ✅ New markdown technician reports
- ✅ Comprehensive raw JSON exports
- ✅ PowerShell execution pattern analysis
- ✅ Complete software inventory with metadata
- ✅ Improved compliance framework mapping
- ✅ Web execution compatibility preparation

### v1.2.0 (Legacy)
- Monolithic script architecture
- Basic CSV/JSON exports
- Limited antivirus detection
- Windows Defender focus only

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, feature requests, or questions:
- Create an issue in the GitHub repository
- Review the troubleshooting section above
- Check the audit logs for detailed error information

---

**Note**: This tool is designed for legitimate security assessment purposes. Ensure you have proper authorization before running audits on systems you do not own or administer.
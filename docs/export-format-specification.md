# Export Format Specification

## Overview
This document defines the standardized export formats for all BusinessNetworkAuditor platform tools to ensure consistency across Windows, macOS, and future platforms.

## Report Types

### 1. Technician Report (Markdown)
**Filename Format:** `{BaseFileName}_technician_report.md`
**Purpose:** Professional, focused report for IT technicians showing only actionable items and critical information

#### Required Sections (in order):
1. **Header**
   - Platform-specific title (e.g., "Windows Workstation Security Audit Report", "macOS Workstation Security Audit Report")
   - Computer name
   - Generation timestamp
   - Tool version

2. **Executive Summary**
   - Risk level counts table with priority descriptions:
     - HIGH: "Immediate Action Required"
     - MEDIUM: "Review and Plan Remediation"
     - LOW: "Monitor and Maintain"
     - INFO: "Informational"

3. **Critical Action Items** (only if HIGH or MEDIUM risk items exist)
   - HIGH PRIORITY section (if any HIGH risk items)
   - MEDIUM PRIORITY section (if any MEDIUM risk items)
   - Format: `- **{Category} - {Item}:** {Value}`
   - Include Details and Recommendation as sub-bullets

4. **Additional Information** (LOW and INFO items only)
   - Group by Category
   - Exclude categories that appear in Critical Action Items
   - Format: `**[{RiskLevel}] {Item}:** {Value}`
   - Include Details and Recommendation as sub-bullets

5. **System Configuration Details**
   - Brief system information (OS, hardware, domain)
   - Platform-specific key metrics

6. **Recommendations** (if any items have recommendations)
   - Group identical recommendations
   - Show affected item count for each recommendation

7. **Footer**
   - Assessment duration
   - Generation timestamp
   - Tool identification
   - Reference to JSON export for detailed analysis

### 2. Raw Data Export (JSON)
**Filename Format:** `{BaseFileName}_raw_data.json`
**Purpose:** Complete structured data for aggregation, analysis, and integration

#### Required Structure:
```json
{
  "metadata": {
    "computer_name": "string",
    "audit_timestamp": "ISO8601 UTC",
    "tool_version": "string",
    "platform": "Windows|macOS|Linux",
    "os_version": "string",
    "os_build": "string",
    "audit_duration_seconds": number
  },
  "system_context": {
    "os_info": {
      "caption": "string",
      "version": "string",
      "build_number": "string",
      "architecture": "string",
      "last_boot_time": "string"
    },
    "hardware_info": {
      "model": "string",
      "total_memory_gb": number,
      "cpu_cores": number
    },
    "domain": "string",
    "computer_name": "string"
  },
  "compliance_framework": {
    "findings": [
      {
        "finding_id": "platform-category-item-hash",
        "category": "string",
        "item": "string",
        "value": "string",
        "requirement": "string", // Details field
        "risk_level": "HIGH|MEDIUM|LOW|INFO",
        "recommendation": "string",
        "framework": "platform_Security_Assessment"
      }
    ]
  },
  "summary": {
    "total_findings": number,
    "risk_distribution": {
      "HIGH": number,
      "MEDIUM": number,
      "LOW": number,
      "INFO": number
    }
  }
}
```

## Risk Level Guidelines

### HIGH
- Security vulnerabilities requiring immediate attention
- Critical misconfigurations exposing the system
- Failed security controls (antivirus, firewall disabled)
- Examples: Disabled Windows Defender, No firewall, Admin without password

### MEDIUM
- Important security improvements needed
- Suboptimal configurations affecting security posture
- Missing recommended security features
- Examples: Outdated software, Weak password policies, Missing updates

### LOW
- Minor improvements or monitoring points
- Best practice recommendations
- Performance considerations
- Examples: High memory usage, Non-critical updates available

### INFO
- Informational findings for awareness
- System inventory and configuration details
- Baseline information
- Examples: Installed software versions, System specifications

## Platform-Specific Considerations

### Windows
- Use PowerShell cmdlet naming conventions
- Include domain/workgroup status
- Windows-specific security features (BitLocker, Windows Defender, etc.)

### macOS
- Use macOS-specific terminology (FileVault, XProtect, Gatekeeper)
- Account for Unix-style permissions and processes
- Include Apple-specific security features

### Cross-Platform Elements
- Network configuration and security
- User account management
- Software inventory
- System performance metrics
- Update/patch status

## Naming Conventions

### Finding IDs
Format: `{platform}-{category-kebab-case}-{item-kebab-case}`
- Use lowercase
- Replace spaces with hyphens
- Remove special characters except hyphens
- Examples: `windows-system-os-version`, `macos-security-firewall-status`

### Categories
Standardized categories across platforms:
- System
- Security
- Network
- Software
- Users
- Updates/Patches
- Storage/Disk
- Memory
- Process

### File Naming
- Use underscore separation for multi-word elements
- Include platform identifier when needed
- Examples: `COMPUTER1_technician_report.md`, `COMPUTER1_raw_data.json`

## Quality Standards

### Report Content
- Exception-based reporting (focus on issues, not verbose status)
- Human-readable process and service names
- Clear, actionable recommendations
- Avoid technical jargon in markdown reports
- Consistent risk level application

### Data Accuracy
- Verify detection methods across platform versions
- Handle edge cases and error conditions gracefully
- Provide fallback detection methods when possible
- Include confidence indicators when detection is uncertain

### Performance
- Minimize audit execution time
- Avoid redundant system calls
- Cache expensive operations when possible
- Provide progress indicators for long-running operations

## Implementation Notes

### Markdown Generation
- Use consistent heading levels
- Implement proper table formatting
- Include line breaks for readability
- Escape special characters in values

### JSON Generation
- Ensure valid JSON structure
- Handle special characters in string values
- Use consistent number formatting
- Implement proper error handling for missing data

### Logging
- Use consistent log levels across platforms
- Include module/category context in log messages
- Provide meaningful error messages
- Support verbose mode for troubleshooting
# Windows Workstation Security Audit Report

**Computer:** ACME-WS-001
**Generated:** 2025-09-24 14:30:15
**Tool Version:** Windows Workstation Auditor v1.3.0

## Executive Summary

| Risk Level | Count | Priority |
|------------|-------|----------|
| HIGH | 3 | Immediate Action Required |
| MEDIUM | 8 | Review and Plan Remediation |
| LOW | 12 | Monitor and Maintain |
| INFO | 47 | Informational |

## Critical Action Items

### HIGH PRIORITY (Immediate Action Required)

- **Patching - Available Updates:** 15 updates
  - Details: 8 Security Updates, 4 Critical Updates, 3 Important Updates
  - Recommendation: Install critical security updates immediately to address known vulnerabilities

- **Security - Windows Defender Real-time Protection:** Disabled
  - Details: Real-time scanning is turned off
  - Recommendation: Enable Windows Defender real-time protection or verify alternative antivirus solution

- **Security - Windows Firewall:** Disabled (Domain Network)
  - Details: Domain network firewall is disabled
  - Recommendation: Enable Windows Firewall or verify enterprise firewall solution

### MEDIUM PRIORITY (Review and Plan)

- **User Accounts - Local Administrators:** 3 accounts
  - Details: ACME\john.smith, ACME\admin.user, local\administrator
  - Recommendation: Review administrator accounts and remove unnecessary administrative privileges

- **Software - Remote Access Software:** 2 applications
  - Details: TeamViewer 15.42.9, Chrome Remote Desktop
  - Recommendation: Review remote access software for security and business justification

- **Network - Open Ports:** 5 services
  - Details: Port 135 (RPC), 139 (NetBIOS), 445 (SMB), 3389 (RDP), 5040 (Unknown)
  - Recommendation: Review listening services for security implications

- **Storage - Low Disk Space:** C: Drive 89% full
  - Details: Used: 445GB, Free: 55GB, Total: 500GB
  - Recommendation: Clean up disk space or expand storage capacity

- **Memory - High Usage:** 87% utilization
  - Details: 14GB used of 16GB total RAM
  - Recommendation: Monitor memory usage patterns and consider additional RAM

- **Patches - Windows Update Service:** Manual configuration
  - Details: Automatic updates are disabled
  - Recommendation: Configure automatic updates or implement enterprise update management

- **Policy - Password Policy:** Weak configuration
  - Details: Minimum length: 6 characters, No complexity requirements
  - Recommendation: Implement stronger password policy with complexity requirements

- **Printers - Network Printers:** 8 configured
  - Details: Multiple network printers from various manufacturers
  - Recommendation: Review printer inventory and remove unused printers

## System Configuration Details

- **Operating System:** Windows 11 Pro (Build 22631.4317)
- **Computer:** ACME-WS-001.acme.local
- **Domain:** ACME.LOCAL (Domain Joined)
- **Hardware:** Dell OptiPlex 7090, Intel Core i7-11700, 16GB RAM, 500GB SSD
- **Last Boot:** 2025-09-23 08:15:22 (1 days ago)
- **System Uptime:** 1 day, 6 hours, 15 minutes

## User Account Analysis

- **Total Users:** 12 accounts (3 active, 9 disabled)
- **Administrator Accounts:** 3 accounts
  - ACME\john.smith (Active - last login: 2025-09-24)
  - ACME\admin.user (Active - last login: 2025-09-22)
  - Administrator (Disabled - last login: Never)
- **Standard Users:** 9 accounts (6 disabled)
- **Password Policy:** Domain policy enforced
- **Account Lockout:** 5 attempts, 30-minute lockout

## Software Inventory

### Critical Applications
- **Web Browsers:** Google Chrome 117.0.5938.132, Microsoft Edge 117.0.2045.47
- **Office Suite:** Microsoft Office 365 (Current Channel)
- **Security Software:** Windows Defender (Built-in)
- **Remote Access:** TeamViewer 15.42.9, Chrome Remote Desktop
- **Development Tools:** Visual Studio Code 1.82.2

### Installed Software Summary
- **Total Installed:** 127 applications
- **Microsoft Products:** 23 applications
- **Third-party Software:** 104 applications
- **Recently Installed:** 5 applications (last 30 days)

## Security Configuration

### Windows Defender Status
- **Antivirus Protection:** Enabled
- **Real-time Protection:** Disabled ⚠️
- **Cloud Protection:** Enabled
- **Sample Submission:** Enabled
- **Last Update:** 2025-09-24 06:00:15

### Firewall Configuration
- **Domain Network:** Disabled ⚠️
- **Private Network:** Enabled
- **Public Network:** Enabled
- **Windows Defender Firewall:** Active

### BitLocker Status
- **C: Drive:** Not Encrypted
- **Recovery Key:** Not backed up
- **TPM Status:** Available (Version 2.0)

## Network Configuration

### Network Adapters
- **Ethernet:** Intel I219-LM (Connected - 1 Gbps)
  - IP: 192.168.1.100/24
  - Gateway: 192.168.1.1
  - DNS: 192.168.1.10, 192.168.1.11
- **Wi-Fi:** Intel AX201 (Disabled)

### Network Shares
- **Mapped Drives:** 2 drives
  - H: \\fileserver\home\john.smith
  - S: \\fileserver\shared
- **Shared Folders:** None configured

### Active Network Connections
- **Established Connections:** 23 connections
- **Listening Ports:** 5 services
  - 135/tcp (RPC Endpoint Mapper)
  - 139/tcp (NetBIOS Session Service)
  - 445/tcp (SMB)
  - 3389/tcp (Remote Desktop)
  - 5040/tcp (Unknown Service)

## System Performance

### Memory Analysis
- **Physical Memory:** 16.00 GB
- **Available Memory:** 2.15 GB (13.4%)
- **Memory Usage:** 87% ⚠️
- **Virtual Memory:** 18.7 GB (77% used)
- **Page File:** C:\pagefile.sys (2.4 GB)

### Top Memory Processes
1. **firefox.exe:** 2.1 GB (13.1%)
2. **chrome.exe:** 1.8 GB (11.3%)
3. **teams.exe:** 845 MB (5.3%)
4. **outlook.exe:** 623 MB (3.9%)
5. **dwm.exe:** 412 MB (2.6%)

### Disk Usage Analysis
- **System Drive (C:):** 89% used ⚠️
  - Total: 500 GB
  - Used: 445 GB
  - Free: 55 GB
- **Largest Folders:**
  - C:\Users: 125 GB
  - C:\Program Files: 89 GB
  - C:\Windows: 67 GB

### Running Processes
- **Total Processes:** 247 processes
- **System Processes:** 45 processes
- **User Processes:** 202 processes

## Patch Management Status

### Windows Update Configuration
- **Update Source:** Windows Update (Internet)
- **Automatic Updates:** Manual ⚠️
- **Last Check:** 2025-09-20 (4 days ago)
- **Pending Reboot:** Yes

### Available Updates
- **Security Updates:** 8 available ⚠️
- **Critical Updates:** 4 available ⚠️
- **Important Updates:** 3 available
- **Optional Updates:** 2 available

### Update History (Last 30 Days)
- **Successfully Installed:** 12 updates
- **Failed Installations:** 1 update
- **Last Successful Update:** 2025-09-15

## Group Policy Analysis

### Applied Policies
- **Computer Policies:** 47 policies applied
- **User Policies:** 23 policies applied
- **Domain:** ACME.LOCAL

### Key Policy Settings
- **Password Policy:** Domain enforced
- **Audit Policy:** Advanced audit enabled
- **Security Options:** 12 settings configured
- **User Rights:** Standard domain user rights

## Printer Configuration

### Installed Printers
- **Network Printers:** 8 printers
  - HP LaserJet P4015 (\\printserver\HP-P4015-Floor2)
  - Canon ImageRunner (\\printserver\Canon-IR-Reception)
  - Brother HL-L2350DW (\\printserver\Brother-Accounting)
  - Xerox WorkCentre (\\printserver\Xerox-Conference)
  - HP Color LaserJet (\\printserver\HP-Color-Marketing)
  - Epson WorkForce (\\printserver\Epson-Graphics)
  - Canon PIXMA (\\printserver\Canon-Labels)
  - Samsung ML-2010 (\\printserver\Samsung-Backup)

### Print Services Status
- **Print Spooler:** Running
- **Print Queue:** 0 jobs pending
- **Default Printer:** HP LaserJet P4015

## Event Log Analysis

### Security Events (Last 7 Days)
- **Logon Events:** 127 events
  - Successful: 125 events
  - Failed: 2 events
- **Account Management:** 5 events
- **System Events:** 23 events

### System Events (Last 7 Days)
- **Critical Events:** 0 events
- **Error Events:** 3 events
- **Warning Events:** 12 events
- **Information Events:** 456 events

### Application Events (Last 7 Days)
- **Error Events:** 8 events
- **Warning Events:** 34 events
- **Information Events:** 234 events

## Recommendations Summary

### Immediate Actions (HIGH Priority)
1. Install all available security and critical updates
2. Enable Windows Defender real-time protection
3. Enable Windows Firewall for domain network
4. Configure automatic Windows Update installation

### Review and Planning (MEDIUM Priority)
1. Review and reduce local administrator accounts
2. Evaluate necessity of remote access software
3. Review network service configuration and open ports
4. Implement disk cleanup procedures
5. Monitor memory usage and consider hardware upgrade
6. Strengthen local password policy requirements
7. Remove unused network printers

### Monitoring (LOW Priority)
1. Monitor system performance trends
2. Review event logs for recurring issues
3. Validate BitLocker encryption implementation
4. Optimize startup programs and services

## Data Export Information

- **Report Generated:** 2025-09-24 14:30:15
- **JSON Export:** ACME-WS-001_20250924_143015_raw_data.json
- **Log File:** ACME-WS-001_20250924_143015_audit.log
- **Assessment Duration:** 3 minutes, 47 seconds
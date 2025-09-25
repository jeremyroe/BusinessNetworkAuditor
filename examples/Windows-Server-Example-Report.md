# Windows Server Security Audit Report

**Computer:** ACME-DC-01
**Generated:** 2025-09-24 15:45:22
**Tool Version:** Windows Server Auditor v1.3.0

## Executive Summary

| Risk Level | Count | Priority |
|------------|-------|----------|
| HIGH | 2 | Immediate Action Required |
| MEDIUM | 6 | Review and Plan Remediation |
| LOW | 18 | Monitor and Maintain |
| INFO | 89 | Informational |

## Critical Action Items

### HIGH PRIORITY (Immediate Action Required)

- **Active Directory - Stale Computer Accounts:** 23 accounts
  - Details: 23 computers not logged in for 180+ days
  - Recommendation: Review and remove stale computer accounts to maintain Active Directory hygiene

- **Security - Print Spooler Service:** Running (PrintNightmare Risk)
  - Details: Print Spooler service enabled on Domain Controller
  - Recommendation: Disable Print Spooler service on Domain Controllers unless required for business operations

### MEDIUM PRIORITY (Review and Plan)

- **Patching - Available Updates:** 8 updates
  - Details: 3 Security Updates, 2 Critical Updates, 3 Important Updates
  - Recommendation: Install critical security updates during next maintenance window

- **Active Directory - Stale User Accounts:** 47 accounts
  - Details: 47 users not logged in for 90+ days
  - Recommendation: Review inactive user accounts and disable unnecessary accounts

- **Network - DNS Forwarders:** External DNS configured
  - Details: DNS forwarding to 8.8.8.8, 1.1.1.1
  - Recommendation: Review DNS forwarder configuration for enterprise compliance

- **Server Roles - DHCP Scope Utilization:** 89% full
  - Details: Scope 192.168.1.0/24 - 214 of 240 addresses used
  - Recommendation: Monitor DHCP scope usage and consider expanding range

- **File Shares - Open Administrative Shares:** C$, ADMIN$, IPC$
  - Details: Default administrative shares enabled
  - Recommendation: Review necessity of administrative shares based on security policy

- **Storage - Event Log Size:** Security log at 95% capacity
  - Details: Security.evtx is 99MB of 100MB maximum
  - Recommendation: Increase event log size or configure log forwarding

## System Configuration Details

- **Operating System:** Windows Server 2022 Standard (Build 20348.2113)
- **Computer:** ACME-DC-01.acme.local
- **Domain:** ACME.LOCAL (Domain Controller)
- **Server Roles:** Active Directory Domain Services, DNS Server, DHCP Server, File Services
- **Hardware:** Dell PowerEdge R750, Intel Xeon Silver 4314, 64GB RAM, 2TB SAS
- **Last Boot:** 2025-09-20 03:00:15 (4 days ago)
- **System Uptime:** 4 days, 12 hours, 45 minutes

## Server Role Analysis

### Active Directory Domain Services
- **Domain:** ACME.LOCAL
- **Forest Level:** Windows Server 2016
- **Domain Level:** Windows Server 2016
- **FSMO Roles Held:** All 5 roles (PDC, RID, Infrastructure, Schema, Domain Naming)
- **Global Catalog:** Yes
- **Replication Partners:** ACME-DC-02.acme.local

### DNS Server Configuration
- **Zone Type:** Active Directory Integrated
- **Forward Lookup Zones:** 3 zones (acme.local, _msdcs.acme.local, TrustAnchors)
- **Reverse Lookup Zones:** 2 zones (192.168.1.x, 10.0.0.x)
- **DNS Forwarders:** 8.8.8.8, 1.1.1.1 ⚠️
- **DNS Scavenging:** Enabled (7-day refresh, 7-day no-refresh)

### DHCP Server Configuration
- **Scopes Configured:** 2 scopes
  - 192.168.1.0/24 (89% utilized) ⚠️
  - 10.0.100.0/24 (23% utilized)
- **Reservations:** 15 static reservations
- **DHCP Options:** DNS servers, domain name, router configured
- **Failover:** Configured with ACME-DC-02

### File Services
- **Shared Folders:** 8 shares
  - NETLOGON (\\ACME-DC-01\NETLOGON)
  - SYSVOL (\\ACME-DC-01\SYSVOL)
  - CompanyShared (\\ACME-DC-01\CompanyShared)
  - UserHome (\\ACME-DC-01\UserHome)
  - IT-Tools (\\ACME-DC-01\IT-Tools)
  - Backups (\\ACME-DC-01\Backups)
  - Software (\\ACME-DC-01\Software)
  - Templates (\\ACME-DC-01\Templates)

## Active Directory Health Analysis

### Domain Controller Diagnostics
- **DCDiag Results:** All tests passed
- **Replication Status:** Healthy
  - Last successful replication: 2025-09-24 15:32:45
  - Replication partner: ACME-DC-02.acme.local
- **SYSVOL Replication:** DFS-R (Healthy)
- **Time Synchronization:** W32Time configured (External source)

### User Account Analysis
- **Total Domain Users:** 247 users
- **Enabled Users:** 195 users
- **Disabled Users:** 52 users
- **Administrative Users:** 12 users
- **Stale User Accounts (90+ days):** 47 users ⚠️
- **Stale User Accounts (180+ days):** 23 users
- **Password Never Expires:** 8 accounts

### Computer Account Analysis
- **Total Computer Accounts:** 189 computers
- **Active Computers:** 145 computers
- **Stale Computer Accounts (90+ days):** 44 computers
- **Stale Computer Accounts (180+ days):** 23 computers ⚠️
- **Operating Systems:**
  - Windows 11: 89 computers
  - Windows 10: 67 computers
  - Windows Server 2022: 8 computers
  - Windows Server 2019: 12 computers
  - Unknown/Legacy: 13 computers

### Group Policy Analysis
- **Group Policy Objects:** 23 GPOs
- **Linked GPOs:** 19 GPOs
- **Unlinked GPOs:** 4 GPOs
- **Computer Policies Applied:** 156 settings
- **User Policies Applied:** 89 settings

## Security Configuration

### Windows Defender Status
- **Antivirus Protection:** Windows Defender
- **Real-time Protection:** Enabled
- **Cloud Protection:** Enabled
- **Tamper Protection:** Enabled
- **Last Update:** 2025-09-24 08:00:22

### Firewall Configuration
- **Domain Profile:** Enabled
- **Private Profile:** Enabled
- **Public Profile:** Enabled
- **Inbound Rules:** 47 rules (12 custom)
- **Outbound Rules:** 23 rules (5 custom)

### BitLocker Status
- **System Drive (C:):** Encrypted
- **Data Drive (D:):** Encrypted
- **Recovery Keys:** Backed up to AD
- **TPM Status:** Available (Version 2.0)

## User Account Analysis

### Domain Administrators
- **Total Domain Admins:** 4 accounts
  - Administrator (Built-in - Disabled)
  - ACME\admin.service (Service Account - Enabled)
  - ACME\john.doe (IT Manager - Enabled - Last login: 2025-09-24)
  - ACME\jane.admin (IT Admin - Enabled - Last login: 2025-09-23)

### Enterprise Administrators
- **Total Enterprise Admins:** 2 accounts
  - Administrator (Built-in - Disabled)
  - ACME\john.doe (IT Manager - Enabled)

### Service Accounts
- **Identified Service Accounts:** 8 accounts
- **Password Never Expires:** 6 service accounts
- **Interactive Logon Allowed:** 2 service accounts ⚠️

## Network Configuration

### Network Adapters
- **Management:** Intel X710 (Connected - 10 Gbps)
  - IP: 192.168.1.10/24
  - Gateway: 192.168.1.1
  - DNS: 127.0.0.1, 192.168.1.11
- **Backup:** Intel X710 #2 (Connected - 10 Gbps)
  - IP: 10.0.0.10/24
  - No Gateway (Management only)

### Network Services Status
- **Active Directory Web Services:** Running
- **DNS Server:** Running
- **DHCP Server:** Running
- **Netlogon:** Running
- **KDC (Kerberos):** Running
- **Print Spooler:** Running ⚠️

### Active Network Connections
- **Established Connections:** 67 connections
- **Listening Services:** 12 services
  - 53/tcp,udp (DNS)
  - 88/tcp,udp (Kerberos)
  - 135/tcp (RPC Endpoint Mapper)
  - 389/tcp (LDAP)
  - 445/tcp (SMB)
  - 464/tcp,udp (Kerberos Password Change)
  - 636/tcp (LDAPS)
  - 3268/tcp (Global Catalog)
  - 3269/tcp (Global Catalog SSL)
  - 3389/tcp (Remote Desktop)
  - 5985/tcp (WinRM HTTP)
  - 9389/tcp (AD Web Services)

## System Performance

### Memory Analysis
- **Physical Memory:** 64.00 GB
- **Available Memory:** 34.2 GB (53.4%)
- **Memory Usage:** 47% (Normal)
- **Virtual Memory:** 73.4 GB (41% used)
- **Page File Usage:** Low

### Top Memory Processes
1. **lsass.exe:** 2.8 GB (4.4%) - Active Directory Services
2. **dns.exe:** 1.2 GB (1.9%) - DNS Server
3. **svchost.exe (multiple):** 3.1 GB (4.8%) - Windows Services
4. **dfsr.exe:** 845 MB (1.3%) - DFS Replication
5. **dfsrs.exe:** 623 MB (1.0%) - DFS Replication Service

### Disk Usage Analysis
- **System Drive (C:):** 45% used
  - Total: 500 GB
  - Used: 225 GB
  - Free: 275 GB
- **Data Drive (D:):** 67% used
  - Total: 1.5 TB
  - Used: 1.0 TB
  - Free: 500 GB

### Running Processes
- **Total Processes:** 156 processes
- **System Processes:** 78 processes
- **Service Processes:** 78 processes

## Event Log Analysis (Last 3 Days)

### Security Events
- **Total Events:** 45,678 events
- **Logon Events (4624):** 3,247 events
- **Logon Failures (4625):** 23 events
- **Account Management (4720-4726):** 12 events
- **Privilege Use (4672):** 1,234 events
- **Policy Changes (4719):** 5 events

### System Events
- **Critical Events:** 0 events
- **Error Events:** 8 events
- **Warning Events:** 34 events
- **Information Events:** 2,456 events

### Directory Service Events
- **Replication Events:** 156 events (All successful)
- **Authentication Events:** 8,934 events
- **LDAP Events:** 2,345 events

## Patch Management Status

### Windows Update Configuration
- **Update Source:** WSUS Server (wsus.acme.local)
- **Automatic Updates:** Automatic download and install
- **Last Check:** 2025-09-24 06:00:00 (Today)
- **Pending Reboot:** No

### Available Updates
- **Security Updates:** 3 available ⚠️
- **Critical Updates:** 2 available ⚠️
- **Important Updates:** 3 available
- **Optional Updates:** 0 available

### Update History (Last 30 Days)
- **Successfully Installed:** 18 updates
- **Failed Installations:** 0 updates
- **Last Successful Update:** 2025-09-22

## DHCP Analysis

### Scope Configuration
- **Scope 192.168.1.0/24:**
  - Range: 192.168.1.50 - 192.168.1.250
  - Total Addresses: 201
  - Available: 22 (11%) ⚠️
  - In Use: 179 (89%)
  - Reserved: 15 addresses

- **Scope 10.0.100.0/24:**
  - Range: 10.0.100.10 - 10.0.100.200
  - Total Addresses: 191
  - Available: 147 (77%)
  - In Use: 44 (23%)
  - Reserved: 5 addresses

### DHCP Options
- **Option 003 (Router):** 192.168.1.1, 10.0.100.1
- **Option 006 (DNS Servers):** 192.168.1.10, 192.168.1.11
- **Option 015 (Domain Name):** acme.local
- **Option 044 (WINS Servers):** Not configured

## DNS Analysis

### Zone Health
- **Forward Zones:** 3 zones (All healthy)
  - acme.local: 247 A records, 45 CNAME records
  - _msdcs.acme.local: Service location records
  - TrustAnchors: DNSSEC trust anchors

- **Reverse Zones:** 2 zones (All healthy)
  - 1.168.192.in-addr.arpa: 179 PTR records
  - 0.0.10.in-addr.arpa: 44 PTR records

### DNS Performance
- **Query Success Rate:** 99.8%
- **Average Query Response:** 2.3ms
- **Cache Hit Ratio:** 89%
- **Recursive Queries:** 23,456 (last 24 hours)

## File Share Analysis

### Share Permissions
- **NETLOGON:** Domain Users (Read), Authenticated Users (Read)
- **SYSVOL:** Domain Users (Read), Authenticated Users (Read)
- **CompanyShared:** Domain Users (Read), IT-Staff (Full Control)
- **UserHome:** Individual user permissions
- **IT-Tools:** IT-Staff (Full Control), Help Desk (Read)
- **Backups:** Backup Operators (Full Control)
- **Software:** Domain Users (Read), IT-Staff (Full Control)
- **Templates:** Domain Users (Read), HR-Staff (Modify)

### Share Utilization
- **Most Active Share:** CompanyShared (1,234 connections/day)
- **Largest Share:** Backups (750 GB used)
- **Total Shared Space:** 1.2 TB across all shares

## Recommendations Summary

### Immediate Actions (HIGH Priority)
1. Clean up 23 stale computer accounts (180+ days inactive)
2. Disable Print Spooler service if not required for business operations
3. Install 5 critical and security updates during maintenance window

### Review and Planning (MEDIUM Priority)
1. Review and disable 47 stale user accounts (90+ days inactive)
2. Expand DHCP scope 192.168.1.0/24 or monitor usage closely
3. Review DNS forwarder configuration for compliance requirements
4. Increase Security event log maximum size to prevent data loss
5. Review necessity of administrative shares based on security policy
6. Remove interactive logon rights from service accounts

### Monitoring (LOW Priority)
1. Monitor Active Directory replication health
2. Review Group Policy settings for optimization opportunities
3. Implement automated stale account cleanup procedures
4. Monitor DHCP scope utilization trends
5. Review file share access patterns and permissions
6. Optimize DNS cache and forwarding performance

## Data Export Information

- **Report Generated:** 2025-09-24 15:45:22
- **JSON Export:** ACME-DC-01_20250924_154522_raw_data.json
- **Log File:** ACME-DC-01_20250924_154522_audit.log
- **Assessment Duration:** 6 minutes, 23 seconds
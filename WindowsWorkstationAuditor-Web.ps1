# WindowsWorkstationAuditor - Self-Contained Web Version
# Version 1.3.0 - Workstation Audit Script
# Platform: Windows 10/11, Windows Server (workstation features)
# Requires: PowerShell 5.0+
# Usage: iex (irm https://your-url/WindowsWorkstationAuditor-Web.ps1)

param(
    [string]$OutputPath = "$env:USERPROFILE\WindowsAudit",
    [switch]$Verbose
)

# Global variables
$Script:LogFile = ""
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:BaseFileName = "${ComputerName}_$($StartTime.ToString('yyyyMMdd_HHmmss'))"

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$LogDirectory = Join-Path $OutputPath "logs"
if (-not (Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}
$Script:LogFile = Join-Path $LogDirectory "${Script:BaseFileName}_audit.log"


# === src\core\Write-LogMessage.ps1 ===
# WindowsWorkstationAuditor - Centralized Logging Module
# Version 1.3.0

function Write-LogMessage {
    <#
    .SYNOPSIS
        Centralized logging function with console and file output
        
    .DESCRIPTION
        Writes log messages with timestamp, level, and category formatting.
        Provides colored console output and file logging capabilities.
        
    .PARAMETER Level
        Log level: ERROR, WARN, SUCCESS, INFO
        
    .PARAMETER Message
        The log message content
        
    .PARAMETER Category
        Optional category for message organization (default: GENERAL)
        
    .NOTES
        Requires: $Script:LogFile global variable for file output
    #>
    param(
        [string]$Level,
        [string]$Message,
        [string]$Category = "GENERAL"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] [$Category] $Message"
    
    # Console output with color coding
    switch ($Level) {
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        "WARN"  { Write-Host $LogEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        default { Write-Host $LogEntry }
    }
    
    # File output
    if ($Script:LogFile) {
        Add-Content -Path $Script:LogFile -Value $LogEntry
    }
}

# === src\core\Initialize-Logging.ps1 ===
# WindowsWorkstationAuditor - Logging Initialization Module
# Version 1.3.0

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the logging system for the audit tool
        
    .DESCRIPTION
        Creates log directory structure and sets up the main log file path.
        Can work with parameters or global script variables.
        
    .PARAMETER LogDirectory
        Directory to create log files in (optional, uses $OutputPath/logs if not specified)
        
    .PARAMETER LogFileName
        Name of the log file (optional, uses ${Script:BaseFileName}_audit.log if not specified)
        
    .NOTES
        Requires: $OutputPath, $Script:BaseFileName, $ComputerName global variables (if parameters not provided)
    #>
    param(
        [string]$LogDirectory,
        [string]$LogFileName
    )
    
    try {
        # Use parameters if provided, otherwise fall back to global variables
        if (-not $LogDirectory) {
            $LogDirectory = Join-Path $OutputPath "logs"
        }
        
        if (-not $LogFileName) {
            $LogFileName = "${Script:BaseFileName}_audit.log"
        }
        
        if (-not (Test-Path $LogDirectory)) {
            New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
        }
        
        $Script:LogFile = Join-Path $LogDirectory $LogFileName
        
        # Determine if this is workstation or server based on the filename
        $AuditorType = if ($LogFileName -like "*server*") { "WindowsServerAuditor" } else { "WindowsWorkstationAuditor" }
        
        Write-LogMessage "INFO" "$AuditorType v1.3.0 Started"
        Write-LogMessage "INFO" "Computer: $($Script:ComputerName)"
        Write-LogMessage "INFO" "User: $env:USERNAME"
        Write-LogMessage "INFO" "Base filename: $Script:BaseFileName"
        Write-LogMessage "INFO" "Log file: $Script:LogFile"
        
        return $true
    }
    catch {
        Write-Host "ERROR: Failed to initialize logging: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# === src\core\Export-MarkdownReport.ps1 ===
# WindowsWorkstationAuditor - Markdown Report Export Module
# Version 1.3.0

function Export-MarkdownReport {
    <#
    .SYNOPSIS
        Exports audit results to a technician-friendly markdown report
        
    .DESCRIPTION
        Creates a comprehensive markdown report with executive summary,
        detailed findings, action items, and full data visibility for technicians.
        
    .PARAMETER Results
        Array of audit results to include in the report
        
    .PARAMETER OutputPath
        Directory path for the markdown report output
        
    .PARAMETER BaseFileName
        Base filename for the report (without extension)
    #>
    param(
        [array]$Results,
        [string]$OutputPath,
        [string]$BaseFileName
    )
    
    if (-not $Results -or $Results.Count -eq 0) {
        Write-LogMessage "WARN" "No results to export to markdown report" "EXPORT"
        return
    }
    
    $ReportPath = Join-Path $OutputPath "${BaseFileName}_technician_report.md"
    
    try {
        # Build report content
        $ReportContent = @()
        
        # Header
        #region Report Header Generation
        # Auto-detect if this is a server audit based on results content or OS type
        $IsServerAudit = $false
        
        # Method 1: Check if server-specific results are present
        $ServerIndicators = @("Server Roles", "DHCP", "DNS", "Active Directory")
        $HasServerResults = $Results | Where-Object { $_.Category -in $ServerIndicators }
        
        # Method 2: Check OS type via WMI
        try {
            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $IsWindowsServer = $OSInfo.ProductType -ne 1  # ProductType: 1=Workstation, 2=DC, 3=Server
        }
        catch {
            $IsWindowsServer = $false
        }
        
        # Determine audit type
        $IsServerAudit = ($HasServerResults.Count -gt 0) -or $IsWindowsServer
        
        # Generate appropriate header
        if ($IsServerAudit) {
            $ReportContent += "# Windows Server IT Assessment Report"
            $ReportTitle = "WindowsServerAuditor v1.3.0"
        } else {
            $ReportContent += "# Windows Workstation Security Audit Report" 
            $ReportTitle = "WindowsWorkstationAuditor v1.3.0"
        }
        
        $ReportContent += ""
        $ReportContent += "**Computer:** $env:COMPUTERNAME"
        $ReportContent += "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $ReportContent += "**Tool Version:** $ReportTitle"
        #endregion
        $ReportContent += ""
        
        # Executive Summary
        $HighRisk = $Results | Where-Object { $_.RiskLevel -eq "HIGH" }
        $MediumRisk = $Results | Where-Object { $_.RiskLevel -eq "MEDIUM" }
        $LowRisk = $Results | Where-Object { $_.RiskLevel -eq "LOW" }
        $InfoItems = $Results | Where-Object { $_.RiskLevel -eq "INFO" }
        
        $ReportContent += "## Executive Summary"
        $ReportContent += ""
        $ReportContent += "| Risk Level | Count | Priority |"
        $ReportContent += "|------------|--------|----------|"
        $ReportContent += "| HIGH | $($HighRisk.Count) | Immediate Action Required |"
        $ReportContent += "| MEDIUM | $($MediumRisk.Count) | Review and Plan Remediation |"
        $ReportContent += "| LOW | $($LowRisk.Count) | Monitor and Maintain |"
        $ReportContent += "| INFO | $($InfoItems.Count) | Informational |"
        $ReportContent += ""
        
        # Critical Action Items
        if ($HighRisk.Count -gt 0 -or $MediumRisk.Count -gt 0) {
            $ReportContent += "## Critical Action Items"
            $ReportContent += ""
            
            if ($HighRisk.Count -gt 0) {
                $ReportContent += "### HIGH PRIORITY (Immediate Action Required)"
                $ReportContent += ""
                foreach ($Item in $HighRisk) {
                    $ReportContent += "- **$($Item.Category) - $($Item.Item):** $($Item.Value)"
                    $ReportContent += "  - Details: $($Item.Details)"
                    if ($Item.Recommendation) {
                        $ReportContent += "  - Recommendation: $($Item.Recommendation)"
                    }
                    $ReportContent += ""
                }
            }
            
            if ($MediumRisk.Count -gt 0) {
                $ReportContent += "### MEDIUM PRIORITY (Review and Plan)"
                $ReportContent += ""
                foreach ($Item in $MediumRisk) {
                    $ReportContent += "- **$($Item.Category) - $($Item.Item):** $($Item.Value)"
                    $ReportContent += "  - Details: $($Item.Details)"
                    if ($Item.Recommendation) {
                        $ReportContent += "  - Recommendation: $($Item.Recommendation)"
                    }
                    $ReportContent += ""
                }
            }
        }
        
        # Additional Information (LOW and INFO items only, excluding Security Events to avoid repetition)
        $AdditionalItems = $Results | Where-Object { $_.RiskLevel -in @("LOW", "INFO") -and $_.Category -ne "Security Events" }
        $AdditionalCategories = $AdditionalItems | Group-Object Category | Sort-Object Name
        
        if ($AdditionalCategories.Count -gt 0) {
            $ReportContent += "## Additional Information"
            $ReportContent += ""
            
            foreach ($Category in $AdditionalCategories) {
                $CategoryName = $Category.Name
                $CategoryItems = $Category.Group
                
                $ReportContent += "### $CategoryName"
                $ReportContent += ""
                
                foreach ($Item in $CategoryItems) {
                    $RiskIcon = switch ($Item.RiskLevel) {
                        "LOW" { "[LOW]" }
                        default { "[INFO]" }
                    }
                    
                    $ReportContent += "**$RiskIcon $($Item.Item):** $($Item.Value)"
                    $ReportContent += ""
                    $ReportContent += "- **Details:** $($Item.Details)"
                    if ($Item.Recommendation) {
                        $ReportContent += "- **Recommendation:** $($Item.Recommendation)"
                    }
                    $ReportContent += ""
                }
            }
        }
        
        # System Information Section with Enhanced Details
        $SystemInfo = $Results | Where-Object { $_.Category -eq "System" }
        if ($SystemInfo) {
            $ReportContent += "## System Configuration Details"
            $ReportContent += ""
            foreach ($Item in $SystemInfo) {
                $ReportContent += "- **$($Item.Item):** $($Item.Value) - $($Item.Details)"
            }
            $ReportContent += ""
        }
        
        # Recommendation Summary
        $RecommendationItems = $Results | Where-Object { $_.Recommendation -and $_.Recommendation.Trim() -ne "" }
        if ($RecommendationItems.Count -gt 0) {
            $ReportContent += "## Recommendations"
            $ReportContent += ""
            $RecommendationItems | Group-Object Recommendation | ForEach-Object {
                $ReportContent += "- **$($_.Name)**"
                $ReportContent += "  - Affected Items: $($_.Count)"
                $ReportContent += ""
            }
        }
        
        # Footer
        $ReportContent += "---"
        $ReportContent += ""
        $ReportContent += "*This report was generated by WindowsWorkstationAuditor v1.3.0*"
        $ReportContent += ""
        $ReportContent += "*For detailed data analysis and aggregation, refer to the corresponding JSON export.*"
        
        # Write report to file
        $ReportContent | Set-Content -Path $ReportPath -Encoding UTF8
        
        Write-LogMessage "SUCCESS" "Markdown report exported: $ReportPath" "EXPORT"
        return $ReportPath
    }
    catch {
        Write-LogMessage "ERROR" "Failed to export markdown report: $($_.Exception.Message)" "EXPORT"
        return $null
    }
}

# === src\core\Export-RawDataJSON.ps1 ===
# WindowsWorkstationAuditor - Raw Data JSON Export Module
# Version 1.3.0

function Export-RawDataJSON {
    <#
    .SYNOPSIS
        Exports comprehensive audit data to structured JSON for aggregation tools
        
    .DESCRIPTION
        Creates a detailed JSON export with complete data structures, raw collections,
        metadata, and standardized schema for use by aggregation and analysis tools.
        
    .PARAMETER Results
        Array of audit results from modules
        
    .PARAMETER RawData
        Hashtable of raw data collections from modules (optional)
        
    .PARAMETER OutputPath
        Directory path for the JSON output
        
    .PARAMETER BaseFileName
        Base filename for the export (without extension)
    #>
    param(
        [array]$Results,
        [hashtable]$RawData = @{},
        [string]$OutputPath,
        [string]$BaseFileName
    )
    
    if (-not $Results -or $Results.Count -eq 0) {
        Write-LogMessage "WARN" "No results to export to raw JSON" "EXPORT"
        return
    }
    
    $JSONPath = Join-Path $OutputPath "${BaseFileName}_raw_data.json"
    
    try {
        # Build comprehensive data structure
        $AuditData = [ordered]@{
            metadata = [ordered]@{
                tool_name = "WindowsWorkstationAuditor"
                tool_version = "1.3.0"
                schema_version = "1.0"
                computer_name = $env:COMPUTERNAME
                audit_timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                audit_duration_seconds = if ($Script:StartTime) { ((Get-Date) - $Script:StartTime).TotalSeconds } else { 0 }
                total_findings = $Results.Count
            }
            
            risk_summary = [ordered]@{
                high_risk_count = ($Results | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
                medium_risk_count = ($Results | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
                low_risk_count = ($Results | Where-Object { $_.RiskLevel -eq "LOW" }).Count
                info_count = ($Results | Where-Object { $_.RiskLevel -eq "INFO" }).Count
                recommendation_findings = ($Results | Where-Object { $_.Recommendation -and $_.Recommendation.Trim() -ne "" }).Count
            }
            
            categories = [ordered]@{}
            
            raw_collections = [ordered]@{}
            
            recommendation_framework = [ordered]@{
                primary = "NIST"
                findings = @()
            }
        }
        
        # Process results by category
        $Categories = $Results | Group-Object Category
        
        foreach ($Category in $Categories) {
            $CategoryName = $Category.Name
            $CategoryItems = $Category.Group
            
            $AuditData.categories[$CategoryName] = [ordered]@{
                total_items = $CategoryItems.Count
                risk_breakdown = [ordered]@{
                    high = ($CategoryItems | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
                    medium = ($CategoryItems | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
                    low = ($CategoryItems | Where-Object { $_.RiskLevel -eq "LOW" }).Count
                    info = ($CategoryItems | Where-Object { $_.RiskLevel -eq "INFO" }).Count
                }
                findings = @()
            }
            
            # Add each finding with enhanced structure
            foreach ($Item in $CategoryItems) {
                $Finding = [ordered]@{
                    id = [System.Guid]::NewGuid().ToString()
                    item_name = $Item.Item
                    value = $Item.Value
                    details = $Item.Details
                    risk_level = $Item.RiskLevel
                    recommendation_note = $Item.Recommendation
                    category = $Item.Category
                    timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
                
                $AuditData.categories[$CategoryName].findings += $Finding
                
                # Add to recommendation findings if applicable
                if ($Item.Recommendation -and $Item.Recommendation.Trim() -ne "") {
                    $RecommendationFinding = [ordered]@{
                        finding_id = $Finding.id
                        framework = "NIST"
                        recommendation = $Item.Recommendation
                        category = $CategoryName
                        item = $Item.Item
                        risk_level = $Item.RiskLevel
                    }
                    $AuditData.recommendation_framework.findings += $RecommendationFinding
                }
            }
        }
        
        # Add raw data collections if provided
        foreach ($DataType in $RawData.Keys) {
            $AuditData.raw_collections[$DataType] = $RawData[$DataType]
        }
        
        # Add system context data
        $AuditData.system_context = [ordered]@{
            powershell_version = $PSVersionTable.PSVersion.ToString()
            execution_policy = (Get-ExecutionPolicy).ToString()
            current_user = $env:USERNAME
            domain = $env:USERDOMAIN
            os_info = [ordered]@{}
        }
        
        # Try to get OS information
        try {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ($OS) {
                $AuditData.system_context.os_info = [ordered]@{
                    caption = $OS.Caption
                    version = $OS.Version
                    build_number = $OS.BuildNumber
                    architecture = $OS.OSArchitecture
                    install_date = if ($OS.InstallDate) { $OS.InstallDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { $null }
                    last_boot_time = if ($OS.LastBootUpTime) { $OS.LastBootUpTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { $null }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve OS information for JSON export: $($_.Exception.Message)" "EXPORT"
        }
        
        # Export with proper formatting
        $JSONContent = $AuditData | ConvertTo-Json -Depth 10 -Compress:$false
        $JSONContent | Set-Content -Path $JSONPath -Encoding UTF8
        
        Write-LogMessage "SUCCESS" "Raw data JSON exported: $JSONPath" "EXPORT"
        return $JSONPath
    }
    catch {
        Write-LogMessage "ERROR" "Failed to export raw JSON: $($_.Exception.Message)" "EXPORT"
        return $null
    }
}

function Add-RawDataCollection {
    <#
    .SYNOPSIS
        Helper function for modules to register raw data collections
        
    .DESCRIPTION
        Allows audit modules to register detailed data collections that should
        be included in the raw JSON export for aggregation tools.
        
    .PARAMETER CollectionName
        Name of the data collection
        
    .PARAMETER Data
        Raw data to be included in export
        
    .PARAMETER Global:RawDataCollections
        Global hashtable to store collections (created if doesn't exist)
    #>
    param(
        [string]$CollectionName,
        [object]$Data
    )
    
    if (-not (Get-Variable -Name "RawDataCollections" -Scope Global -ErrorAction SilentlyContinue)) {
        $Global:RawDataCollections = @{}
    }
    
    $Global:RawDataCollections[$CollectionName] = $Data
    Write-LogMessage "INFO" "Added raw data collection: $CollectionName ($($Data.Count) items)" "EXPORT"
}

# === src\modules\Get-SystemInformation.ps1 ===
# WindowsWorkstationAuditor - System Information Module
# Version 1.3.0

function Get-SystemInformation {
    <#
    .SYNOPSIS
        Collects comprehensive system information including Azure AD and WSUS detection
        
    .DESCRIPTION
        Gathers OS, hardware, domain status, Azure AD tenant info, MDM enrollment,
        and WSUS configuration details for security assessment.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (dsregcmd for Azure AD detection)
    #>
    
    Write-LogMessage "INFO" "Collecting system information..." "SYSTEM"
    
    try {
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem
        $Computer = Get-CimInstance -ClassName Win32_ComputerSystem
        
        # Azure AD and MDM Detection
        $AzureADJoined = $false
        $DomainJoined = $Computer.PartOfDomain
        $DomainName = if ($DomainJoined) { $Computer.Domain } else { "WORKGROUP" }
        $TenantId = ""
        $TenantName = ""
        $MDMEnrolled = $false
        
        try {
            Write-LogMessage "INFO" "Checking Azure AD status with dsregcmd..." "SYSTEM"
            $DsregOutput = & dsregcmd /status 2>$null
            if ($LASTEXITCODE -eq 0) {
                # Check Azure AD joined status
                $AzureADLine = $DsregOutput | Where-Object { $_ -match "AzureAdJoined\s*:\s*YES" }
                $AzureADJoined = $AzureADLine -ne $null
                
                if ($AzureADJoined) {
                    $DomainName = "Azure AD Joined"
                    
                    # Extract Tenant ID
                    $TenantLine = $DsregOutput | Where-Object { $_ -match "TenantId\s*:\s*(.+)" }
                    if ($TenantLine -and $matches[1]) {
                        $TenantId = $matches[1].Trim()
                        Write-LogMessage "INFO" "Azure AD Tenant ID: $TenantId" "SYSTEM"
                    }
                    
                    # Try to get tenant name/domain
                    $TenantDisplayLine = $DsregOutput | Where-Object { $_ -match "TenantDisplayName\s*:\s*(.+)" }
                    if ($TenantDisplayLine -and $matches[1]) {
                        $TenantName = $matches[1].Trim()
                        Write-LogMessage "INFO" "Azure AD Tenant Name: $TenantName" "SYSTEM"
                    } else {
                        $TenantNameLine = $DsregOutput | Where-Object { $_ -match "TenantName\s*:\s*(.+)" }
                        if ($TenantNameLine -and $matches[1]) {
                            $TenantName = $matches[1].Trim()
                            Write-LogMessage "INFO" "Azure AD Tenant Name (alt): $TenantName" "SYSTEM"
                        }
                    }
                    
                    # Check MDM enrollment status
                    $MDMUrlLine = $DsregOutput | Where-Object { $_ -match "MdmUrl\s*:\s*(.+)" }
                    if ($MDMUrlLine) {
                        $MDMEnrolled = $true
                        Write-LogMessage "INFO" "MDM enrolled: Yes" "SYSTEM"
                    } else {
                        Write-LogMessage "INFO" "MDM enrolled: No" "SYSTEM"
                    }
                }
                
                Write-LogMessage "SUCCESS" "Azure AD joined: $AzureADJoined, MDM enrolled: $MDMEnrolled" "SYSTEM"
            } else {
                Write-LogMessage "WARN" "dsregcmd returned exit code: $LASTEXITCODE" "SYSTEM"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check Azure AD status: $($_.Exception.Message)" "SYSTEM"
        }
        
        # WSUS Configuration Check
        $WSUSConfigured = $false
        $WSUSServer = ""
        try {
            $WSUSRegKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
            if ($WSUSRegKey -and $WSUSRegKey.WUServer) {
                $WSUSConfigured = $true
                $WSUSServer = $WSUSRegKey.WUServer
                Write-LogMessage "INFO" "WSUS Server detected: $WSUSServer" "SYSTEM"
            } else {
                # Check local machine settings as fallback
                $WSUSRegKey2 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -ErrorAction SilentlyContinue
                if ($WSUSRegKey2 -and $WSUSRegKey2.WUServer) {
                    $WSUSConfigured = $true
                    $WSUSServer = $WSUSRegKey2.WUServer
                    Write-LogMessage "INFO" "WSUS Server detected in local settings: $WSUSServer" "SYSTEM"
                }
            }
            
            if (-not $WSUSConfigured) {
                Write-LogMessage "INFO" "WSUS not configured - using Microsoft Update directly" "SYSTEM"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check WSUS configuration: $($_.Exception.Message)" "SYSTEM"
        }
        
        $Results = @()
        
        # Operating System Info
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "Operating System"
            Value = "$($OS.Caption) $($OS.Version)"
            Details = "Build: $($OS.BuildNumber), Install Date: $($OS.InstallDate)"
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        # Hardware Info
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "Hardware"
            Value = "$($Computer.Manufacturer) $($Computer.Model)"
            Details = "RAM: $([math]::Round($Computer.TotalPhysicalMemory/1GB, 2))GB, Processors: $($Computer.NumberOfProcessors)"
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        # Domain Status with Tenant Info
        $DomainDetails = if ($AzureADJoined) { 
            $TenantInfo = if ($TenantName) { 
                "$TenantName ($TenantId)" 
            } else { 
                "Tenant ID: $TenantId" 
            }
            "Azure AD joined - $TenantInfo"
        } elseif ($DomainJoined) { 
            "Domain joined system" 
        } else { 
            "Workgroup system" 
        }
        
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "Domain Status"
            Value = $DomainName
            Details = $DomainDetails
            RiskLevel = if ($AzureADJoined -or $DomainJoined) { "LOW" } else { "MEDIUM" }
            Recommendation = if (-not $AzureADJoined -and -not $DomainJoined) { "Consider domain or Azure AD joining for centralized management" } else { "" }
        }
        
        # WSUS Configuration Status
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "WSUS Configuration"
            Value = if ($WSUSConfigured) { "Configured" } else { "Not Configured" }
            Details = if ($WSUSConfigured) { "Server: $WSUSServer" } else { "Using Microsoft Update directly" }
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        # MDM Enrollment Status (only for Azure AD joined systems)
        if ($AzureADJoined) {
            $Results += [PSCustomObject]@{
                Category = "System"
                Item = "MDM Enrollment"
                Value = if ($MDMEnrolled) { "Enrolled" } else { "Not Enrolled" }
                Details = if ($MDMEnrolled) { "Device enrolled in Mobile Device Management" } else { "Device not enrolled in MDM" }
                RiskLevel = if ($MDMEnrolled) { "LOW" } else { "MEDIUM" }
                Recommendation = if (-not $MDMEnrolled) { "Consider MDM enrollment for device management" } else { "" }
            }
        }
        
        Write-LogMessage "SUCCESS" "System information collected - Domain: $DomainName, WSUS: $WSUSConfigured, MDM: $MDMEnrolled" "SYSTEM"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to collect system information: $($_.Exception.Message)" "SYSTEM"
        return @()
    }
}

# === src\modules\Get-UserAccountAnalysis.ps1 ===
# WindowsWorkstationAuditor - User Account Analysis Module
# Version 1.3.0

function Get-UserAccountAnalysis {
    <#
    .SYNOPSIS
        Analyzes user accounts and administrative privileges with Azure AD support
        
    .DESCRIPTION
        Performs comprehensive analysis of local and Azure AD user accounts including:
        - Local administrator account enumeration
        - Current user privilege assessment
        - Guest account status verification
        - Azure AD joined system detection
        - Administrative privilege distribution analysis
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local admin rights recommended for complete analysis
        Supports: Traditional domain, Azure AD joined, and workgroup systems
    #>
    
    Write-LogMessage "INFO" "Analyzing user accounts..." "USERS"
    
    try {
        $LocalAdmins = @()
        
        # Determine execution context
        $CurrentUser = if ($env:USERNAME -eq "SYSTEM") { "SYSTEM" } else { $env:USERNAME }
        Write-LogMessage "INFO" "Current user: $CurrentUser" "USERS"
        
        # Check if current user is admin
        $IsCurrentUserAdmin = $false
        try {
            $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
            $IsCurrentUserAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            Write-LogMessage "INFO" "Current user is admin: $IsCurrentUserAdmin" "USERS"
        }
        catch {
            Write-LogMessage "WARN" "Could not check current user admin status: $($_.Exception.Message)" "USERS"
        }
        
        # Detect if we're on a Domain Controller
        $IsDomainController = $false
        try {
            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $IsDomainController = $OSInfo.ProductType -eq 2  # ProductType: 1=Workstation, 2=DC, 3=Server
            Write-LogMessage "INFO" "Domain Controller detected: $IsDomainController" "USERS"
        }
        catch {
            Write-LogMessage "WARN" "Could not determine system type for DC detection" "USERS"
        }
        
        # Use different methods based on whether we're on a Domain Controller
        if ($IsDomainController) {
            Write-LogMessage "INFO" "Using Active Directory methods for Domain Controller..." "USERS"
            try {
                # Try to import AD module
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                
                # Get Domain Admins and Enterprise Admins
                $DomainAdmins = @()
                $EnterpriseAdmins = @()
                
                try {
                    $DomainAdmins = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                } catch {
                    Write-LogMessage "WARN" "Could not get Domain Admins: $($_.Exception.Message)" "USERS"
                }
                
                try {
                    $EnterpriseAdmins = Get-ADGroupMember "Enterprise Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                } catch {
                    Write-LogMessage "WARN" "Could not get Enterprise Admins: $($_.Exception.Message)" "USERS"
                }
                
                # Combine and deduplicate
                $LocalAdmins = @($DomainAdmins) + @($EnterpriseAdmins) | Sort-Object -Unique | Where-Object { $_ -ne $null }
                Write-LogMessage "INFO" "Found $($DomainAdmins.Count) Domain Admins, $($EnterpriseAdmins.Count) Enterprise Admins" "USERS"
            }
            catch {
                Write-LogMessage "WARN" "AD module not available, falling back to local group detection: $($_.Exception.Message)" "USERS"
                $IsDomainController = $false  # Fall back to local methods
            }
        }
        
        # Use local methods for non-DCs or if AD methods failed
        if (-not $IsDomainController -or $LocalAdmins.Count -eq 0) {
            Write-LogMessage "INFO" "Using local group detection methods..." "USERS"
        
        # Method 1: Try Get-LocalGroupMember (best for Azure AD)
        try {
            Write-LogMessage "INFO" "Attempting Get-LocalGroupMember..." "USERS"
            $AdminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            Write-LogMessage "INFO" "Get-LocalGroupMember returned $($AdminMembers.Count) members" "USERS"
            
            $LocalAdmins = foreach ($Member in $AdminMembers) {
                Write-LogMessage "INFO" "Processing member: Name='$($Member.Name)', ObjectClass='$($Member.ObjectClass)'" "USERS"
                
                # Extract just the username part
                if ($Member.Name -match "\\") {
                    $Username = $Member.Name.Split('\')[-1]
                } else {
                    $Username = $Member.Name
                }
                Write-LogMessage "INFO" "Extracted username: '$Username'" "USERS"
                $Username
            }
        }
        catch {
            Write-LogMessage "WARN" "Get-LocalGroupMember failed: $($_.Exception.Message)" "USERS"
        }
        
        # Method 2: Fallback to net localgroup
        if ($LocalAdmins.Count -eq 0) {
            try {
                Write-LogMessage "INFO" "Fallback: Using net localgroup Administrators" "USERS"
                $NetOutput = & net localgroup Administrators 2>&1
                Write-LogMessage "INFO" "Net command output has $($NetOutput.Count) lines" "USERS"
                
                if ($LASTEXITCODE -eq 0) {
                    $InMembersList = $false
                    $LocalAdmins = foreach ($Line in $NetOutput) {
                        # Look for the separator line
                        if ($Line -match "^-+$") {
                            $InMembersList = $true
                            continue
                        }
                        
                        # Process member lines
                        if ($InMembersList -and $Line.Trim() -ne "" -and $Line -notmatch "The command completed successfully") {
                            $CleanName = $Line.Trim()
                            # Handle AzureAD\ prefix
                            if ($CleanName -match "^AzureAD\\(.+)$") {
                                $CleanName = $matches[1]
                            }
                            Write-LogMessage "INFO" "Found admin: '$CleanName'" "USERS"
                            $CleanName
                        }
                    }
                }
            }
            catch {
                Write-LogMessage "ERROR" "Net localgroup method failed: $($_.Exception.Message)" "USERS"
            }
        }
        
            # Method 3: If still no admins but current user is admin, add them
            if ($LocalAdmins.Count -eq 0 -and $IsCurrentUserAdmin) {
                Write-LogMessage "INFO" "Adding current user as admin since detection failed" "USERS"
                $LocalAdmins = @($env:USERNAME)
            }
        }
        
        $Results = @()
        
        # Local Administrator Count (always add this result)
        $AdminCount = $LocalAdmins.Count
        Write-LogMessage "SUCCESS" "Administrator count: $AdminCount" "USERS"
        $Results += [PSCustomObject]@{
            Category = "Users"
            Item = "Local Administrators"
            Value = $AdminCount
            Details = "Users: $($LocalAdmins -join ', ')"
            RiskLevel = if ($AdminCount -gt 3) { "HIGH" } elseif ($AdminCount -gt 1) { "MEDIUM" } else { "LOW" }
            Recommendation = if ($AdminCount -gt 3) { "Limit administrative access" } else { "" }
        }
        
        # Account Security Analysis (different for DCs vs regular systems)
        if ($IsDomainController) {
            # For Domain Controllers: Check for disabled domain accounts
            try {
                if (Get-Module -Name ActiveDirectory -ListAvailable) {
                    $DisabledUsers = Get-ADUser -Filter {Enabled -eq $false} -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
                    $Results += [PSCustomObject]@{
                        Category = "Users"
                        Item = "Disabled Domain Accounts"
                        Value = $DisabledUsers
                        Details = "Disabled user accounts in Active Directory"
                        RiskLevel = if ($DisabledUsers -gt 10) { "MEDIUM" } else { "LOW" }
                        Recommendation = if ($DisabledUsers -gt 10) { "Review and clean up disabled accounts" } else { "" }
                    }
                    Write-LogMessage "INFO" "Found $DisabledUsers disabled domain accounts" "USERS"
                } else {
                    Write-LogMessage "INFO" "Active Directory module not available for disabled account analysis" "USERS"
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not check disabled domain accounts: $($_.Exception.Message)" "USERS"
            }
        } else {
            # For regular systems: Check Guest Account Status
            try {
                $LocalUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
                if ($LocalUsers) {
                    $GuestAccount = $LocalUsers | Where-Object { $_.Name -eq "Guest" }
                    if ($GuestAccount) {
                        $Results += [PSCustomObject]@{
                            Category = "Users"
                            Item = "Guest Account"
                            Value = if ($GuestAccount.Disabled) { "Disabled" } else { "Enabled" }
                            Details = "Guest account status"
                            RiskLevel = if ($GuestAccount.Disabled) { "LOW" } else { "HIGH" }
                            Recommendation = if (-not $GuestAccount.Disabled) { "Disable guest account" } else { "" }
                        }
                    } else {
                        Write-LogMessage "INFO" "No Guest account found in local users" "USERS"
                    }
                } else {
                    Write-LogMessage "WARN" "Unable to enumerate local users" "USERS"
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not check local users for Guest account: $($_.Exception.Message)" "USERS"
            }
        }
        
        Write-LogMessage "SUCCESS" "User account analysis completed - Found $AdminCount administrators" "USERS"
        Write-LogMessage "INFO" "Returning $($Results.Count) user account results" "USERS"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze user accounts: $($_.Exception.Message)" "USERS"
        return @()
    }
}

# === src\modules\Get-SoftwareInventory.ps1 ===
# WindowsWorkstationAuditor - Software Inventory Module
# Version 1.3.0

function Get-SoftwareInventory {
    <#
    .SYNOPSIS
        Collects comprehensive software inventory from Windows registry
        
    .DESCRIPTION
        Performs detailed software inventory analysis including:
        - Installed program enumeration from both 32-bit and 64-bit registry locations
        - Critical software version checking (browsers, office suites, runtimes)
        - Software age analysis for update compliance
        - Installation date tracking for security assessment
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Standard user rights sufficient for registry reading
        Coverage: Both 32-bit and 64-bit installed applications
    #>
    
    Write-LogMessage "INFO" "Collecting software inventory..." "SOFTWARE"
    
    try {
        $Software64 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -and $_.DisplayName -notlike "KB*" }
        
        $Software32 = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -and $_.DisplayName -notlike "KB*" }
        
        $AllSoftware = $Software64 + $Software32 | Sort-Object DisplayName -Unique
        
        $Results = @()
        
        # Software count summary
        $Results += [PSCustomObject]@{
            Category = "Software"
            Item = "Total Installed Programs"
            Value = $AllSoftware.Count
            Details = "Unique installed applications"
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        # Check for critical software and versions
        $CriticalSoftware = @(
            @{Name="Google Chrome"; Pattern="Chrome"}
            @{Name="Mozilla Firefox"; Pattern="Firefox"}
            @{Name="Adobe Acrobat"; Pattern="Adobe.*Acrobat"}
            @{Name="Microsoft Office"; Pattern="Microsoft Office"}
            @{Name="Java"; Pattern="Java"}
        )
        
        foreach ($Critical in $CriticalSoftware) {
            $Found = $AllSoftware | Where-Object { $_.DisplayName -match $Critical.Pattern } | Select-Object -First 1
            if ($Found) {
                $InstallDate = if ($Found.InstallDate) { 
                    try { [datetime]::ParseExact($Found.InstallDate, "yyyyMMdd", $null) } catch { $null }
                } else { $null }
                
                $AgeInDays = if ($InstallDate) { (New-TimeSpan -Start $InstallDate -End (Get-Date)).Days } else { $null }
                
                $RiskLevel = if ($AgeInDays -gt 365) { "HIGH" } elseif ($AgeInDays -gt 180) { "MEDIUM" } else { "LOW" }
                
                $Results += [PSCustomObject]@{
                    Category = "Software"
                    Item = $Critical.Name
                    Value = $Found.DisplayVersion
                    Details = "Install Date: $(if ($InstallDate) { $InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }), Age: $(if ($AgeInDays) { "$AgeInDays days" } else { 'Unknown' })"
                    RiskLevel = $RiskLevel
                    Recommendation = if ($AgeInDays -gt 365) { "Regular software updates required" } else { "" }
                }
            }
        }
        
        # Check for remote access software - investigation point
        $RemoteAccessSoftware = @(
            @{Name="TeamViewer"; Pattern="TeamViewer"; Risk="MEDIUM"}
            @{Name="AnyDesk"; Pattern="AnyDesk"; Risk="MEDIUM"}
            @{Name="Chrome Remote Desktop"; Pattern="Chrome Remote Desktop"; Risk="MEDIUM"}
            @{Name="VNC Viewer"; Pattern="VNC.*Viewer|RealVNC"; Risk="MEDIUM"}
            @{Name="UltraVNC"; Pattern="UltraVNC"; Risk="MEDIUM"}
            @{Name="TightVNC"; Pattern="TightVNC"; Risk="MEDIUM"}
            @{Name="Remote Desktop Manager"; Pattern="Remote Desktop Manager"; Risk="MEDIUM"}
            @{Name="LogMeIn"; Pattern="LogMeIn"; Risk="MEDIUM"}
            @{Name="GoToMyPC"; Pattern="GoToMyPC"; Risk="MEDIUM"}
            @{Name="Splashtop"; Pattern="Splashtop"; Risk="MEDIUM"}
            @{Name="Parsec"; Pattern="Parsec"; Risk="MEDIUM"}
            @{Name="Ammyy Admin"; Pattern="Ammyy"; Risk="HIGH"}
            @{Name="SupRemo"; Pattern="SupRemo"; Risk="MEDIUM"}
            @{Name="Radmin"; Pattern="Radmin"; Risk="MEDIUM"}
            # Additional common enterprise remote access tools
            @{Name="ScreenConnect"; Pattern="ScreenConnect|ConnectWise.*Control"; Risk="MEDIUM"}
            @{Name="ConnectWise Control"; Pattern="ConnectWise.*Control|ScreenConnect"; Risk="MEDIUM"}
            @{Name="BeyondTrust Remote Support"; Pattern="BeyondTrust|Bomgar"; Risk="MEDIUM"}
            @{Name="Jump Desktop"; Pattern="Jump Desktop"; Risk="MEDIUM"}
            @{Name="NoMachine"; Pattern="NoMachine"; Risk="MEDIUM"}
            @{Name="Windows Remote Assistance"; Pattern="Remote Assistance"; Risk="MEDIUM"}
            @{Name="Apple Remote Desktop"; Pattern="Apple Remote Desktop|ARD"; Risk="MEDIUM"}
            @{Name="DameWare"; Pattern="DameWare"; Risk="MEDIUM"}
            @{Name="pcAnywhere"; Pattern="pcAnywhere"; Risk="MEDIUM"}
            @{Name="GoToAssist"; Pattern="GoToAssist"; Risk="MEDIUM"}
            @{Name="RemotePC"; Pattern="RemotePC"; Risk="MEDIUM"}
            @{Name="NinjaOne Remote"; Pattern="NinjaOne"; Risk="MEDIUM"}
            @{Name="Zoho Assist"; Pattern="Zoho Assist"; Risk="MEDIUM"}
            @{Name="LiteManager"; Pattern="LiteManager"; Risk="MEDIUM"}
        )
        
        $DetectedRemoteAccess = @()
        foreach ($RemoteApp in $RemoteAccessSoftware) {
            $Found = $AllSoftware | Where-Object { $_.DisplayName -match $RemoteApp.Pattern }
            foreach ($App in $Found) {
                $InstallDate = if ($App.InstallDate) { 
                    try { [datetime]::ParseExact($App.InstallDate, "yyyyMMdd", $null) } catch { $null }
                } else { $null }
                
                $DetectedRemoteAccess += [PSCustomObject]@{
                    Name = $RemoteApp.Name
                    DisplayName = $App.DisplayName
                    Version = $App.DisplayVersion
                    InstallDate = $InstallDate
                    Risk = $RemoteApp.Risk
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Software"
                    Item = "Remote Access Software"
                    Value = "$($App.DisplayName) - $($App.DisplayVersion)"
                    Details = "Remote access software detected. Install date: $(if ($InstallDate) { $InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }). Review business justification and security controls."
                    RiskLevel = $RemoteApp.Risk
                    Recommendation = "Document and secure remote access tools"
                }
            }
        }
        
        if ($DetectedRemoteAccess.Count -gt 0) {
            Write-LogMessage "WARN" "Remote access software detected: $(($DetectedRemoteAccess | Select-Object -ExpandProperty Name) -join ', ')" "SOFTWARE"
            
            # Add to raw data collection
            Add-RawDataCollection -CollectionName "RemoteAccessSoftware" -Data $DetectedRemoteAccess
        } else {
            Write-LogMessage "INFO" "No remote access software detected" "SOFTWARE"
        }
        
        # Check for RMM (Remote Monitoring and Management) software - investigation point
        $RMMSoftware = @(
            # ConnectWise Products
            @{Name="ConnectWise Automate"; Pattern="ConnectWise.*Automate|LabTech|LTService"; Risk="MEDIUM"}
            @{Name="ConnectWise Continuum"; Pattern="Continuum.*Agent|ConnectWise.*Continuum"; Risk="MEDIUM"}
            
            # Major RMM Platforms
            @{Name="NinjaOne RMM"; Pattern="NinjaOne|NinjaRMM|NinjaAgent"; Risk="MEDIUM"}
            @{Name="Kaseya VSA"; Pattern="Kaseya|AgentMon"; Risk="MEDIUM"}
            @{Name="Datto RMM"; Pattern="Datto.*RMM|CentraStage|Autotask"; Risk="MEDIUM"}
            @{Name="Atera"; Pattern="Atera.*Agent"; Risk="MEDIUM"}
            @{Name="Syncro"; Pattern="Syncro.*Agent|RepairShopr"; Risk="MEDIUM"}
            @{Name="Pulseway"; Pattern="Pulseway"; Risk="MEDIUM"}
            @{Name="N-able RMM"; Pattern="N-able|SolarWinds.*RMM|N-central"; Risk="MEDIUM"}
            @{Name="ManageEngine"; Pattern="ManageEngine|Desktop.*Central"; Risk="MEDIUM"}
            
            # Network Monitoring
            @{Name="Auvik"; Pattern="Auvik"; Risk="MEDIUM"}
            @{Name="PRTG"; Pattern="PRTG"; Risk="MEDIUM"}
            @{Name="WhatsUp Gold"; Pattern="WhatsUp.*Gold"; Risk="MEDIUM"}
            
            # Security/Endpoint Management
            @{Name="CrowdStrike"; Pattern="CrowdStrike|Falcon"; Risk="MEDIUM"}
            @{Name="SentinelOne"; Pattern="SentinelOne|Sentinel.*Agent"; Risk="MEDIUM"}
            @{Name="Huntress"; Pattern="Huntress"; Risk="MEDIUM"}
            @{Name="Bitdefender GravityZone"; Pattern="Bitdefender.*Gravity|GravityZone"; Risk="MEDIUM"}
            
            # Legacy/Other
            @{Name="LogMeIn Central"; Pattern="LogMeIn.*Central"; Risk="MEDIUM"}
            @{Name="GoToAssist Corporate"; Pattern="GoToAssist.*Corporate"; Risk="MEDIUM"}
            @{Name="Bomgar/BeyondTrust"; Pattern="Bomgar|BeyondTrust.*Remote"; Risk="MEDIUM"}
        )
        
        $DetectedRMM = @()
        foreach ($RMMApp in $RMMSoftware) {
            $Found = $AllSoftware | Where-Object { $_.DisplayName -match $RMMApp.Pattern }
            foreach ($App in $Found) {
                $InstallDate = if ($App.InstallDate) { 
                    try { [datetime]::ParseExact($App.InstallDate, "yyyyMMdd", $null) } catch { $null }
                } else { $null }
                
                $DetectedRMM += [PSCustomObject]@{
                    Name = $RMMApp.Name
                    DisplayName = $App.DisplayName
                    Version = $App.DisplayVersion
                    InstallDate = $InstallDate
                    Risk = $RMMApp.Risk
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Software"
                    Item = "RMM/Monitoring Software"
                    Value = "$($App.DisplayName) - $($App.DisplayVersion)"
                    Details = "RMM/monitoring software detected. Install date: $(if ($InstallDate) { $InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }). Review management authorization and security controls."
                    RiskLevel = $RMMApp.Risk
                    Recommendation = "Document and authorize remote monitoring tools"
                }
            }
        }
        
        if ($DetectedRMM.Count -gt 0) {
            Write-LogMessage "WARN" "RMM/monitoring software detected: $(($DetectedRMM | Select-Object -ExpandProperty Name) -join ', ')" "SOFTWARE"
            
            # Add to raw data collection
            Add-RawDataCollection -CollectionName "RMMSoftware" -Data $DetectedRMM
        } else {
            Write-LogMessage "INFO" "No RMM/monitoring software detected" "SOFTWARE"
        }
        
        # Add all software to raw data collection for detailed export
        $SoftwareList = @()
        foreach ($App in $AllSoftware) {
            $InstallDate = if ($App.InstallDate) { 
                try { [datetime]::ParseExact($App.InstallDate, "yyyyMMdd", $null) } catch { $null }
            } else { $null }
            
            $SoftwareList += [PSCustomObject]@{
                Name = $App.DisplayName
                Version = $App.DisplayVersion
                Publisher = $App.Publisher
                InstallDate = if ($InstallDate) { $InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }
                InstallLocation = $App.InstallLocation
                UninstallString = $App.UninstallString
                EstimatedSize = $App.EstimatedSize
            }
        }
        
        # Add to global raw data collection
        Add-RawDataCollection -CollectionName "InstalledSoftware" -Data $SoftwareList
        
        # Add a summary finding with software categories
        $Browsers = $AllSoftware | Where-Object { $_.DisplayName -match "Chrome|Firefox|Edge|Safari" }
        $DevTools = $AllSoftware | Where-Object { $_.DisplayName -match "Visual Studio|Git|Docker|Node" }
        $Office = $AllSoftware | Where-Object { $_.DisplayName -match "Office|Word|Excel|PowerPoint" }
        $Security = $AllSoftware | Where-Object { $_.DisplayName -match "Antivirus|McAfee|Norton|Symantec|Defender" }
        
        $Results += [PSCustomObject]@{
            Category = "Software"
            Item = "Software Categories"
            Value = "Full inventory available in raw data"
            Details = "Browsers: $($Browsers.Count), Dev Tools: $($DevTools.Count), Office: $($Office.Count), Security: $($Security.Count), Total: $($AllSoftware.Count)"
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        Write-LogMessage "SUCCESS" "Software inventory completed - $($AllSoftware.Count) programs found" "SOFTWARE"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to collect software inventory: $($_.Exception.Message)" "SOFTWARE"
        return @()
    }
}

# === src\modules\Get-SecuritySettings.ps1 ===
# WindowsWorkstationAuditor - Security Settings Analysis Module
# Version 1.3.0

function Get-SecuritySettings {
    <#
    .SYNOPSIS
        Analyzes critical Windows security settings and configurations
        
    .DESCRIPTION
        Performs comprehensive security settings analysis including:
        - Windows Defender antivirus status and configuration
        - Third-party antivirus detection via Security Center
        - Windows Firewall profile status (Domain, Private, Public)
        - User Account Control (UAC) configuration
        - Real-time protection and security service status
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Standard user rights for most checks, admin rights for comprehensive analysis
        Dependencies: Windows Defender, Security Center WMI classes
    #>
    
    Write-LogMessage "INFO" "Analyzing security settings..." "SECURITY"
    
    try {
        $Results = @()
        
        # Enhanced Antivirus Detection System
        $DetectedAV = @()
        $ActiveAV = @()
        
        # Function to decode Security Center product state
        function Get-AVProductState($ProductState) {
            # Product state is a complex bitmask
            # Based on research: https://bit.ly/3sKzQbU
            $State = @{
                Enabled = ($ProductState -band 0x1000) -ne 0
                UpToDate = ($ProductState -band 0x10) -eq 0
                RealTime = ($ProductState -band 0x100) -ne 0
                StateHex = "0x{0:X}" -f $ProductState
            }
            return $State
        }
        
        # Method 1: Windows Defender via PowerShell (most reliable for Defender)
        try {
            $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop
            $DefenderInfo = [PSCustomObject]@{
                Name = "Windows Defender"
                Enabled = $DefenderStatus.AntivirusEnabled
                RealTime = $DefenderStatus.RealTimeProtectionEnabled
                UpToDate = $DefenderStatus.AntivirusSignatureAge -lt 7
                LastUpdate = $DefenderStatus.AntivirusSignatureLastUpdated
                Method = "PowerShell API"
                ProductState = "N/A"
            }
            $DetectedAV += $DefenderInfo
            if ($DefenderInfo.Enabled) { $ActiveAV += $DefenderInfo }
            
            Write-LogMessage "INFO" "Windows Defender: Enabled=$($DefenderInfo.Enabled), RealTime=$($DefenderInfo.RealTime)" "SECURITY"
        }
        catch {
            Write-LogMessage "WARN" "Could not query Windows Defender via PowerShell: $($_.Exception.Message)" "SECURITY"
        }
        
        # Method 2: Security Center WMI (comprehensive for all AV products)
        $SecurityCenterAVs = @()
        try {
            $SecurityCenterAV = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
            
            # Group by displayName to handle duplicates
            $GroupedAV = $SecurityCenterAV | Group-Object displayName
            
            foreach ($AVGroup in $GroupedAV) {
                $AV = $AVGroup.Group[0]  # Take first instance of each unique product
                $State = Get-AVProductState -ProductState $AV.productState
                
                $AVInfo = [PSCustomObject]@{
                    Name = $AV.displayName
                    Enabled = $State.Enabled
                    RealTime = $State.RealTime
                    UpToDate = $State.UpToDate
                    ProductState = $State.StateHex
                    ExecutablePath = $AV.pathToSignedProductExe
                    Method = "Security Center"
                    InstanceGuid = $AV.instanceGuid
                    InstanceCount = $AVGroup.Count
                }
                
                $SecurityCenterAVs += $AVInfo
                
                # Avoid duplicate Defender entries
                if ($AV.displayName -notlike "*Windows Defender*" -or $DetectedAV.Count -eq 0) {
                    $DetectedAV += $AVInfo
                    if ($State.Enabled) { $ActiveAV += $AVInfo }
                }
            }
            
            # Log unique Security Center products only
            if ($SecurityCenterAVs.Count -gt 0) {
                Write-LogMessage "INFO" "Security Center detected $($SecurityCenterAVs.Count) unique AV products:" "SECURITY"
                foreach ($AV in $SecurityCenterAVs) {
                    $InstanceText = if ($AV.InstanceCount -gt 1) { " ($($AV.InstanceCount) instances)" } else { "" }
                    Write-LogMessage "INFO" "  - $($AV.Name): Enabled=$($AV.Enabled), State=$($AV.ProductState)$InstanceText" "SECURITY"
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not query Security Center WMI: $($_.Exception.Message)" "SECURITY"
        }
        
        # Method 3: Process detection as supplemental verification only
        # Only run if Security Center found limited results or to validate findings
        $RunProcessDetection = $SecurityCenterAVs.Count -eq 0 -or $SecurityCenterAVs.Count -eq 1
        
        if ($RunProcessDetection) {
            Write-LogMessage "INFO" "Running supplemental process-based AV detection..." "SECURITY"
            
            $AVProcessSignatures = @{
                # Enterprise EDR/AV Solutions
                "SentinelOne" = @("SentinelAgent", "SentinelRemediation", "SentinelCtl")
                "CrowdStrike" = @("CSAgent", "CSFalconService", "CSFalconContainer")
                "CarbonBlack" = @("cb", "CarbonBlack", "RepMgr", "RepUtils", "RepUx")
                "Cortex XDR" = @("cytool", "cyserver", "CyveraService")
                
                # Traditional AV Solutions  
                "McAfee" = @("mcshield", "mfemms", "mfevtps", "McCSPServiceHost", "masvc")
                "Symantec/Norton" = @("ccSvcHst", "NortonSecurity", "navapsvc", "rtvscan", "savroam")
                "Trend Micro" = @("tmbmsrv", "tmproxy", "tmlisten", "PccNTMon", "TmListen")
                "Kaspersky" = @("avp", "avpui", "klnagent", "ksde", "kavfs")
                "Bitdefender" = @("bdagent", "vsservppl", "vsserv", "updatesrv", "bdredline")
                "ESET" = @("epag", "epwd", "ekrn", "egui", "efsw")
                "Sophos" = @("SophosAgent", "savservice", "SophosFS", "SophosHealth")
                "F-Secure" = @("fsm32", "fsgk32", "fsav32", "fshoster", "FSMA")
                "Avast" = @("avastui", "avastsvc", "avastbrowser", "wsc_proxy")
                "AVG" = @("avguard", "avgui", "avgrsa", "avgfws", "avgcsrvx")
                "Webroot" = @("WRSA", "WRData", "WRCore", "WRConsumerService")
                "Malwarebytes" = @("mbamservice", "mbamtray", "MBAMProtector", "mbae64")
            }
            
            try {
                $RunningProcesses = Get-Process | Select-Object ProcessName
                $DetectedByProcess = @()
                
                foreach ($AVName in $AVProcessSignatures.Keys) {
                    $Processes = $AVProcessSignatures[$AVName]
                    $Found = $false
                    
                    foreach ($ProcessPattern in $Processes) {
                        if ($RunningProcesses | Where-Object { $_.ProcessName -like "*$ProcessPattern*" }) {
                            $Found = $true
                            break
                        }
                    }
                    
                    if ($Found) {
                        $DetectedByProcess += $AVName
                    }
                }
                
                if ($DetectedByProcess.Count -gt 0) {
                    Write-LogMessage "INFO" "Process verification found: $($DetectedByProcess -join ', ')" "SECURITY"
                    
                    # Report process-detected AV that wasn't found via Security Center
                    foreach ($ProcessAV in $DetectedByProcess) {
                        $AlreadyDetected = $DetectedAV | Where-Object { $_.Name -like "*$ProcessAV*" }
                        if (-not $AlreadyDetected) {
                            $Results += [PSCustomObject]@{
                                Category = "Security"
                                Item = "Antivirus Process Detected"
                                Value = "$ProcessAV - Process Running"
                                Details = "AV processes detected but not registered with Security Center. May indicate configuration issue or secondary AV installation."
                                RiskLevel = "MEDIUM"
                                Recommendation = "Verify antivirus registration and avoid conflicting AV products"
                            }
                            
                            Write-LogMessage "WARN" "AV process detected but not in Security Center: $ProcessAV" "SECURITY"
                        }
                    }
                } else {
                    Write-LogMessage "INFO" "Process verification: No additional AV products found" "SECURITY"
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not run process verification: $($_.Exception.Message)" "SECURITY"
            }
        } else {
            Write-LogMessage "INFO" "Skipping process detection - Security Center found sufficient AV products ($($SecurityCenterAVs.Count))" "SECURITY"
        }
        
        # Generate consolidated results with enhanced multiple AV reporting
        if ($DetectedAV.Count -gt 0) {
            # Group by product name to handle multiple instances cleanly
            $GroupedDetectedAV = $DetectedAV | Group-Object Name
            
            foreach ($AVGroup in $GroupedDetectedAV) {
                $AV = $AVGroup.Group[0]  # Take primary instance for display
                $InstanceCount = $AVGroup.Count
                
                $StatusText = if ($AV.Enabled) { "Active" } else { "Installed but Inactive" }
                $UpdateStatus = if ($AV.UpToDate) { "Up to date" } else { "Outdated signatures" }
                
                $Details = "Status: $StatusText"
                if ($AV.RealTime -ne $null) { $Details += ", Real-time: $($AV.RealTime)" }
                if ($AV.UpToDate -ne $null) { $Details += ", $UpdateStatus" }
                if ($AV.LastUpdate) { $Details += ", Last update: $($AV.LastUpdate)" }
                if ($AV.ProductState -ne "N/A") { $Details += " (State: $($AV.ProductState))" }
                if ($InstanceCount -gt 1) { $Details += ", Multiple instances detected: $InstanceCount" }
                
                $RiskLevel = "LOW"
                $Recommendation = ""
                
                if (-not $AV.Enabled) {
                    # Check if this is Windows Defender and other AV products are active
                    if ($AV.Name -match "Windows Defender" -and $ActiveAV.Count -gt 0) {
                        $RiskLevel = "LOW" 
                        $Recommendation = "Windows Defender properly disabled - other active AV products detected"
                    } else {
                        $RiskLevel = "HIGH"
                        $Recommendation = "Antivirus must be enabled and active"
                    }
                } elseif ($AV.UpToDate -eq $false) {
                    $RiskLevel = "MEDIUM"
                    $Recommendation = "Antivirus signatures must be current"
                } elseif ($InstanceCount -gt 1) {
                    $RiskLevel = "MEDIUM"
                    $Recommendation = "Multiple instances may indicate conflicting installations"
                }
                
                $DisplayName = if ($InstanceCount -gt 1) { "$($AV.Name) (x$InstanceCount)" } else { $AV.Name }
                
                $Results += [PSCustomObject]@{
                    Category = "Security"
                    Item = "Antivirus Product"
                    Value = "$DisplayName - $StatusText"
                    Details = $Details
                    RiskLevel = $RiskLevel
                    Recommendation = ""
                }
            }
            
            # Enhanced summary with multiple product analysis
            $UniqueActiveProducts = ($ActiveAV | Group-Object Name).Count
            $UniqueDetectedProducts = $GroupedDetectedAV.Count
            $TotalInstances = $DetectedAV.Count
            
            $ActiveProductNames = ($ActiveAV | Group-Object Name | Select-Object -ExpandProperty Name) -join ', '
            $AllProductNames = ($GroupedDetectedAV | Select-Object -ExpandProperty Name) -join ', '
            
            $SummaryDetails = "Active products: $ActiveProductNames"
            if ($TotalInstances -gt $UniqueDetectedProducts) {
                $SummaryDetails += ". Multiple instances detected ($TotalInstances total installations of $UniqueDetectedProducts products)"
            }
            
            $SummaryRisk = "LOW"
            $SummaryRecommendation = ""
            
            if ($UniqueActiveProducts -eq 0) {
                $SummaryRisk = "HIGH"
                $SummaryRecommendation = "No active antivirus protection"
            } elseif ($UniqueActiveProducts -gt 1) {
                $SummaryRisk = "MEDIUM"
                $SummaryRecommendation = "Multiple active AV products may cause conflicts - review configuration"
            } elseif ($TotalInstances -gt $UniqueDetectedProducts) {
                $SummaryRisk = "MEDIUM"
                $SummaryRecommendation = "Multiple instances of same products detected - review for cleanup"
            }
            
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Antivirus Protection Summary"
                Value = "$UniqueActiveProducts active of $UniqueDetectedProducts products"
                Details = $SummaryDetails
                RiskLevel = $SummaryRisk
                Recommendation = ""
            }
            
            Write-LogMessage "SUCCESS" "Enhanced AV detection: $UniqueActiveProducts unique active products, $UniqueDetectedProducts total products, $TotalInstances instances" "SECURITY"
        } else {
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Antivirus Protection"
                Value = "None detected"
                Details = "No antivirus software detected via Security Center, Defender API, or process analysis"
                RiskLevel = "HIGH"
                Recommendation = "Antivirus protection required"
            }
            
            Write-LogMessage "ERROR" "No antivirus protection detected by enhanced detection methods" "SECURITY"
        }
        
        # Add detected AV products to raw data collection
        Add-RawDataCollection -CollectionName "AntivirusProducts" -Data $DetectedAV
        
        # Windows Firewall Status
        $FirewallProfiles = Get-NetFirewallProfile
        foreach ($Profile in $FirewallProfiles) {
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Firewall - $($Profile.Name)"
                Value = if ($Profile.Enabled) { "Enabled" } else { "Disabled" }
                Details = "Default action: Inbound=$($Profile.DefaultInboundAction), Outbound=$($Profile.DefaultOutboundAction)"
                RiskLevel = if ($Profile.Enabled) { "LOW" } else { "HIGH" }
                Recommendation = if (-not $Profile.Enabled) { "Enable firewall protection" } else { "" }
            }
        }
        
        # UAC Status
        $UACKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
        $Results += [PSCustomObject]@{
            Category = "Security"
            Item = "User Account Control (UAC)"
            Value = if ($UACKey.EnableLUA) { "Enabled" } else { "Disabled" }
            Details = "UAC elevation prompts"
            RiskLevel = if ($UACKey.EnableLUA) { "LOW" } else { "HIGH" }
            Recommendation = if (-not $UACKey.EnableLUA) { "Enable UAC for privilege escalation control" } else { "" }
        }
        
        # BitLocker Encryption Analysis
        try {
            Write-LogMessage "INFO" "Analyzing BitLocker encryption status..." "SECURITY"
            
            # Check if BitLocker is available
            $BitLockerFeature = Get-WindowsOptionalFeature -Online -FeatureName "BitLocker" -ErrorAction SilentlyContinue
            if ($BitLockerFeature -and $BitLockerFeature.State -eq "Enabled") {
                
                # Get all BitLocker volumes
                $BitLockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
                if ($BitLockerVolumes) {
                    $EncryptedVolumes = @()
                    $UnencryptedVolumes = @()
                    
                    foreach ($Volume in $BitLockerVolumes) {
                        $VolumeInfo = @{
                            MountPoint = $Volume.MountPoint
                            EncryptionPercentage = $Volume.EncryptionPercentage
                            VolumeStatus = $Volume.VolumeStatus
                            ProtectionStatus = $Volume.ProtectionStatus
                            EncryptionMethod = $Volume.EncryptionMethod
                            KeyProtectors = $Volume.KeyProtector
                        }
                        
                        if ($Volume.VolumeStatus -eq "FullyEncrypted") {
                            $EncryptedVolumes += $VolumeInfo
                        } else {
                            $UnencryptedVolumes += $VolumeInfo
                        }
                        
                        # Analyze key protectors and escrow status
                        $KeyProtectorDetails = @()
                        $RecoveryKeyEscrowed = $false
                        $EscrowLocation = "None"
                        
                        foreach ($Protector in $Volume.KeyProtector) {
                            $KeyProtectorDetails += "$($Protector.KeyProtectorType)"
                            
                            # Check for recovery password protector
                            if ($Protector.KeyProtectorType -eq "RecoveryPassword") {
                                # Try to determine escrow status via manage-bde
                                try {
                                    $MbdeOutput = & manage-bde -protectors -get $Volume.MountPoint 2>$null
                                    if ($LASTEXITCODE -eq 0) {
                                        # Check for Azure AD or AD escrow indicators
                                        if ($MbdeOutput -match "Backed up to Azure Active Directory|Backed up to Microsoft Entra") {
                                            $RecoveryKeyEscrowed = $true
                                            $EscrowLocation = "Azure AD"
                                        }
                                        elseif ($MbdeOutput -match "Backed up to Active Directory") {
                                            $RecoveryKeyEscrowed = $true
                                            $EscrowLocation = "Active Directory"
                                        }
                                    }
                                }
                                catch {
                                    Write-LogMessage "WARN" "Could not determine recovery key escrow status for volume $($Volume.MountPoint)" "SECURITY"
                                }
                            }
                        }
                        
                        # Report individual volume status
                        $VolumeRisk = switch ($Volume.VolumeStatus) {
                            "FullyEncrypted" { "LOW" }
                            "EncryptionInProgress" { "MEDIUM" }
                            "DecryptionInProgress" { "HIGH" }
                            "FullyDecrypted" { "HIGH" }
                            default { "HIGH" }
                        }
                        
                        $VolumeRecommendation = switch ($Volume.VolumeStatus) {
                            "FullyDecrypted" { "Enable BitLocker encryption for data protection" }
                            "DecryptionInProgress" { "Complete BitLocker decryption or re-enable encryption" }
                            "EncryptionInProgress" { "Allow BitLocker encryption to complete" }
                            default { "" }
                        }
                        
                        # Add recovery key escrow compliance
                        if ($Volume.VolumeStatus -eq "FullyEncrypted" -and -not $RecoveryKeyEscrowed) {
                            $VolumeRecommendation = "Backup BitLocker recovery key to Azure AD or Active Directory"
                            $VolumeRisk = "MEDIUM"
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Security"
                            Item = "BitLocker Volume"
                            Value = "$($Volume.MountPoint) - $($Volume.VolumeStatus)"
                            Details = "Encryption: $($Volume.EncryptionPercentage)%, Protection: $($Volume.ProtectionStatus), Method: $($Volume.EncryptionMethod), Key Escrow: $EscrowLocation"
                            RiskLevel = $VolumeRisk
                            Recommendation = ""
                        }
                        
                        Write-LogMessage "INFO" "BitLocker volume $($Volume.MountPoint): $($Volume.VolumeStatus), Escrow: $EscrowLocation" "SECURITY"
                    }
                    
                    # Summary report
                    $TotalVolumes = $BitLockerVolumes.Count
                    $EncryptedCount = $EncryptedVolumes.Count
                    $Results += [PSCustomObject]@{
                        Category = "Security"
                        Item = "BitLocker Encryption Summary"
                        Value = "$EncryptedCount of $TotalVolumes volumes encrypted"
                        Details = "BitLocker disk encryption status across all volumes"
                        RiskLevel = if ($EncryptedCount -eq $TotalVolumes) { "LOW" } elseif ($EncryptedCount -gt 0) { "MEDIUM" } else { "HIGH" }
                        Recommendation = if ($EncryptedCount -lt $TotalVolumes) { "Encrypt all system and data volumes with BitLocker" } else { "" }
                    }
                    
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Security"
                        Item = "BitLocker Encryption"
                        Value = "No volumes detected"
                        Details = "Unable to retrieve BitLocker volume information"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Verify BitLocker configuration and permissions"
                    }
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Security"
                    Item = "BitLocker Encryption"
                    Value = "Not Available"
                    Details = "BitLocker feature not enabled or not supported"
                    RiskLevel = "HIGH"
                    Recommendation = "Enable BitLocker feature for disk encryption"
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not analyze BitLocker encryption: $($_.Exception.Message)" "SECURITY"
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "BitLocker Encryption"
                Value = "Analysis Failed"
                Details = "Unable to analyze BitLocker status - may require elevated privileges"
                RiskLevel = "MEDIUM"
                Recommendation = "Manual verification required"
            }
        }
        
        Write-LogMessage "SUCCESS" "Security settings analysis completed" "SECURITY"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze security settings: $($_.Exception.Message)" "SECURITY"
        return @()
    }
}

# === src\modules\Get-PatchStatus.ps1 ===
# WindowsWorkstationAuditor - Patch Status Analysis Module
# Version 1.3.0

function Get-PatchStatus {
    <#
    .SYNOPSIS
        Analyzes Windows patch status with InProgress update detection
        
    .DESCRIPTION
        Performs comprehensive patch management analysis including:
        - Available Windows updates scanning via PSWindowsUpdate module
        - InProgress update detection (downloaded but requiring reboot)
        - Critical security update identification
        - System uptime analysis for restart requirements
        - Windows Update service configuration verification
        - Automatic update policy assessment
        - Recent hotfix installation history
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function, PSWindowsUpdate module (auto-installed)
        Permissions: Local admin rights for complete patch analysis
        Dependencies: Windows Update service, PSWindowsUpdate PowerShell module
    #>
    
    Write-LogMessage "INFO" "Analyzing patch status with InProgress detection..." "PATCHES"
    
    try {
        $Results = @()
        
        # Install PSWindowsUpdate if needed - handle NuGet prompts automatically
        $PSWUAvailable = $false
        try {
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Write-LogMessage "INFO" "Installing PSWindowsUpdate module..." "PATCHES"
                Set-ExecutionPolicy RemoteSigned -Scope Process -Force
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                
                # Install NuGet provider automatically to avoid prompts  
                # Use AllUsers scope if running as SYSTEM, CurrentUser otherwise
                $InstallScope = if ($env:USERNAME -eq "SYSTEM") { "AllUsers" } else { "CurrentUser" }
                Write-LogMessage "INFO" "Installing NuGet and PSWindowsUpdate with scope: $InstallScope" "PATCHES"
                
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope $InstallScope
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                
                Install-Module PSWindowsUpdate -Force -Scope $InstallScope -SkipPublisherCheck
            }
            Import-Module PSWindowsUpdate -Force
            $PSWUAvailable = $true
            Write-LogMessage "SUCCESS" "PSWindowsUpdate module available" "PATCHES"
        }
        catch {
            Write-LogMessage "ERROR" "PSWindowsUpdate installation failed: $($_.Exception.Message)" "PATCHES"
        }
        
        if ($PSWUAvailable) {
            try {
                # Check for new available updates
                Write-LogMessage "INFO" "Scanning for available updates..." "PATCHES"
                $AvailableUpdates = @(Get-WindowsUpdate -MicrosoftUpdate -Verbose:$false -ErrorAction SilentlyContinue)
                Write-LogMessage "INFO" "Available updates to install: $($AvailableUpdates.Count)" "PATCHES"
                
                # Check update history for InProgress updates (downloaded but need reboot)
                Write-LogMessage "INFO" "Checking update history for InProgress updates..." "PATCHES"
                $UpdateHistory = Get-WUHistory -Last 30 -ErrorAction SilentlyContinue
                $InProgressUpdates = @($UpdateHistory | Where-Object { 
                    $_.Result -eq "InProgress" -and $_.Date -gt (Get-Date).AddDays(-30)
                })
                
                Write-LogMessage "INFO" "InProgress updates found: $($InProgressUpdates.Count)" "PATCHES"
                
                # Log the specific InProgress updates
                if ($InProgressUpdates.Count -gt 0) {
                    Write-LogMessage "WARN" "UPDATES REQUIRING REBOOT DETECTED:" "PATCHES"
                    foreach ($Update in $InProgressUpdates) {
                        Write-LogMessage "WARN" "  - NEEDS REBOOT: $($Update.Title)" "PATCHES"
                    }
                }
                
                # Analyze InProgress updates for criticality
                $CriticalInProgress = @($InProgressUpdates | Where-Object { 
                    $_.Title -match "Cumulative Update|Critical|Security Update"
                })
                
                # Check reboot status
                $RebootRequired = $false
                try {
                    $SystemInfo = New-Object -ComObject Microsoft.Update.SystemInfo
                    $RebootRequired = $SystemInfo.RebootRequired
                    Write-LogMessage "INFO" "System reboot required: $RebootRequired" "PATCHES"
                }
                catch {
                    $RebootRequired = $InProgressUpdates.Count -gt 0
                    Write-LogMessage "INFO" "Reboot required based on InProgress updates: $RebootRequired" "PATCHES"
                }
                
                # Main patch status report
                $TotalPending = $AvailableUpdates.Count + $InProgressUpdates.Count
                $StatusDetails = "Available: $($AvailableUpdates.Count), Downloaded/Pending Reboot: $($InProgressUpdates.Count)"
                
                $Results += [PSCustomObject]@{
                    Category = "Patches"
                    Item = "Update Status"
                    Value = "$TotalPending total"
                    Details = $StatusDetails
                    RiskLevel = if ($CriticalInProgress.Count -gt 0) { "HIGH" } elseif ($InProgressUpdates.Count -gt 0) { "HIGH" } elseif ($AvailableUpdates.Count -gt 0) { "MEDIUM" } else { "LOW" }
                    Recommendation = if ($CriticalInProgress.Count -gt 0) { "CRITICAL: Restart required for critical updates" } elseif ($InProgressUpdates.Count -gt 0) { "Restart required to complete updates" } else { "" }
                }
                
                # Critical updates requiring reboot
                if ($CriticalInProgress.Count -gt 0) {
                    $CriticalTitles = ($CriticalInProgress | Select-Object -First 2).Title -join "; "
                    $Results += [PSCustomObject]@{
                        Category = "Patches"
                        Item = "Critical Updates Awaiting Reboot"
                        Value = $CriticalInProgress.Count
                        Details = $CriticalTitles
                        RiskLevel = "HIGH"
                        Recommendation = "IMMEDIATE: Restart to complete critical security updates"
                    }
                }
                
                # Reboot required alert
                if ($RebootRequired -or $InProgressUpdates.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Patches"
                        Item = "Reboot Required"
                        Value = "Yes"
                        Details = "System restart needed to complete $($InProgressUpdates.Count) updates"
                        RiskLevel = "HIGH"
                        Recommendation = "Restart system to complete update installation"
                    }
                }
                
                # Available updates (not yet downloaded)
                if ($AvailableUpdates.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Patches"
                        Item = "Available Updates"
                        Value = "$($AvailableUpdates.Count) updates"
                        Details = "Updates available for download and installation"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Install available updates within 30 days"
                    }
                }
                
                Write-LogMessage "SUCCESS" "Patch analysis complete - Available: $($AvailableUpdates.Count), InProgress: $($InProgressUpdates.Count), Critical InProgress: $($CriticalInProgress.Count)" "PATCHES"
                
            }
            catch {
                Write-LogMessage "ERROR" "PSWindowsUpdate patch analysis failed: $($_.Exception.Message)" "PATCHES"
            }
        } else {
            # Simple fallback when PSWindowsUpdate fails
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Update Status"
                Value = "Module Failed"
                Details = "PSWindowsUpdate module could not be loaded - manual verification required"
                RiskLevel = "MEDIUM"
                Recommendation = "Manually verify patch status"
            }
        }
        
        # Get recent hotfixes (last 90 days)
        try {
            $RecentDate = (Get-Date).AddDays(-90)
            $RecentHotfixes = Get-HotFix | Where-Object { 
                $_.InstalledOn -and $_.InstalledOn -gt $RecentDate 
            } | Measure-Object
            
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Recent Patches (90 days)"
                Value = $RecentHotfixes.Count
                Details = "Hotfixes installed in last 90 days"
                RiskLevel = if ($RecentHotfixes.Count -eq 0) { "HIGH" } elseif ($RecentHotfixes.Count -lt 5) { "MEDIUM" } else { "LOW" }
                Recommendation = if ($RecentHotfixes.Count -eq 0) { "No recent patches detected - verify update process" } else { "" }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve recent hotfix information: $($_.Exception.Message)" "PATCHES"
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Recent Patches (90 days)"
                Value = "Unknown"
                Details = "Could not retrieve hotfix history"
                RiskLevel = "MEDIUM"
                Recommendation = "Verify patch installation history"
            }
        }
        
        # Get last boot time (indicates recent patching activity)
        try {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem
            $LastBootTime = $OS.LastBootUpTime
            $UptimeDays = [math]::Round((New-TimeSpan -Start $LastBootTime -End (Get-Date)).TotalDays, 1)
            
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "System Uptime"
                Value = "$UptimeDays days"
                Details = "Last boot: $($LastBootTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                RiskLevel = if ($UptimeDays -gt 30) { "MEDIUM" } elseif ($UptimeDays -gt 60) { "HIGH" } else { "LOW" }
                Recommendation = if ($UptimeDays -gt 30) { "Consider regular restarts for patch application" } else { "" }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve system uptime: $($_.Exception.Message)" "PATCHES"
        }
        
        # Windows Update service status
        try {
            $UpdateService = Get-Service -Name "wuauserv" -ErrorAction Stop
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Windows Update Service"
                Value = $UpdateService.Status
                Details = "Service startup type: $($UpdateService.StartType)"
                RiskLevel = if ($UpdateService.Status -eq "Running") { "LOW" } elseif ($UpdateService.Status -eq "Stopped" -and $UpdateService.StartType -eq "Manual") { "LOW" } else { "HIGH" }
                Recommendation = if ($UpdateService.Status -ne "Running" -and $UpdateService.StartType -eq "Disabled") { "Windows Update service should not be permanently disabled" } else { "" }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check Windows Update service status: $($_.Exception.Message)" "PATCHES"
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Windows Update Service"
                Value = "Unknown"
                Details = "Could not retrieve service status"
                RiskLevel = "MEDIUM"
                Recommendation = "Verify Windows Update service configuration"
            }
        }
        
        # Comprehensive Windows Update configuration detection (effective settings)
        try {
            Write-LogMessage "INFO" "Detecting effective Windows Update configuration..." "PATCHES"
            
            # Check for WSUS configuration (Group Policy takes precedence)
            $WSUSServerGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
            $UseWSUSGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction SilentlyContinue
            $NoInternetGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue
            $AUOptionsGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
            $NoAutoUpdateGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
            
            # Check for SCCM/ConfigMgr client
            $SCCMClient = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client" -ErrorAction SilentlyContinue
            $SCCMVersion = if ($SCCMClient -and $SCCMClient.SmsClientVersion) { $SCCMClient.SmsClientVersion } else { $null }
            
            # Check for Windows Update for Business (WUfB/Intune)
            $WUfBPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\Current\Device\Update" -ErrorAction SilentlyContinue
            
            # Determine effective configuration (in order of precedence)
            $UpdateConfig = ""
            $UpdateDetails = ""
            $RiskLevel = "INFO"
            $Recommendation = ""
            
            # 1. SCCM/ConfigMgr (highest precedence for enterprise)
            if ($SCCMClient) {
                $UpdateConfig = "SCCM/ConfigMgr Managed"
                $UpdateDetails = "ConfigMgr client detected"
                if ($SCCMVersion) { $UpdateDetails += " (version: $SCCMVersion)" }
                $RiskLevel = "LOW"
                Write-LogMessage "SUCCESS" "SCCM ConfigMgr client detected: $SCCMVersion" "PATCHES"
            }
            
            # 2. WSUS Configuration (Group Policy managed)
            elseif ($WSUSServerGP -and $WSUSServerGP.WUServer -and $UseWSUSGP -and $UseWSUSGP.UseWUServer -eq 1) {
                $UpdateConfig = "WSUS Server"
                $UpdateDetails = "WSUS Server: $($WSUSServerGP.WUServer)"
                if ($NoInternetGP -and $NoInternetGP.DoNotConnectToWindowsUpdateInternetLocations -eq 1) {
                    $UpdateDetails += " (Internet blocked)"
                }
                $RiskLevel = "LOW"
                Write-LogMessage "SUCCESS" "WSUS configuration detected: $($WSUSServerGP.WUServer)" "PATCHES"
            }
            
            # 3. Windows Update for Business (WUfB/Intune)
            elseif ($WUfBPolicy) {
                $UpdateConfig = "Windows Update for Business"
                $UpdateDetails = "Managed by Intune/WUfB policies"
                $RiskLevel = "LOW"
                Write-LogMessage "SUCCESS" "Windows Update for Business detected" "PATCHES"
            }
            
            # 4. Group Policy Automatic Updates (without WSUS)
            elseif ($AUOptionsGP -or $NoAutoUpdateGP) {
                if ($NoAutoUpdateGP -and $NoAutoUpdateGP.NoAutoUpdate -eq 1) {
                    $UpdateConfig = "Automatic Updates Disabled"
                    $UpdateDetails = "Disabled by Group Policy (NoAutoUpdate=1)"
                    $RiskLevel = "HIGH"
                    $Recommendation = "Automatic updates should be enabled or managed by WSUS/SCCM"
                } elseif ($AUOptionsGP -and $AUOptionsGP.AUOptions) {
                    $AUValue = $AUOptionsGP.AUOptions
                    $UpdateConfig = switch ($AUValue) {
                        2 { "Notify before downloading" }
                        3 { "Download but notify before installing" }
                        4 { "Install automatically" }
                        5 { "Allow users to choose setting" }
                        default { "Custom configuration (AUOptions: $AUValue)" }
                    }
                    $UpdateDetails = "Group Policy managed (AUOptions: $AUValue)"
                    $RiskLevel = if ($AUValue -in @(3,4)) { "LOW" } elseif ($AUValue -eq 2) { "MEDIUM" } else { "HIGH" }
                }
                Write-LogMessage "SUCCESS" "Group Policy automatic updates: AUOptions=$($AUOptionsGP.AUOptions)" "PATCHES"
            }
            
            # 5. Local Registry Configuration
            else {
                $LocalAUConfig = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue
                if ($LocalAUConfig -and $LocalAUConfig.AUOptions) {
                    $AUValue = $LocalAUConfig.AUOptions
                    $UpdateConfig = switch ($AUValue) {
                        1 { "Automatic updates disabled" }
                        2 { "Notify before downloading" }
                        3 { "Download but notify before installing" }
                        4 { "Install automatically" }
                        5 { "Allow users to choose setting" }
                        default { "Custom configuration (AUOptions: $AUValue)" }
                    }
                    $UpdateDetails = "Local registry setting (AUOptions: $AUValue)"
                    $RiskLevel = if ($AUValue -in @(3,4)) { "LOW" } elseif ($AUValue -eq 2) { "MEDIUM" } else { "HIGH" }
                    Write-LogMessage "SUCCESS" "Local automatic updates: AUOptions=$AUValue" "PATCHES"
                } else {
                    # No explicit configuration found - Windows default behavior
                    $UpdateConfig = "Windows Default Behavior"
                    $UpdateDetails = "No explicit update configuration detected - using Windows default automatic update behavior"
                    $RiskLevel = "MEDIUM"
                    $Recommendation = "Consider implementing managed Windows Update strategy (WSUS, SCCM, or WUfB)"
                    Write-LogMessage "WARN" "No Windows Update configuration detected" "PATCHES"
                }
            }
            
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Windows Update Configuration"
                Value = $UpdateConfig
                Details = $UpdateDetails
                RiskLevel = $RiskLevel
                Recommendation = ""
            }
        }
        catch {
            Write-LogMessage "ERROR" "Failed to detect Windows Update configuration: $($_.Exception.Message)" "PATCHES"
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Windows Update Configuration"
                Value = "Detection Failed"
                Details = "Error detecting update configuration: $($_.Exception.Message)"
                RiskLevel = "ERROR"
                Recommendation = "Investigate Windows Update configuration detection issue"
            }
        }
        
        Write-LogMessage "SUCCESS" "Patch status analysis completed" "PATCHES"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze patch status: $($_.Exception.Message)" "PATCHES"
        return @()
    }
}

# === src\modules\Get-PolicyAnalysis.ps1 ===
# WindowsWorkstationAuditor - Policy Analysis Module
# Version 1.3.0

function Get-PolicyAnalysis {
    <#
    .SYNOPSIS
        Analyzes security policies, Group Policy, and audit configurations
        
    .DESCRIPTION
        Performs comprehensive policy analysis including:
        - Group Policy Object (GPO) detection and enumeration
        - Local security policy analysis via secedit export
        - Password policy configuration (length, complexity, history)
        - Account lockout policy settings
        - Screen lock/screen saver policy verification
        - Audit policy configuration for security logging
        - User rights assignment analysis for privilege escalation risks
        - Windows Defender policy restrictions
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Admin rights for comprehensive policy analysis
        Dependencies: secedit.exe, auditpol.exe, gpresult.exe
        Coverage: Local policies, Group Policy, audit settings
    #>
    
    Write-LogMessage "INFO" "Analyzing security policies and settings..." "POLICY"
    
    try {
        $Results = @()
        
        # Policy Management Detection - distinguish between Group Policy, MDM, and Local Security Policy
        Write-LogMessage "INFO" "Checking Group Policy configuration..." "POLICY"
        
        # 1. Check for traditional Group Policy (domain-joined)
        try {
            $GPResult = & gpresult /r /scope:computer 2>$null
            if ($LASTEXITCODE -eq 0) {
                # Parse GP result for applied policies
                $AppliedGPOs = @()
                $InGPOSection = $false
                $IsLocalPolicyOnly = $true
                
                foreach ($Line in $GPResult) {
                    if ($Line -match "Applied Group Policy Objects") {
                        $InGPOSection = $true
                        continue
                    }
                    if ($Line -match "The following GPOs were not applied" -or $Line -match "The computer is a part of the following security groups") {
                        $InGPOSection = $false
                        continue
                    }
                    if ($InGPOSection -and $Line.Trim() -ne "" -and $Line -notmatch "^-+$" -and $Line -notmatch "^\s*$") {
                        $CleanedGPOName = $Line.Trim()
                        if ($CleanedGPOName -notmatch "^-+$" -and $CleanedGPOName -ne "Applied Group Policy Objects") {
                            $AppliedGPOs += $CleanedGPOName
                            # Check if it's real Group Policy or just Local Security Policy
                            if ($CleanedGPOName -ne "Local Group Policy") {
                                $IsLocalPolicyOnly = $false
                            }
                            Write-LogMessage "INFO" "Found policy: $CleanedGPOName" "POLICY"
                        }
                    }
                }
                
                # Categorize the results properly
                if ($AppliedGPOs.Count -gt 0 -and -not $IsLocalPolicyOnly) {
                    # Real Group Policy Objects found
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "Domain Group Policy"
                        Value = "$($AppliedGPOs.Count) GPOs Applied"
                        Details = "Traditional Active Directory Group Policy Objects"
                        RiskLevel = "LOW"
                        Recommendation = ""
                    }
                    
                    foreach ($GPO in $AppliedGPOs) {
                        if ($GPO -and $GPO.Trim() -ne "" -and $GPO -ne "Local Group Policy") {
                            $Results += [PSCustomObject]@{
                                Category = "Policy"
                                Item = "Domain GPO"
                                Value = $GPO
                                Details = "Active Directory Group Policy Object"
                                RiskLevel = "INFO"
                                Recommendation = ""
                            }
                        }
                    }
                } else {
                    # No real GPOs - expected for Azure AD joined devices
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "Domain Group Policy"
                        Value = "Not Applied"
                        Details = "No traditional AD Group Policy Objects (normal for Azure AD joined devices)"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check Group Policy status: $($_.Exception.Message)" "POLICY"
        }
        
        # 2. Check for MDM/Intune Policy (for Azure AD joined devices)
        try {
            # Check MDM enrollment status
            $MDMEnrolled = $false
            $MDMDetails = "Not enrolled"
            $AppliedPolicies = @()
            
            # Check registry for MDM enrollment
            $MDMKey = "HKLM:\SOFTWARE\Microsoft\Enrollments"
            if (Test-Path $MDMKey) {
                $Enrollments = Get-ChildItem $MDMKey -ErrorAction SilentlyContinue
                foreach ($Enrollment in $Enrollments) {
                    $EnrollmentInfo = Get-ItemProperty $Enrollment.PSPath -ErrorAction SilentlyContinue
                    if ($EnrollmentInfo -and ($EnrollmentInfo.ProviderID -eq "MS DM Server" -or $EnrollmentInfo.EnrollmentType -eq 6)) {
                        $MDMEnrolled = $true
                        $MDMDetails = "Enrolled via Microsoft Intune/MDM"
                        Write-LogMessage "INFO" "MDM enrollment detected: $($EnrollmentInfo.ProviderID)" "POLICY"
                        break
                    }
                }
            }
            
            # If MDM enrolled, try to detect applied policies
            if ($MDMEnrolled) {
                # Method 1: Check PolicyManager registry for applied policies (correct path)
                $PolicyManagerKey = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device"
                if (Test-Path $PolicyManagerKey) {
                    $PolicyCategories = Get-ChildItem $PolicyManagerKey -ErrorAction SilentlyContinue
                    foreach ($Category in $PolicyCategories) {
                        if ($Category.Name -notmatch "Status|Reporting") {
                            $CategoryName = $Category.PSChildName
                            $PolicyValues = Get-ItemProperty $Category.PSPath -ErrorAction SilentlyContinue
                            if ($PolicyValues) {
                                $ValueCount = ($PolicyValues.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Count
                                if ($ValueCount -gt 0) {
                                    $AppliedPolicies += "$CategoryName ($ValueCount settings)"
                                }
                            }
                        }
                    }
                    Write-LogMessage "INFO" "MDM applied policies detected: $($AppliedPolicies.Count) categories" "POLICY"
                }
                
                # Method 1b: Check specific common Intune CSPs
                $CommonCSPs = @(
                    @{Name = "DeviceLock"; Description = "Device lock and password policies"},
                    @{Name = "Bitlocker"; Description = "BitLocker encryption policies"},
                    @{Name = "Update"; Description = "Windows Update policies"},
                    @{Name = "Firewall"; Description = "Windows Firewall policies"},
                    @{Name = "ApplicationControl"; Description = "Application control policies"},
                    @{Name = "VPNv2"; Description = "VPN configuration policies"},
                    @{Name = "WiFi"; Description = "WiFi configuration policies"}
                )
                
                $CSPDetailsMap = @{}
                foreach ($CSP in $CommonCSPs) {
                    $CSPKey = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\$($CSP.Name)"
                    if (Test-Path $CSPKey) {
                        $CSPSettings = Get-ItemProperty $CSPKey -ErrorAction SilentlyContinue
                        if ($CSPSettings) {
                            $SettingNames = ($CSPSettings.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Name
                            if ($SettingNames.Count -gt 0) {
                                $AppliedPolicies += "$($CSP.Name) ($($SettingNames.Count) settings)"
                                
                                # Filter out technical metadata and capture meaningful settings
                                $FilteredSettingNames = $SettingNames | Where-Object { 
                                    $_ -notmatch "_ProviderSet$|_WinningProvider$|_LastWrite$|_Version$" 
                                }
                                
                                $SettingDetails = @()
                                foreach ($SettingName in ($FilteredSettingNames | Select-Object -First 8)) {
                                    $SettingValue = $CSPSettings.$SettingName
                                    if ($SettingValue -ne $null -and $SettingValue -ne "") {
                                        # Format boolean values more clearly
                                        if ($SettingValue -eq "1") {
                                            $SettingDetails += "$SettingName=Enabled"
                                        } elseif ($SettingValue -eq "0") {
                                            $SettingDetails += "$SettingName=Disabled"
                                        } else {
                                            $SettingDetails += "$SettingName=$SettingValue"
                                        }
                                    } else {
                                        $SettingDetails += "$SettingName"
                                    }
                                }
                                $CSPDetailsMap[$CSP.Name] = @{
                                    Description = $CSP.Description
                                    Settings = $SettingDetails
                                    Count = $FilteredSettingNames.Count
                                    TotalCount = $SettingNames.Count
                                }
                                
                                Write-LogMessage "INFO" "$($CSP.Name) CSP policies found: $($SettingNames.Count) settings" "POLICY"
                            }
                        }
                    }
                }
                
                # Method 2: Try WMI Bridge Provider (requires elevated privileges)
                try {
                    $WMIClasses = Get-CimClass -Namespace "root\cimv2\mdm\dmmap" -ClassName "*Policy_Result*" -ErrorAction SilentlyContinue
                    if ($WMIClasses) {
                        Write-LogMessage "INFO" "MDM WMI Bridge Provider accessible - $($WMIClasses.Count) policy classes" "POLICY"
                    }
                }
                catch {
                    Write-LogMessage "INFO" "MDM WMI Bridge Provider not accessible (normal for non-SYSTEM context)" "POLICY"
                }
            }
            
            # Results
            $Results += [PSCustomObject]@{
                Category = "Policy"
                Item = "MDM Policy Management"
                Value = if ($MDMEnrolled) { "Active" } else { "Not Detected" }
                Details = if ($MDMEnrolled -and $AppliedPolicies.Count -gt 0) { 
                    "Intune/MDM enrolled with policies applied: $($AppliedPolicies -join ', ')" 
                } elseif ($MDMEnrolled) { 
                    "Intune/MDM enrolled - policy details require elevated access" 
                } else { 
                    "Not enrolled in MDM management" 
                }
                RiskLevel = if ($MDMEnrolled) { "LOW" } else { "MEDIUM" }
                Recommendation = if (-not $MDMEnrolled) { "Consider MDM enrollment for centralized management" } else { "" }
            }
            
            # Individual policy categories with detailed settings if detected
            if ($CSPDetailsMap.Count -gt 0) {
                foreach ($CSPName in $CSPDetailsMap.Keys) {
                    $CSPInfo = $CSPDetailsMap[$CSPName]
                    $SettingsPreview = if ($CSPInfo.Settings.Count -gt 0) {
                        $FirstFewSettings = $CSPInfo.Settings | Select-Object -First 3
                        "Settings: $($FirstFewSettings -join ', ')"
                        if ($CSPInfo.Settings.Count -gt 3) {
                            $SettingsPreview += " (+$($CSPInfo.Count - 3) more)"
                        }
                    } else {
                        "$($CSPInfo.Count) configured settings"
                    }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "$CSPName Policy"
                        Value = "$($CSPInfo.Count) settings configured"
                        Details = "$($CSPInfo.Description): $SettingsPreview"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check MDM status: $($_.Exception.Message)" "POLICY"
        }
        
        # Local Security Policy Analysis using secedit
        Write-LogMessage "INFO" "Analyzing local security policies..." "POLICY"
        try {
            $TempSecPol = "$env:TEMP\secpol.cfg"
            $SecEditResult = & secedit /export /cfg $TempSecPol /quiet 2>$null
            
            if (Test-Path $TempSecPol) {
                $SecPolContent = Get-Content $TempSecPol
                
                # Password Policy Analysis with null checking
                $MinPasswordLengthLine = $SecPolContent | Where-Object { $_ -match "MinimumPasswordLength" } | Select-Object -First 1
                $MinPasswordLength = if ($MinPasswordLengthLine) { $MinPasswordLengthLine.Split('=')[1].Trim() } else { $null }
                
                $PasswordComplexityLine = $SecPolContent | Where-Object { $_ -match "PasswordComplexity" } | Select-Object -First 1
                $PasswordComplexity = if ($PasswordComplexityLine) { $PasswordComplexityLine.Split('=')[1].Trim() } else { $null }
                
                $MaxPasswordAgeLine = $SecPolContent | Where-Object { $_ -match "MaximumPasswordAge" } | Select-Object -First 1
                $MaxPasswordAge = if ($MaxPasswordAgeLine) { $MaxPasswordAgeLine.Split('=')[1].Trim() } else { $null }
                
                $MinPasswordAgeLine = $SecPolContent | Where-Object { $_ -match "MinimumPasswordAge" } | Select-Object -First 1
                $MinPasswordAge = if ($MinPasswordAgeLine) { $MinPasswordAgeLine.Split('=')[1].Trim() } else { $null }
                
                $PasswordHistorySizeLine = $SecPolContent | Where-Object { $_ -match "PasswordHistorySize" } | Select-Object -First 1
                $PasswordHistorySize = if ($PasswordHistorySizeLine) { $PasswordHistorySizeLine.Split('=')[1].Trim() } else { $null }
                
                # Account Lockout Policy with null checking
                $LockoutThresholdLine = $SecPolContent | Where-Object { $_ -match "LockoutBadCount" } | Select-Object -First 1
                $LockoutThreshold = if ($LockoutThresholdLine) { $LockoutThresholdLine.Split('=')[1].Trim() } else { $null }
                
                $LockoutDurationLine = $SecPolContent | Where-Object { $_ -match "LockoutDuration" } | Select-Object -First 1
                $LockoutDuration = if ($LockoutDurationLine) { $LockoutDurationLine.Split('=')[1].Trim() } else { $null }
                
                $ResetLockoutCounterLine = $SecPolContent | Where-Object { $_ -match "ResetLockoutCount" } | Select-Object -First 1
                $ResetLockoutCounter = if ($ResetLockoutCounterLine) { $ResetLockoutCounterLine.Split('=')[1].Trim() } else { $null }
                
                # Password Policy Results
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password Length Requirement"
                    Value = if ($MinPasswordLength) { "$MinPasswordLength characters" } else { "Not configured" }
                    Details = "Minimum password length policy"
                    RiskLevel = if ([int]$MinPasswordLength -ge 12) { "LOW" } elseif ([int]$MinPasswordLength -ge 8) { "MEDIUM" } else { "HIGH" }
                    Recommendation = if ([int]$MinPasswordLength -lt 8) { "Minimum 8 characters required" } elseif ([int]$MinPasswordLength -lt 12) { "Consider 12+ characters for enhanced security" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password Complexity"
                    Value = if ($PasswordComplexity -eq "1") { "Enabled" } else { "Disabled" }
                    Details = "Requires uppercase, lowercase, numbers, and symbols"
                    RiskLevel = if ($PasswordComplexity -eq "1") { "LOW" } else { "HIGH" }
                    Recommendation = if ($PasswordComplexity -ne "1") { "Enable password complexity requirements" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password History"
                    Value = if ($PasswordHistorySize) { "$PasswordHistorySize passwords remembered" } else { "Not configured" }
                    Details = "Prevents password reuse"
                    RiskLevel = if ([int]$PasswordHistorySize -ge 12) { "LOW" } elseif ([int]$PasswordHistorySize -ge 5) { "MEDIUM" } else { "HIGH" }
                    Recommendation = if ([int]$PasswordHistorySize -lt 12) { "Remember last 12 passwords minimum" } else { "" }
                }
                
                # Account Lockout Policy Results
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Account Lockout Threshold"
                    Value = if ($LockoutThreshold -and $LockoutThreshold -ne "0") { "$LockoutThreshold invalid attempts" } else { "No lockout policy" }
                    Details = "Failed logon attempts before lockout"
                    RiskLevel = if ($LockoutThreshold -and [int]$LockoutThreshold -le 10 -and [int]$LockoutThreshold -gt 0) { "LOW" } elseif ($LockoutThreshold -eq "0") { "HIGH" } else { "MEDIUM" }
                    Recommendation = if ($LockoutThreshold -eq "0") { "Configure account lockout policy" } else { "" }
                }
                
                if ($LockoutThreshold -and $LockoutThreshold -ne "0") {
                    $LockoutDurationMinutes = if ($LockoutDuration) { [math]::Round([int]$LockoutDuration / 60) } else { 0 }
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "Account Lockout Duration"
                        Value = if ($LockoutDuration -eq "-1") { "Until admin unlocks" } else { "$LockoutDurationMinutes minutes" }
                        Details = "How long accounts remain locked"
                        RiskLevel = if ($LockoutDuration -eq "-1" -or $LockoutDurationMinutes -ge 15) { "LOW" } else { "MEDIUM" }
                        Recommendation = ""
                    }
                }
                
                # Clean up temp file
                Remove-Item $TempSecPol -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not analyze local security policies: $($_.Exception.Message)" "POLICY"
        }
        
        # Screen Lock / Screen Saver Policy
        Write-LogMessage "INFO" "Checking screen lock policies..." "POLICY"
        try {
            # Check screen saver settings (skip HKCU if running as SYSTEM)
            $ScreenSaveActive = $null
            $ScreenSaveTimeOut = $null  
            $ScreenSaverIsSecure = $null
            
            if ($env:USERNAME -ne "SYSTEM") {
                $ScreenSaveActive = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
                $ScreenSaveTimeOut = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
                $ScreenSaverIsSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
            } else {
                Write-LogMessage "INFO" "Running as SYSTEM - skipping user-specific screen saver settings" "POLICY"
            }
            
            # Check machine-wide policy settings
            $MachineScreenSaver = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue
            
            if ($ScreenSaveActive -and $ScreenSaveActive.ScreenSaveActive -eq "1") {
                $TimeoutMinutes = if ($ScreenSaveTimeOut) { [math]::Round([int]$ScreenSaveTimeOut.ScreenSaveTimeOut / 60) } else { 0 }
                $IsSecure = $ScreenSaverIsSecure -and $ScreenSaverIsSecure.ScreenSaverIsSecure -eq "1"
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Screen Lock Policy"
                    Value = "Enabled - $TimeoutMinutes minutes"
                    Details = "Secure: $IsSecure, Timeout: $TimeoutMinutes minutes"
                    RiskLevel = if ($IsSecure -and $TimeoutMinutes -le 15 -and $TimeoutMinutes -gt 0) { "LOW" } elseif ($IsSecure -and $TimeoutMinutes -le 30) { "MEDIUM" } else { "HIGH" }
                    Recommendation = if (-not $IsSecure) { "Enable secure screen saver" } elseif ($TimeoutMinutes -gt 15) { "Screen lock timeout should be 15 minutes or less" } else { "" }
                }
            } else {
                # Handle case where no user context exists (SYSTEM) or screen saver is disabled
                $PolicyStatus = if ($env:USERNAME -eq "SYSTEM") { "Cannot Check (System Context)" } else { "Disabled" }
                $PolicyRisk = if ($env:USERNAME -eq "SYSTEM") { "MEDIUM" } else { "HIGH" }
                $PolicyRecommendation = if ($env:USERNAME -eq "SYSTEM") { "Screen lock policy should be enforced via Group Policy" } else { "Configure automatic screen lock" }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Screen Lock Policy"
                    Value = $PolicyStatus
                    Details = if ($env:USERNAME -eq "SYSTEM") { "Running as SYSTEM - user-specific settings not accessible" } else { "No automatic screen lock configured" }
                    RiskLevel = $PolicyRisk
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check screen lock policies: $($_.Exception.Message)" "POLICY"
        }
        
        # Audit Policy Analysis
        Write-LogMessage "INFO" "Analyzing audit policies..." "POLICY"
        try {
            $AuditPolResult = & auditpol /get /category:* 2>$null
            if ($LASTEXITCODE -eq 0) {
                # Parse audit policy results
                $CriticalAuditEvents = @(
                    @{Name="Logon/Logoff"; Pattern="Logon"}
                    @{Name="Account Logon"; Pattern="Credential Validation"}
                    @{Name="Account Management"; Pattern="User Account Management"}
                    @{Name="Policy Change"; Pattern="Audit Policy Change"}
                    @{Name="Privilege Use"; Pattern="Sensitive Privilege Use"}
                )
                
                $AuditResults = @()
                foreach ($AuditEvent in $CriticalAuditEvents) {
                    $EventLine = $AuditPolResult | Where-Object { $_ -match $AuditEvent.Pattern }
                    if ($EventLine) {
                        $AuditStatus = if ($EventLine -match "Success and Failure|Success|Failure") { 
                            $matches[0] 
                        } else { 
                            "No Auditing" 
                        }
                        $AuditResults += "$($AuditEvent.Name): $AuditStatus"
                    }
                }
                
                $EnabledAudits = ($AuditResults | Where-Object { $_ -notmatch "No Auditing" }).Count
                $TotalAudits = $AuditResults.Count
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Audit Policy Configuration"
                    Value = "$EnabledAudits of $TotalAudits critical audits enabled"
                    Details = $AuditResults -join "; "
                    RiskLevel = if ($EnabledAudits -eq $TotalAudits) { "LOW" } elseif ($EnabledAudits -ge 3) { "MEDIUM" } else { "HIGH" }
                    Recommendation = if ($EnabledAudits -lt $TotalAudits) { "Enable comprehensive audit logging" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not analyze audit policies: $($_.Exception.Message)" "POLICY"
        }
        
        # User Rights Assignment (Critical Rights)
        Write-LogMessage "INFO" "Checking critical user rights assignments..." "POLICY"
        try {
            $TempUserRights = "$env:TEMP\userrights.txt"
            $SecEditResult = & secedit /export /areas USER_RIGHTS /cfg $TempUserRights /quiet 2>$null
            
            if (Test-Path $TempUserRights) {
                $UserRightsContent = Get-Content $TempUserRights
                
                # Check critical rights with detailed analysis
                $CriticalRights = @{
                    "SeServiceLogonRight" = @{ Name = "Log on as a service"; Pattern = "SeServiceLogonRight"; Risk = "HIGH" }
                    "SeInteractiveLogonRight" = @{ Name = "Log on locally"; Pattern = "SeInteractiveLogonRight"; Risk = "MEDIUM" }
                    "SeShutdownPrivilege" = @{ Name = "Shut down the system"; Pattern = "SeShutdownPrivilege"; Risk = "MEDIUM" }
                    "SeBackupPrivilege" = @{ Name = "Back up files and directories"; Pattern = "SeBackupPrivilege"; Risk = "HIGH" }
                    "SeRestorePrivilege" = @{ Name = "Restore files and directories"; Pattern = "SeRestorePrivilege"; Risk = "HIGH" }
                    "SeDebugPrivilege" = @{ Name = "Debug programs"; Pattern = "SeDebugPrivilege"; Risk = "HIGH" }
                    "SeTakeOwnershipPrivilege" = @{ Name = "Take ownership"; Pattern = "SeTakeOwnershipPrivilege"; Risk = "HIGH" }
                }
                
                $DangerousRights = @()
                $CheckedRights = @()
                
                foreach ($Right in $CriticalRights.Keys) {
                    $RightInfo = $CriticalRights[$Right]
                    $RightLine = $UserRightsContent | Where-Object { $_ -match $Right } | Select-Object -First 1
                    
                    if ($RightLine) {
                        $AssignedUsers = $RightLine.Split('=')[1]
                        $CheckedRights += "$($RightInfo.Name): Configured"
                        
                        # Check for overly permissive assignments
                        if ($AssignedUsers -and $AssignedUsers -match "Everyone") {
                            $DangerousRights += "$($RightInfo.Name) assigned to Everyone"
                        }
                        elseif ($AssignedUsers -and $AssignedUsers -match "Users" -and $RightInfo.Risk -eq "HIGH") {
                            $DangerousRights += "$($RightInfo.Name) assigned to Users group"
                        }
                    } else {
                        $CheckedRights += "$($RightInfo.Name): Not configured"
                    }
                }
                
                # Summary entry
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Local Security Policy"
                    Value = "Active"
                    Details = "Local computer security settings managed independently"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                if ($DangerousRights.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "User Rights Assignment"
                        Value = "Issues Found"
                        Details = $DangerousRights -join "; "
                        RiskLevel = "MEDIUM"
                        Recommendation = "Review user rights assignments for least privilege"
                    }
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "User Rights Assignment"
                        Value = "Secure Configuration"
                        Details = "Critical rights: $($CheckedRights -join ', ')"
                        RiskLevel = "LOW"
                        Recommendation = ""
                    }
                }
                
                Remove-Item $TempUserRights -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check user rights assignments: $($_.Exception.Message)" "POLICY"
        }
        
        # Windows Defender Policy Settings
        Write-LogMessage "INFO" "Checking Windows Defender policy settings..." "POLICY"
        try {
            $DefenderPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -ErrorAction SilentlyContinue
            $DefenderRealTime = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ErrorAction SilentlyContinue
            
            if ($DefenderPolicy -and $DefenderPolicy.DisableAntiSpyware -eq 1) {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Windows Defender Policy"
                    Value = "Disabled by Policy"
                    Details = "Windows Defender disabled through Group Policy"
                    RiskLevel = "HIGH"
                    Recommendation = "Ensure antivirus protection is enabled unless replaced by third-party solution"
                }
            } elseif ($DefenderRealTime -and $DefenderRealTime.DisableRealtimeMonitoring -eq 1) {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Windows Defender Policy"
                    Value = "Real-time Protection Disabled"
                    Details = "Real-time protection disabled by policy"
                    RiskLevel = "HIGH"
                    Recommendation = "Enable real-time antivirus protection"
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Windows Defender Policy"
                    Value = "Not Restricted"
                    Details = "No policy restrictions on Windows Defender"
                    RiskLevel = "LOW"
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check Windows Defender policies: $($_.Exception.Message)" "POLICY"
        }
        
        Write-LogMessage "SUCCESS" "Policy analysis completed" "POLICY"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze policies: $($_.Exception.Message)" "POLICY"
        return @()
    }
}

# === src\modules\Get-DiskSpaceAnalysis.ps1 ===
# WindowsWorkstationAuditor - Disk Space Analysis Module
# Version 1.3.0

function Get-DiskSpaceAnalysis {
    <#
    .SYNOPSIS
        Analyzes disk space, drive capacity, and storage health status
        
    .DESCRIPTION
        Collects comprehensive disk space information including drive capacity,
        free space percentages, disk health status, and storage risk assessment.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (WMI access)
    #>
    
    Write-LogMessage "INFO" "Analyzing disk space and storage..." "DISK"
    
    try {
        $Results = @()
        $Drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        
        foreach ($Drive in $Drives) {
            $DriveLetter = $Drive.DeviceID
            $TotalSizeGB = [math]::Round($Drive.Size / 1GB, 2)
            $FreeSpaceGB = [math]::Round($Drive.FreeSpace / 1GB, 2)
            $UsedSpaceGB = $TotalSizeGB - $FreeSpaceGB
            $FreeSpacePercent = [math]::Round(($FreeSpaceGB / $TotalSizeGB) * 100, 1)
            
            # Determine risk level based on free space percentage
            $RiskLevel = if ($FreeSpacePercent -lt 10) { "HIGH" } 
                        elseif ($FreeSpacePercent -lt 20) { "MEDIUM" } 
                        else { "LOW" }
            
            $Recommendation = if ($FreeSpacePercent -lt 15) { 
                "Maintain adequate free disk space for system operations" 
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Storage"
                Item = "Disk Space ($DriveLetter)"
                Value = "$FreeSpacePercent% free"
                Details = "Total: $TotalSizeGB GB, Used: $UsedSpaceGB GB, Free: $FreeSpaceGB GB"
                RiskLevel = $RiskLevel
                Recommendation = ""
            }
            
            Write-LogMessage "INFO" "Drive $DriveLetter - $FreeSpacePercent% free ($FreeSpaceGB GB / $TotalSizeGB GB)" "DISK"
        }
        
        # Check for disk health using SMART data if available
        try {
            $PhysicalDisks = Get-CimInstance -ClassName Win32_DiskDrive
            foreach ($Disk in $PhysicalDisks) {
                $DiskModel = $Disk.Model
                $DiskSize = [math]::Round($Disk.Size / 1GB, 2)
                $DiskStatus = $Disk.Status
                
                $HealthRisk = if ($DiskStatus -ne "OK") { "HIGH" } else { "LOW" }
                $HealthRecommendation = if ($DiskStatus -ne "OK") { 
                    "Monitor disk health and replace failing drives" 
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Storage"
                    Item = "Disk Health"
                    Value = $DiskStatus
                    Details = "$DiskModel ($DiskSize GB)"
                    RiskLevel = $HealthRisk
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Physical disk: $DiskModel - Status: $DiskStatus" "DISK"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve disk health information: $($_.Exception.Message)" "DISK"
        }
        
        $DriveCount = if ($Drives) { $Drives.Count } else { 0 }
        Write-LogMessage "SUCCESS" "Disk space analysis completed - $DriveCount drives analyzed" "DISK"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze disk space: $($_.Exception.Message)" "DISK"
        return @()
    }
}

# === src\modules\Get-MemoryAnalysis.ps1 ===
# WindowsWorkstationAuditor - Memory Analysis Module
# Version 1.3.0

function Get-MemoryAnalysis {
    <#
    .SYNOPSIS
        Analyzes system memory usage, virtual memory, and performance counters
        
    .DESCRIPTION
        Collects comprehensive memory information including RAM usage, virtual memory
        configuration, page file settings, and memory performance analysis.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (WMI and performance counter access)
    #>
    
    Write-LogMessage "INFO" "Analyzing memory usage and performance..." "MEMORY"
    
    try {
        $Results = @()
        
        # Get physical memory information
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem
        $Computer = Get-CimInstance -ClassName Win32_ComputerSystem
        
        $TotalMemoryGB = [math]::Round($Computer.TotalPhysicalMemory / 1GB, 2)
        $FreeMemoryGB = [math]::Round($OS.FreePhysicalMemory / 1KB / 1MB, 2)
        $UsedMemoryGB = $TotalMemoryGB - $FreeMemoryGB
        $MemoryUsagePercent = [math]::Round(($UsedMemoryGB / $TotalMemoryGB) * 100, 1)
        
        # Determine memory usage risk level
        $MemoryRiskLevel = if ($MemoryUsagePercent -gt 85) { "HIGH" }
                          elseif ($MemoryUsagePercent -gt 75) { "MEDIUM" }
                          else { "LOW" }
        
        $MemoryRecommendation = if ($MemoryUsagePercent -gt 80) {
            "High memory usage may impact system performance"
        } else { "" }
        
        $Results += [PSCustomObject]@{
            Category = "Memory"
            Item = "Physical Memory Usage"
            Value = "$MemoryUsagePercent% used"
            Details = "Total: $TotalMemoryGB GB, Used: $UsedMemoryGB GB, Free: $FreeMemoryGB GB"
            RiskLevel = $MemoryRiskLevel
            Recommendation = ""
        }
        
        Write-LogMessage "INFO" "Physical Memory: $MemoryUsagePercent% used ($UsedMemoryGB GB / $TotalMemoryGB GB)" "MEMORY"
        
        # Get virtual memory (page file) information
        try {
            $PageFiles = Get-CimInstance -ClassName Win32_PageFileUsage
            if ($PageFiles) {
                foreach ($PageFile in $PageFiles) {
                    $PageFileSizeGB = [math]::Round($PageFile.AllocatedBaseSize / 1024, 2)
                    $PageFileUsedGB = [math]::Round($PageFile.CurrentUsage / 1024, 2)
                    $PageFileUsagePercent = if ($PageFileSizeGB -gt 0) { 
                        [math]::Round(($PageFileUsedGB / $PageFileSizeGB) * 100, 1) 
                    } else { 0 }
                    
                    $PageFileRisk = if ($PageFileUsagePercent -gt 80) { "HIGH" }
                                   elseif ($PageFileUsagePercent -gt 60) { "MEDIUM" }
                                   else { "LOW" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Memory"
                        Item = "Virtual Memory"
                        Value = "$PageFileUsagePercent% used"
                        Details = "Page File: $($PageFile.Name), Size: $PageFileSizeGB GB, Used: $PageFileUsedGB GB"
                        RiskLevel = $PageFileRisk
                        Recommendation = if ($PageFileUsagePercent -gt 70) { "Monitor virtual memory usage" } else { "" }
                    }
                    
                    Write-LogMessage "INFO" "Page File $($PageFile.Name): $PageFileUsagePercent% used ($PageFileUsedGB GB / $PageFileSizeGB GB)" "MEMORY"
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Memory"
                    Item = "Virtual Memory"
                    Value = "No page file configured"
                    Details = "System has no virtual memory page file"
                    RiskLevel = "MEDIUM"
                    Recommendation = "Consider configuring virtual memory for system stability"
                }
                Write-LogMessage "WARN" "No page file configured on system" "MEMORY"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve page file information: $($_.Exception.Message)" "MEMORY"
        }
        
        # Get memory performance counters
        try {
            $AvailableBytes = (Get-Counter "\Memory\Available Bytes" -SampleInterval 1 -MaxSamples 1).CounterSamples[0].CookedValue
            $AvailableMB = [math]::Round($AvailableBytes / 1MB, 0)
            
            $CommittedBytes = (Get-Counter "\Memory\Committed Bytes" -SampleInterval 1 -MaxSamples 1).CounterSamples[0].CookedValue
            $CommittedMB = [math]::Round($CommittedBytes / 1MB, 0)
            
            $Results += [PSCustomObject]@{
                Category = "Memory"
                Item = "Available Memory"
                Value = "$AvailableMB MB available"
                Details = "System has $AvailableMB MB available for allocation"
                RiskLevel = if ($AvailableMB -lt 512) { "HIGH" } elseif ($AvailableMB -lt 1024) { "MEDIUM" } else { "LOW" }
                Recommendation = if ($AvailableMB -lt 1024) { "Low available memory may impact performance" } else { "" }
            }
            
            $Results += [PSCustomObject]@{
                Category = "Memory"
                Item = "Committed Memory"
                Value = "$CommittedMB MB committed"
                Details = "System has committed $CommittedMB MB of virtual memory"
                RiskLevel = "INFO"
                Recommendation = ""
            }
            
            Write-LogMessage "INFO" "Memory Performance: Available: $AvailableMB MB, Committed: $CommittedMB MB" "MEMORY"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve memory performance counters: $($_.Exception.Message)" "MEMORY"
        }
        
        Write-LogMessage "SUCCESS" "Memory analysis completed - Total RAM: $TotalMemoryGB GB, Usage: $MemoryUsagePercent%" "MEMORY"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze memory: $($_.Exception.Message)" "MEMORY"
        return @()
    }
}

# === src\modules\Get-PrinterAnalysis.ps1 ===
# WindowsWorkstationAuditor - Printer Analysis Module
# Version 1.3.0

function Get-PrinterAnalysis {
    <#
    .SYNOPSIS
        Analyzes installed printers, drivers, and network printer configurations
        
    .DESCRIPTION
        Collects comprehensive printer information including local and network printers,
        driver versions and status, print spooler service health, and default printer settings.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (WMI access and print spooler service access)
    #>
    
    Write-LogMessage "INFO" "Analyzing printer configurations and drivers..." "PRINTER"
    
    try {
        $Results = @()
        
        # Check Print Spooler service status
        try {
            $SpoolerService = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
            if ($SpoolerService) {
                $SpoolerRisk = if ($SpoolerService.Status -ne "Running") { "HIGH" } else { "LOW" }
                $SpoolerRecommendation = if ($SpoolerService.Status -ne "Running") {
                    "Print Spooler service should be running for proper printer functionality"
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Print Spooler Service"
                    Value = $SpoolerService.Status
                    Details = "Service startup type: $($SpoolerService.StartType)"
                    RiskLevel = $SpoolerRisk
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Print Spooler Service: $($SpoolerService.Status)" "PRINTER"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve Print Spooler service status: $($_.Exception.Message)" "PRINTER"
        }
        
        # Get installed printers
        try {
            $Printers = Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue
            $PrinterCount = if ($Printers) { $Printers.Count } else { 0 }
            
            if ($PrinterCount -eq 0) {
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Installed Printers"
                    Value = "No printers found"
                    Details = "System has no configured printers"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                Write-LogMessage "INFO" "No printers configured on system" "PRINTER"
            } else {
                $LocalPrinters = 0
                $NetworkPrinters = 0
                $DefaultPrinter = ""
                
                foreach ($Printer in $Printers) {
                    $PrinterName = $Printer.Name
                    $PrinterStatus = $Printer.PrinterStatus
                    $IsNetworkPrinter = $Printer.Network
                    $IsDefaultPrinter = $Printer.Default
                    $DriverName = $Printer.DriverName
                    $PortName = $Printer.PortName
                    
                    if ($IsNetworkPrinter) {
                        $NetworkPrinters++
                    } else {
                        $LocalPrinters++
                    }
                    
                    if ($IsDefaultPrinter) {
                        $DefaultPrinter = $PrinterName
                    }
                    
                    # Determine printer risk level based on status
                    $PrinterRisk = switch ($PrinterStatus) {
                        1 { "INFO" }    # Other
                        2 { "INFO" }    # Unknown
                        3 { "LOW" }     # Idle
                        4 { "LOW" }     # Printing
                        5 { "LOW" }     # Warmup
                        6 { "MEDIUM" }  # Stopped Printing
                        7 { "HIGH" }    # Offline
                        default { "MEDIUM" }
                    }
                    
                    $StatusText = switch ($PrinterStatus) {
                        1 { "Other" }
                        2 { "Unknown" }
                        3 { "Idle" }
                        4 { "Printing" }
                        5 { "Warmup" }
                        6 { "Stopped Printing" }
                        7 { "Offline" }
                        default { "Status Code: $PrinterStatus" }
                    }
                    
                    $PrinterRecommendation = if ($PrinterStatus -eq 7) {
                        "Offline printers should be investigated and restored"
                    } elseif ($PrinterStatus -eq 6) {
                        "Stopped printers may indicate driver or connectivity issues"
                    } else { "" }
                    
                    $PrinterType = if ($IsNetworkPrinter) { "Network" } else { "Local" }
                    $DefaultIndicator = if ($IsDefaultPrinter) { " (Default)" } else { "" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Printing"
                        Item = "Printer$DefaultIndicator"
                        Value = "$PrinterName"
                        Details = "Type: $PrinterType, Status: $StatusText, Driver: $DriverName"
                        RiskLevel = $PrinterRisk
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "INFO" "$PrinterType printer '$PrinterName': $StatusText" "PRINTER"
                }
                
                # Summary of printer configuration
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Printer Summary"
                    Value = "$PrinterCount total printers"
                    Details = "Local: $LocalPrinters, Network: $NetworkPrinters, Default: $DefaultPrinter"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Printer Summary: $PrinterCount total ($LocalPrinters local, $NetworkPrinters network)" "PRINTER"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve printer information: $($_.Exception.Message)" "PRINTER"
        }
        
        # Get printer drivers
        try {
            $PrinterDrivers = Get-CimInstance -ClassName Win32_PrinterDriver -ErrorAction SilentlyContinue
            $DriverCount = $PrinterDrivers.Count
            
            if ($DriverCount -gt 0) {
                $UniqueDrivers = $PrinterDrivers | Group-Object -Property Name | Measure-Object | Select-Object -ExpandProperty Count
                
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Printer Drivers"
                    Value = "$UniqueDrivers unique drivers installed"
                    Details = "Total driver installations: $DriverCount"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Printer Drivers: $UniqueDrivers unique drivers, $DriverCount total installations" "PRINTER"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve printer driver information: $($_.Exception.Message)" "PRINTER"
        }
        
        # Get printer ports (network connections)
        try {
            $PrinterPorts = Get-CimInstance -ClassName Win32_TCPIPPrinterPort -ErrorAction SilentlyContinue
            if ($PrinterPorts) {
                $NetworkPortCount = $PrinterPorts.Count
                
                foreach ($Port in $PrinterPorts) {
                    $PortName = $Port.Name
                    $HostAddress = $Port.HostAddress
                    $PortNumber = $Port.PortNumber
                    $SNMPEnabled = $Port.SNMPEnabled
                    
                    $PortRisk = if (-not $SNMPEnabled -and $Port.Protocol -eq 1) { "MEDIUM" } else { "LOW" }
                    $PortRecommendation = if (-not $SNMPEnabled -and $Port.Protocol -eq 1) {
                        "Consider enabling SNMP for better printer monitoring"
                    } else { "" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Printing"
                        Item = "Network Printer Port"
                        Value = "${HostAddress}:${PortNumber}"
                        Details = "Port: $PortName, SNMP Enabled: $SNMPEnabled"
                        RiskLevel = $PortRisk
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "INFO" "Network printer port: $PortName -> ${HostAddress}:${PortNumber}" "PRINTER"
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve printer port information: $($_.Exception.Message)" "PRINTER"
        }
        
        # Check print job queue
        try {
            $PrintJobs = Get-CimInstance -ClassName Win32_PrintJob -ErrorAction SilentlyContinue
            $JobCount = $PrintJobs.Count
            
            if ($JobCount -gt 0) {
                $StuckJobs = $PrintJobs | Where-Object { $_.Status -like "*Error*" -or $_.Status -like "*Paused*" } | Measure-Object | Select-Object -ExpandProperty Count
                
                $QueueRisk = if ($StuckJobs -gt 0) { "MEDIUM" } elseif ($JobCount -gt 10) { "MEDIUM" } else { "LOW" }
                $QueueRecommendation = if ($StuckJobs -gt 0) {
                    "Clear stuck print jobs to maintain system performance"
                } elseif ($JobCount -gt 10) {
                    "Large print queue may indicate printer or network issues"
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Print Queue"
                    Value = "$JobCount jobs queued"
                    Details = "Active jobs: $JobCount, Stuck/Error jobs: $StuckJobs"
                    RiskLevel = $QueueRisk
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Print queue: $JobCount jobs ($StuckJobs stuck/error)" "PRINTER"
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Print Queue"
                    Value = "Empty"
                    Details = "No print jobs currently queued"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Print queue is empty" "PRINTER"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve print job information: $($_.Exception.Message)" "PRINTER"
        }
        
        Write-LogMessage "SUCCESS" "Printer analysis completed - $($Results.Count) items analyzed" "PRINTER"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze printers: $($_.Exception.Message)" "PRINTER"
        return @()
    }
}

# === src\modules\Get-NetworkAnalysis.ps1 ===
# WindowsWorkstationAuditor - Network Analysis Module
# Version 1.3.0

function Get-NetworkAnalysis {
    <#
    .SYNOPSIS
        Analyzes network adapters, IP configuration, open ports, and network shares
        
    .DESCRIPTION
        Collects comprehensive network information including network adapter status,
        IP configuration (static vs DHCP), open ports and listening services,
        network shares, and network security settings.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (WMI access and network configuration access)
    #>
    
    Write-LogMessage "INFO" "Analyzing network configuration and security..." "NETWORK"
    
    try {
        $Results = @()
        
        # Get network adapters
        try {
            $NetworkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -ne $null }
            $ActiveAdapters = $NetworkAdapters | Where-Object { $_.NetConnectionStatus -eq 2 }
            $DisconnectedAdapters = $NetworkAdapters | Where-Object { $_.NetConnectionStatus -eq 7 }
            
            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "Network Adapters"
                Value = "$($ActiveAdapters.Count) active, $($DisconnectedAdapters.Count) disconnected"
                Details = "Total adapters: $($NetworkAdapters.Count)"
                RiskLevel = "INFO"
                Recommendation = ""
            }
            
            foreach ($Adapter in $ActiveAdapters) {
                $AdapterName = $Adapter.Name
                $ConnectionName = $Adapter.NetConnectionID
                $Speed = if ($Adapter.Speed) { "$([math]::Round($Adapter.Speed / 1MB, 0)) Mbps" } else { "Unknown" }
                $MACAddress = $Adapter.MACAddress
                
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Active Network Adapter"
                    Value = "Connected"
                    Details = "$ConnectionName ($AdapterName), Speed: $Speed, MAC: $MACAddress"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Active adapter: $ConnectionName - $Speed" "NETWORK"
            }
            
            $ActiveCount = if ($ActiveAdapters) { $ActiveAdapters.Count } else { 0 }
            $TotalCount = if ($NetworkAdapters) { $NetworkAdapters.Count } else { 0 }
            Write-LogMessage "INFO" "Network adapters: $ActiveCount active, $TotalCount total" "NETWORK"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve network adapter information: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get IP configuration
        try {
            $IPConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
            
            foreach ($IPConfig in $IPConfigs) {
                $InterfaceIndex = $IPConfig.InterfaceIndex
                $IPAddresses = $IPConfig.IPAddress
                $SubnetMasks = $IPConfig.IPSubnet
                $DefaultGateways = $IPConfig.DefaultIPGateway
                $DHCPEnabled = $IPConfig.DHCPEnabled
                $DNSServers = $IPConfig.DNSServerSearchOrder
                $Description = $IPConfig.Description
                
                if ($IPAddresses) {
                    foreach ($i in 0..($IPAddresses.Count - 1)) {
                        $IPAddress = $IPAddresses[$i]
                        $SubnetMask = if ($SubnetMasks -and $i -lt $SubnetMasks.Count) { $SubnetMasks[$i] } else { "N/A" }
                        
                        # Skip IPv6 link-local addresses for cleaner output
                        if ($IPAddress -match "^fe80:" -or $IPAddress -match "^169\.254\.") {
                            continue
                        }
                        
                        $ConfigType = if ($DHCPEnabled) { "DHCP" } else { "Static" }
                        $IPType = if ($IPAddress -match ":") { "IPv6" } else { "IPv4" }
                        
                        $IPRisk = if (-not $DHCPEnabled -and $IPAddress -match "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
                            "LOW"
                        } elseif (-not $DHCPEnabled) {
                            "MEDIUM"
                        } else {
                            "LOW"
                        }
                        
                        $IPRecommendation = if (-not $DHCPEnabled -and $IPType -eq "IPv4") {
                            "Static IP configuration should be documented and managed"
                        } else { "" }
                        
                        $GatewayInfo = if ($DefaultGateways) { "Gateway: $($DefaultGateways[0])" } else { "No gateway" }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Network"
                            Item = "IP Configuration ($IPType)"
                            Value = "$IPAddress ($ConfigType)"
                            Details = "$Description, Subnet: $SubnetMask, $GatewayInfo"
                            RiskLevel = $IPRisk
                            Recommendation = ""
                        }
                        
                        Write-LogMessage "INFO" "IP Config: $IPAddress ($ConfigType) on $Description" "NETWORK"
                    }
                }
                
                # DNS Configuration
                if ($DNSServers) {
                    $DNSList = $DNSServers -join ", "
                    $DNSRisk = "LOW"
                    $DNSRecommendation = ""
                    
                    # Check for potentially insecure DNS servers
                    $PublicDNS = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "208.67.222.222", "208.67.220.220")
                    $HasPublicDNS = $DNSServers | Where-Object { $_ -in $PublicDNS }
                    
                    if ($HasPublicDNS) {
                        $DNSRisk = "MEDIUM"
                        $DNSRecommendation = "Consider using internal DNS servers for better security control"
                    }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Network"
                        Item = "DNS Configuration"
                        Value = $DNSServers.Count.ToString() + " servers configured"
                        Details = "DNS Servers: $DNSList"
                        RiskLevel = $DNSRisk
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "INFO" "DNS servers: $DNSList" "NETWORK"
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve IP configuration: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get open ports and listening services
        try {
            $ListeningPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Sort-Object LocalPort
            $UDPPorts = Get-NetUDPEndpoint | Sort-Object LocalPort
            
            $TCPPortCount = $ListeningPorts.Count
            $UDPPortCount = $UDPPorts.Count
            
            # Check for common risky ports
            $RiskyTCPPorts = @(21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900)
            $OpenRiskyPorts = $ListeningPorts | Where-Object { $_.LocalPort -in $RiskyTCPPorts }
            
            $PortRisk = if ($OpenRiskyPorts.Count -gt 0) { "HIGH" } 
                       elseif ($TCPPortCount -gt 50) { "MEDIUM" } 
                       else { "LOW" }
            
            $PortRecommendation = if ($OpenRiskyPorts.Count -gt 0) {
                "Review open ports for security risks - found potentially risky ports"
            } elseif ($TCPPortCount -gt 50) {
                "Large number of open ports may increase attack surface"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "Open Ports"
                Value = "$TCPPortCount TCP, $UDPPortCount UDP"
                Details = "Risky TCP ports open: $($OpenRiskyPorts.Count)"
                RiskLevel = $PortRisk
                Recommendation = ""
            }
            
            # Detail risky ports if found - header + detail format
            $UniqueRiskyPorts = $OpenRiskyPorts | Group-Object LocalPort | ForEach-Object { $_.Group[0] }
            if ($UniqueRiskyPorts.Count -gt 0) {
                # Header entry with compliance message
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Risky Open Ports"
                    Value = "$($UniqueRiskyPorts.Count) high-risk ports detected"
                    Details = "Network services that may present security risks"
                    RiskLevel = "HIGH"
                    Recommendation = "Secure or disable unnecessary network services"
                }
                
                # Individual detail entries without compliance duplication
                foreach ($RiskyPort in $UniqueRiskyPorts) {
                    $PortNumber = $RiskyPort.LocalPort
                    $ProcessId = $RiskyPort.OwningProcess
                    $ProcessName = if ($ProcessId) {
                        try { (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue).ProcessName }
                        catch { "Unknown" }
                    } else { "Unknown" }
                    
                    $ServiceName = switch ($PortNumber) {
                        21 { "FTP" }
                        23 { "Telnet" }
                        135 { "RPC Endpoint Mapper" }
                        139 { "NetBIOS Session Service" }
                        445 { "SMB/CIFS" }
                        1433 { "SQL Server" }
                        1521 { "Oracle Database" }
                        3306 { "MySQL" }
                        3389 { "Remote Desktop" }
                        5432 { "PostgreSQL" }
                        5900 { "VNC" }
                        default { "Unknown Service" }
                    }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Network"
                        Item = "Port $PortNumber"
                        Value = "$ServiceName"
                        Details = "Process: $ProcessName (PID: $ProcessId)"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "WARN" "Risky port open: $PortNumber ($ServiceName) - Process: $ProcessName" "NETWORK"
                }
            }
            
            $UniqueRiskyCount = ($UniqueRiskyPorts | Measure-Object).Count
            Write-LogMessage "INFO" "Open ports: $TCPPortCount TCP, $UDPPortCount UDP ($UniqueRiskyCount risky)" "NETWORK"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve open port information: $($_.Exception.Message)" "NETWORK"
        }
        
        # Check Remote Desktop (RDP) Configuration - High Risk if enabled
        try {
            # Check if RDP is enabled via registry
            $RDPEnabled = $false
            $RDPPort = 3389  # Default RDP port
            
            try {
                $RDPRegistry = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
                $RDPEnabled = ($RDPRegistry.fDenyTSConnections -eq 0)
            } catch {
                Write-LogMessage "WARN" "Could not check RDP registry settings: $($_.Exception.Message)" "NETWORK"
            }
            
            # Check if RDP port is open/listening
            $RDPListening = $false
            if ($TCPConnections) {
                $RDPListening = $TCPConnections | Where-Object { $_.LocalPort -eq $RDPPort -and $_.State -eq "Listen" }
            }
            
            # Check for custom RDP port
            try {
                $CustomPortRegistry = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
                if ($CustomPortRegistry -and $CustomPortRegistry.PortNumber -ne 3389) {
                    $RDPPort = $CustomPortRegistry.PortNumber
                    $RDPListening = $TCPConnections | Where-Object { $_.LocalPort -eq $RDPPort -and $_.State -eq "Listen" }
                }
            } catch {
                # Ignore errors checking for custom port
            }
            
            if ($RDPEnabled -or $RDPListening) {
                $RDPStatus = if ($RDPEnabled -and $RDPListening) { "Enabled and Listening" }
                            elseif ($RDPEnabled) { "Enabled (Not Listening)" }
                            else { "Listening (Unknown Config)" }
                
                $PortText = if ($RDPPort -ne 3389) { " on custom port $RDPPort" } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Remote Desktop (RDP)"
                    Value = $RDPStatus
                    Details = "RDP is accessible$PortText. This provides remote access to the system and should be secured with strong authentication, network restrictions, and monitoring."
                    RiskLevel = "HIGH"
                    Recommendation = "Secure remote access - use VPN, strong auth, restrict source IPs, enable logging"
                }
                
                Write-LogMessage "WARN" "RDP detected: $RDPStatus on port $RDPPort" "NETWORK"
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Remote Desktop (RDP)"
                    Value = "Disabled"
                    Details = "RDP is properly disabled"
                    RiskLevel = "LOW"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "RDP is disabled - good security posture" "NETWORK"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not analyze RDP configuration: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get network shares
        try {
            $NetworkShares = Get-CimInstance -ClassName Win32_Share | Where-Object { $_.Type -eq 0 }  # Disk shares only
            $AdminShares = $NetworkShares | Where-Object { $_.Name -match '\$$' }
            $UserShares = $NetworkShares | Where-Object { $_.Name -notmatch '\$$' }
            
            $ShareRisk = if ($UserShares.Count -gt 0) { "MEDIUM" } 
                        elseif ($AdminShares.Count -gt 3) { "MEDIUM" } 
                        else { "LOW" }
            
            $ShareRecommendation = if ($UserShares.Count -gt 0) {
                "Review network share permissions and access controls"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "Network Shares"
                Value = "$($NetworkShares.Count) total shares"
                Details = "User shares: $($UserShares.Count), Admin shares: $($AdminShares.Count)"
                RiskLevel = $ShareRisk
                Recommendation = ""
            }
            
            foreach ($Share in $UserShares) {
                $ShareName = $Share.Name
                $SharePath = $Share.Path
                $ShareDescription = $Share.Description
                
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Network Share"
                    Value = $ShareName
                    Details = "Path: $SharePath, Description: $ShareDescription"
                    RiskLevel = "MEDIUM"
                    Recommendation = "Ensure proper access controls and monitoring for network shares"
                }
                
                Write-LogMessage "INFO" "Network share: $ShareName -> $SharePath" "NETWORK"
            }
            
            Write-LogMessage "INFO" "Network shares: $($NetworkShares.Count) total ($($UserShares.Count) user, $($AdminShares.Count) admin)" "NETWORK"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve network share information: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get network discovery and file sharing settings
        try {
            $NetworkProfile = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $true }
            $NetworkDiscovery = Get-NetFirewallRule -DisplayGroup "Network Discovery" | Where-Object { $_.Enabled -eq $true }
            $FileSharing = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Where-Object { $_.Enabled -eq $true }
            
            $DiscoveryEnabled = $NetworkDiscovery.Count -gt 0
            $FileSharingEnabled = $FileSharing.Count -gt 0
            
            $DiscoveryRisk = if ($DiscoveryEnabled) { "MEDIUM" } else { "LOW" }
            $DiscoveryRecommendation = if ($DiscoveryEnabled) {
                "Network discovery should be disabled on untrusted networks"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "Network Discovery"
                Value = if ($DiscoveryEnabled) { "Enabled" } else { "Disabled" }
                Details = "Network discovery firewall rules: $($NetworkDiscovery.Count) enabled"
                RiskLevel = $DiscoveryRisk
                Recommendation = ""
            }
            
            $SharingRisk = if ($FileSharingEnabled) { "MEDIUM" } else { "LOW" }
            $SharingRecommendation = if ($FileSharingEnabled) {
                "File sharing should be carefully controlled and monitored"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "File and Printer Sharing"
                Value = if ($FileSharingEnabled) { "Enabled" } else { "Disabled" }
                Details = "File sharing firewall rules: $($FileSharing.Count) enabled"
                RiskLevel = $SharingRisk
                Recommendation = ""
            }
            
            Write-LogMessage "INFO" "Network Discovery: $(if ($DiscoveryEnabled) {'Enabled'} else {'Disabled'}), File Sharing: $(if ($FileSharingEnabled) {'Enabled'} else {'Disabled'})" "NETWORK"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve network security settings: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get wireless network information if available
        try {
            $WirelessProfiles = netsh wlan show profiles 2>$null | Select-String "All User Profile"
            if ($WirelessProfiles) {
                $ProfileCount = $WirelessProfiles.Count
                
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Wireless Profiles"
                    Value = "$ProfileCount saved profiles"
                    Details = "Saved wireless network configurations"
                    RiskLevel = "MEDIUM"
                    Recommendation = "Review wireless network profiles and remove unused ones"
                }
                
                Write-LogMessage "INFO" "Wireless profiles: $ProfileCount saved" "NETWORK"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve wireless profile information: $($_.Exception.Message)" "NETWORK"
        }
        
        Write-LogMessage "SUCCESS" "Network analysis completed - $($Results.Count) items analyzed" "NETWORK"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze network configuration: $($_.Exception.Message)" "NETWORK"
        return @()
    }
}

# === src\modules\Get-ProcessAnalysis.ps1 ===
# WindowsWorkstationAuditor - Process Analysis Module
# Version 1.3.0

function Get-ProcessAnalysis {
    <#
    .SYNOPSIS
        Analyzes running processes, services, and startup programs
        
    .DESCRIPTION
        Collects comprehensive process information including running processes,
        system services, startup programs, and identifies potential security risks
        based on process characteristics and known threat indicators.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (process enumeration, service access)
    #>
    
    Write-LogMessage "INFO" "Analyzing processes, services, and startup programs..." "PROCESS"
    
    try {
        $Results = @()
        
        # Get running processes with detailed information
        try {
            $Processes = Get-Process | Sort-Object CPU -Descending
            $ProcessCount = $Processes.Count
            $SystemProcesses = $Processes | Where-Object { $_.ProcessName -match "^(System|Registry|smss|csrss|wininit|winlogon|services|lsass|lsm|svchost|dwm|explorer)$" }
            $UserProcesses = $Processes | Where-Object { $_.ProcessName -notmatch "^(System|Registry|smss|csrss|wininit|winlogon|services|lsass|lsm|svchost|dwm|explorer)$" }
            
            $Results += [PSCustomObject]@{
                Category = "Processes"
                Item = "Process Summary"
                Value = "$ProcessCount total processes"
                Details = "System processes: $($SystemProcesses.Count), User processes: $($UserProcesses.Count)"
                RiskLevel = "INFO"
                Recommendation = ""
            }
            
            # Check for high CPU usage processes - header + detail format
            $HighCPUProcesses = $Processes | Where-Object { $_.CPU -gt 60 } | Select-Object -First 5
            if ($HighCPUProcesses.Count -gt 0) {
                $HighestCPU = $HighCPUProcesses | Sort-Object CPU -Descending | Select-Object -First 1
                $TopCPU = [math]::Round($HighestCPU.CPU, 2)
                $CPURisk = if ($TopCPU -gt 300) { "HIGH" } elseif ($TopCPU -gt 120) { "MEDIUM" } else { "LOW" }
                
                # Header entry with compliance message
                $Results += [PSCustomObject]@{
                    Category = "Processes"
                    Item = "High CPU Processes"
                    Value = "$($HighCPUProcesses.Count) processes detected"
                    Details = "Processes using significant CPU time may impact system performance"
                    RiskLevel = $CPURisk
                    Recommendation = if ($TopCPU -gt 180) { "Investigate high CPU usage processes for performance impact" } else { "" }
                }
                
                # Individual detail entries without compliance duplication
                foreach ($Process in $HighCPUProcesses) {
                    $ProcessName = $Process.ProcessName
                    $CPU = [math]::Round($Process.CPU, 2)
                    $Memory = [math]::Round($Process.WorkingSet64 / 1MB, 2)
                    $ProcessId = $Process.Id
                    
                    $Results += [PSCustomObject]@{
                        Category = "Processes"
                        Item = "High CPU Process"
                        Value = "$ProcessName (PID: $ProcessId)"
                        Details = "CPU: $CPU seconds, Memory: $Memory MB"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "INFO" "High CPU process: $ProcessName - CPU: $CPU seconds, Memory: $Memory MB" "PROCESS"
                }
            }
            
            Write-LogMessage "INFO" "Process analysis: $ProcessCount total, $($HighCPUProcesses.Count) high CPU" "PROCESS"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve process information: $($_.Exception.Message)" "PROCESS"
        }
        
        # Analyze system services
        try {
            $Services = Get-Service
            $RunningServices = $Services | Where-Object { $_.Status -eq "Running" }
            $StoppedServices = $Services | Where-Object { $_.Status -eq "Stopped" }
            $StartupServices = $Services | Where-Object { $_.StartType -eq "Automatic" }
            
            $Results += [PSCustomObject]@{
                Category = "Services"
                Item = "Service Summary"
                Value = "$($Services.Count) total services"
                Details = "Running: $($RunningServices.Count), Stopped: $($StoppedServices.Count), Auto-start: $($StartupServices.Count)"
                RiskLevel = "INFO"
                Recommendation = ""
            }
            
            # Check for critical security services
            $SecurityServices = @(
                @{Name = "Windows Defender Antivirus Service"; ServiceName = "WinDefend"},
                @{Name = "Windows Security Center"; ServiceName = "wscsvc"},
                @{Name = "Windows Firewall"; ServiceName = "MpsSvc"},
                @{Name = "Base Filtering Engine"; ServiceName = "BFE"},
                @{Name = "DNS Client"; ServiceName = "Dnscache"}
            )
            
            foreach ($SecurityService in $SecurityServices) {
                $ServiceName = $SecurityService.ServiceName
                $DisplayName = $SecurityService.Name
                $Service = $Services | Where-Object { $_.Name -eq $ServiceName }
                
                if ($Service) {
                    $ServiceStatus = $Service.Status
                    $ServiceRisk = if ($ServiceStatus -ne "Running") { "HIGH" } else { "LOW" }
                    $ServiceRecommendation = if ($ServiceStatus -ne "Running") {
                        "Critical security service should be running"
                    } else { "" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Services"
                        Item = "$DisplayName"
                        Value = $ServiceStatus
                        Details = "Critical security service ($ServiceName)"
                        RiskLevel = $ServiceRisk
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "INFO" "Security service $DisplayName`: $ServiceStatus" "PROCESS"
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Services"
                        Item = "$DisplayName"
                        Value = "Not Found"
                        Details = "Critical security service ($ServiceName) not found"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Security service not found - may indicate system compromise"
                    }
                    
                    Write-LogMessage "WARN" "Security service not found: $DisplayName" "PROCESS"
                }
            }
            
            Write-LogMessage "INFO" "Service analysis: $($Services.Count) total, $($RunningServices.Count) running" "PROCESS"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve service information: $($_.Exception.Message)" "PROCESS"
        }
        
        # Analyze startup programs
        try {
            # Check registry startup locations - system-wide and user-specific
            $StartupLocations = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            )
            
            # Add user-specific entries only if not running as SYSTEM
            if ($env:USERNAME -ne "SYSTEM") {
                $StartupLocations += @(
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                )
            } else {
                Write-LogMessage "INFO" "Running as SYSTEM - checking system-wide startup entries only" "PROCESS"
            }
            
            $StartupPrograms = @()
            foreach ($Location in $StartupLocations) {
                try {
                    $RegItems = Get-ItemProperty -Path $Location -ErrorAction SilentlyContinue
                    if ($RegItems) {
                        $RegItems.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                            $StartupPrograms += [PSCustomObject]@{
                                Name = $_.Name
                                Command = $_.Value
                                Location = $Location
                            }
                        }
                    }
                }
                catch {
                    Write-LogMessage "WARN" "Could not access startup location: $Location" "PROCESS"
                }
            }
            
            # Check startup folder (may be empty in system context)
            try {
                $StartupFolder = [System.Environment]::GetFolderPath("Startup")
                $CommonStartupFolder = [System.Environment]::GetFolderPath("CommonStartup")
                
                $StartupFiles = @()
                if ($StartupFolder -and (Test-Path $StartupFolder)) {
                    $StartupFiles += Get-ChildItem -Path $StartupFolder -File -ErrorAction SilentlyContinue
                }
                if ($CommonStartupFolder -and (Test-Path $CommonStartupFolder)) {
                    $StartupFiles += Get-ChildItem -Path $CommonStartupFolder -File -ErrorAction SilentlyContinue
                }
                
                foreach ($File in $StartupFiles) {
                    $StartupPrograms += [PSCustomObject]@{
                        Name = $File.Name
                        Command = $File.FullName
                        Location = "Startup Folder"
                    }
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not access startup folders: $($_.Exception.Message)" "PROCESS"
            }
            
            $StartupCount = $StartupPrograms.Count
            $StartupRisk = if ($StartupCount -gt 20) { "MEDIUM" } elseif ($StartupCount -gt 30) { "HIGH" } else { "LOW" }
            $StartupRecommendation = if ($StartupCount -gt 25) {
                "Large number of startup programs may impact boot time and security"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Startup"
                Item = "Startup Programs"
                Value = "$StartupCount programs configured"
                Details = "Registry entries and startup folder items"
                RiskLevel = $StartupRisk
                Recommendation = ""
            }
            
            # Check for startup entries from unusual locations
            $UnusualLocationStartup = $StartupPrograms | Where-Object {
                $_.Command -match "\\temp\\|\\tmp\\|\\appdata\\local\\temp\\|\\users\\public\\|\\downloads\\"
            }
            
            if ($UnusualLocationStartup.Count -gt 0) {
                foreach ($Unusual in ($UnusualLocationStartup | Select-Object -First 5)) {
                    $Results += [PSCustomObject]@{
                        Category = "Startup"
                        Item = "Startup from Unusual Location"
                        Value = $Unusual.Name
                        Details = "Running from: $($Unusual.Command). Programs should typically run from Program Files or system directories."
                        RiskLevel = "HIGH"
                        Recommendation = "Investigate startup programs from temporary or unusual locations"
                    }
                    
                    Write-LogMessage "WARN" "Startup from unusual location: $($Unusual.Name) - $($Unusual.Command)" "PROCESS"
                }
            }
            
            Write-LogMessage "INFO" "Startup analysis: $StartupCount programs, $($UnusualLocationStartup.Count) from unusual locations" "PROCESS"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve startup program information: $($_.Exception.Message)" "PROCESS"
        }
        
        # Check system performance and resource usage
        try {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem
            $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
            
            $TotalMemoryGB = [math]::Round($ComputerSystem.TotalPhysicalMemory / 1GB, 2)
            $FreeMemoryGB = [math]::Round($OS.FreePhysicalMemory / 1KB / 1MB, 2)
            $MemoryUsagePercent = [math]::Round((($TotalMemoryGB - $FreeMemoryGB) / $TotalMemoryGB) * 100, 1)
            
            $ProcessorCount = (Get-CimInstance -ClassName Win32_ComputerSystem).NumberOfLogicalProcessors
            $ProcessorUsage = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Processor | Where-Object { $_.Name -eq "_Total" }
            
            $Results += [PSCustomObject]@{
                Category = "Performance"
                Item = "System Resource Usage"
                Value = "Memory: $MemoryUsagePercent% used"
                Details = "Total RAM: $TotalMemoryGB GB, Processors: $ProcessorCount, Active processes: $ProcessCount"
                RiskLevel = if ($MemoryUsagePercent -gt 85) { "HIGH" } elseif ($MemoryUsagePercent -gt 75) { "MEDIUM" } else { "LOW" }
                Recommendation = if ($MemoryUsagePercent -gt 80) { "High memory usage may impact system performance" } else { "" }
            }
            
            Write-LogMessage "INFO" "System resources: $MemoryUsagePercent% memory used, $ProcessorCount processors" "PROCESS"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve system performance information: $($_.Exception.Message)" "PROCESS"
        }
        
        Write-LogMessage "SUCCESS" "Process analysis completed - $($Results.Count) items analyzed" "PROCESS"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze processes: $($_.Exception.Message)" "PROCESS"
        return @()
    }
}

# === src\modules\Get-EventLogAnalysis.ps1 ===
# WindowsWorkstationAuditor - Event Log Analysis Module
# Version 1.3.0

function Get-EventLogAnalysis {
    <#
    .SYNOPSIS
        Analyzes critical system events and security events from Windows Event Logs
        
    .DESCRIPTION
        Collects and analyzes Windows Event Logs for security-relevant events including
        logon failures, system errors, security policy changes, and other critical events
        that may indicate security issues or system problems.
        
        Performance optimized for servers with extensive log histories.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (Event Log read access)
        Performance: Limits analysis timeframe based on system type for optimal performance
    #>
    
    Write-LogMessage "INFO" "Analyzing Windows Event Logs for security events..." "EVENTLOG"
    
    try {
        $Results = @()
        
        # Auto-detect system type and get configuration settings
        try {
            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $IsServer = $OSInfo.ProductType -ne 1  # ProductType: 1=Workstation, 2=DC, 3=Server
        }
        catch {
            $IsServer = $false
        }
        
        # Get event log configuration from config (with fallback defaults)
        $EventLogConfig = $null
        if (Get-Variable -Name "Config" -Scope Global -ErrorAction SilentlyContinue) {
            $EventLogConfig = $Global:Config.settings.eventlog
        }
        
        # Set analysis timeframes based on configuration or intelligent defaults
        if ($EventLogConfig) {
            if ($IsServer) {
                $AnalysisDays = if ($EventLogConfig.analysis_days) { $EventLogConfig.analysis_days } else { 3 }
                $MaxEventsPerQuery = if ($EventLogConfig.max_events_per_query) { $EventLogConfig.max_events_per_query } else { 500 }
            } else {
                $AnalysisDays = if ($EventLogConfig.workstation_analysis_days) { $EventLogConfig.workstation_analysis_days } else { 7 }
                $MaxEventsPerQuery = if ($EventLogConfig.workstation_max_events) { $EventLogConfig.workstation_max_events } else { 1000 }
            }
            Write-LogMessage "INFO" "Using configured event log settings: $AnalysisDays days, max $MaxEventsPerQuery events" "EVENTLOG"
        } else {
            # Fallback to hardcoded defaults if no config available
            if ($IsServer) {
                $AnalysisDays = 3
                $MaxEventsPerQuery = 500
                Write-LogMessage "INFO" "Server detected - using default: 3 days, max 500 events (no config)" "EVENTLOG"
            } else {
                $AnalysisDays = 7
                $MaxEventsPerQuery = 1000
                Write-LogMessage "INFO" "Workstation detected - using default: 7 days, max 1000 events (no config)" "EVENTLOG"
            }
        }
        
        $AnalysisStartTime = (Get-Date).AddDays(-$AnalysisDays)
        
        $SystemType = if ($IsServer) { "Server" } else { "Workstation" }
        Write-LogMessage "INFO" "$SystemType detected - analyzing last $AnalysisDays days (max $MaxEventsPerQuery events per query)" "EVENTLOG"
        
        # Define critical event IDs to monitor
        $CriticalEvents = @{
            # High-priority security events only
            4625 = @{LogName = "Security"; Description = "Failed Logon"; RiskLevel = "MEDIUM"}
            4720 = @{LogName = "Security"; Description = "User Account Created"; RiskLevel = "MEDIUM"}
            4724 = @{LogName = "Security"; Description = "Password Reset Attempt"; RiskLevel = "MEDIUM"}
            4732 = @{LogName = "Security"; Description = "User Added to Security Group"; RiskLevel = "MEDIUM"}
            4740 = @{LogName = "Security"; Description = "User Account Locked"; RiskLevel = "HIGH"}
            4771 = @{LogName = "Security"; Description = "Kerberos Pre-auth Failed"; RiskLevel = "MEDIUM"}
            
            # Critical system events
            6008 = @{LogName = "System"; Description = "Unexpected System Shutdown"; RiskLevel = "HIGH"}
            7034 = @{LogName = "System"; Description = "Service Crashed"; RiskLevel = "MEDIUM"}
            
            # Application stability events
            1000 = @{LogName = "Application"; Description = "Application Error"; RiskLevel = "MEDIUM"}
        }
        
        # Get event log summary information
        try {
            $EventLogs = Get-EventLog -List
            $SecurityLog = $EventLogs | Where-Object { $_.LogDisplayName -eq "Security" }
            $SystemLog = $EventLogs | Where-Object { $_.LogDisplayName -eq "System" }
            $ApplicationLog = $EventLogs | Where-Object { $_.LogDisplayName -eq "Application" }
            
            if ($SecurityLog) {
                $SecurityLogSize = [math]::Round($SecurityLog.FileSize / 1MB, 2)
                $SecurityMaxSize = [math]::Round($SecurityLog.MaximumKilobytes / 1024, 2)
                $SecurityUsagePercent = [math]::Round(($SecurityLogSize / $SecurityMaxSize) * 100, 1)
                
                $SecurityRisk = if ($SecurityUsagePercent -gt 90) { "HIGH" } elseif ($SecurityUsagePercent -gt 75) { "MEDIUM" } else { "LOW" }
                $SecurityRecommendation = if ($SecurityUsagePercent -gt 85) {
                    "Security event log approaching capacity - consider archiving"
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Event Logs"
                    Item = "Security Log Status"
                    Value = "$SecurityUsagePercent% full"
                    Details = "Size: $SecurityLogSize MB / $SecurityMaxSize MB, Entry count available via event queries"
                    RiskLevel = $SecurityRisk
                    Recommendation = $SecurityRecommendation
                }
                
                Write-LogMessage "INFO" "Security log: $SecurityUsagePercent% full ($SecurityLogSize MB / $SecurityMaxSize MB)" "EVENTLOG"
            }
            
            if ($SystemLog) {
                $SystemLogSize = [math]::Round($SystemLog.FileSize / 1MB, 2)
                $SystemMaxSize = [math]::Round($SystemLog.MaximumKilobytes / 1024, 2)
                $SystemUsagePercent = [math]::Round(($SystemLogSize / $SystemMaxSize) * 100, 1)
                
                $Results += [PSCustomObject]@{
                    Category = "Event Logs"
                    Item = "System Log Status"
                    Value = "$SystemUsagePercent% full"
                    Details = "Size: $SystemLogSize MB / $SystemMaxSize MB, Entry count available via event queries"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "System log: $SystemUsagePercent% full ($SystemLogSize MB / $SystemMaxSize MB)" "EVENTLOG"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve event log summary: $($_.Exception.Message)" "EVENTLOG"
        }
        
        # Analyze critical security events
        foreach ($EventID in $CriticalEvents.Keys) {
            $EventInfo = $CriticalEvents[$EventID]
            $LogName = $EventInfo.LogName
            $Description = $EventInfo.Description
            $BaseRiskLevel = $EventInfo.RiskLevel
            
            try {
                Write-LogMessage "INFO" "Checking for Event ID $EventID ($Description) in $LogName log..." "EVENTLOG"
                
                # Performance-limited event query
                $Events = Get-EventLog -LogName $LogName -After $AnalysisStartTime -InstanceId $EventID -Newest $MaxEventsPerQuery -ErrorAction SilentlyContinue
                
                if ($Events) {
                    $EventCount = $Events.Count
                    $MostRecent = $Events | Sort-Object TimeGenerated -Descending | Select-Object -First 1
                    $MostRecentTime = $MostRecent.TimeGenerated
                    
                    # Determine risk level based on event type and frequency
                    $RiskLevel = $BaseRiskLevel
                    $Recommendation = ""
                    
                    # Special handling for high-frequency events
                    if ($EventID -eq 4625 -and $EventCount -gt 50) {  # Multiple failed logons
                        $RiskLevel = "HIGH"
                        $Recommendation = "Investigate multiple failed logon attempts - possible brute force attack"
                    }
                    elseif ($EventID -eq 4740 -and $EventCount -gt 5) {  # Multiple account lockouts
                        $RiskLevel = "HIGH"
                        $Recommendation = "Multiple account lockouts may indicate attack or policy issues"
                    }
                    elseif ($EventID -eq 6008 -and $EventCount -gt 3) {  # Multiple unexpected shutdowns
                        $RiskLevel = "HIGH"
                        $Recommendation = "Multiple unexpected shutdowns may indicate system instability"
                    }
                    elseif ($EventID -eq 7034 -and $EventCount -gt 10) {  # Multiple service crashes
                        $RiskLevel = "HIGH"
                        $Recommendation = "Multiple service crashes may indicate system problems"
                    }
                    elseif ($EventID -eq 4625) {
                        $Recommendation = "Monitor failed logon attempts for security threats"
                    }
                    elseif ($EventID -eq 4672) {
                        $Recommendation = "Monitor special privilege assignments for unauthorized elevation"
                    }
                    
                    # Dynamic timeframe display using configured values
                    $TimeframeDays = "$AnalysisDays days"
                    $EventCountDisplay = if ($EventCount -eq $MaxEventsPerQuery) { "$EventCount+ events" } else { "$EventCount events" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Security Events"
                        Item = $Description
                        Value = "$EventCountDisplay ($TimeframeDays)"
                        Details = "Event ID: $EventID, Most recent: $MostRecentTime"
                        RiskLevel = $RiskLevel
                        Recommendation = $Recommendation
                    }
                    
                    Write-LogMessage "INFO" "Event ID $EventID`: $EventCount events found, most recent: $MostRecentTime" "EVENTLOG"
                }
                else {
                    # Only report absence of critical security events, not routine events
                    if ($EventID -in @(4625, 4740)) {
                        Write-LogMessage "INFO" "Event ID $EventID`: No events found (good)" "EVENTLOG"
                    }
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not query Event ID $EventID in $LogName log: $($_.Exception.Message)" "EVENTLOG"
            }
        }
        
        # Check for Windows Defender events (performance limited)
        try {
            $DefenderEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Windows Defender/Operational"; StartTime=$AnalysisStartTime} -MaxEvents $MaxEventsPerQuery -ErrorAction SilentlyContinue
            
            if ($DefenderEvents) {
                $ThreatEvents = $DefenderEvents | Where-Object { $_.Id -in @(1006, 1007, 1008, 1009, 1116, 1117) }
                $ScanEvents = $DefenderEvents | Where-Object { $_.Id -in @(1000, 1001, 1002) }
                
                # Use dynamic timeframe for display
                $TimeframeDays = "$AnalysisDays days"
                
                if ($ThreatEvents) {
                    $ThreatCount = $ThreatEvents.Count
                    $Results += [PSCustomObject]@{
                        Category = "Security Events"
                        Item = "Windows Defender Threats"
                        Value = "$ThreatCount threats detected"
                        Details = "Threat detection events in last $TimeframeDays"
                        RiskLevel = "HIGH"
                        Recommendation = "Investigate and remediate detected security threats"
                    }
                    Write-LogMessage "WARN" "Windows Defender: $ThreatCount threats detected in last $TimeframeDays" "EVENTLOG"
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Security Events"
                        Item = "Windows Defender Threats"
                        Value = "0 threats detected"
                        Details = "No threat detection events in last $TimeframeDays"
                        RiskLevel = "LOW"
                        Recommendation = ""
                    }
                }
                
                if ($ScanEvents) {
                    $ScanCount = $ScanEvents.Count
                    $Results += [PSCustomObject]@{
                        Category = "Security Events"
                        Item = "Windows Defender Scans"
                        Value = "$ScanCount scans performed"
                        Details = "Antivirus scan events in last $TimeframeDays"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                    Write-LogMessage "INFO" "Windows Defender: $ScanCount scans performed in last $TimeframeDays" "EVENTLOG"
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve Windows Defender events: $($_.Exception.Message)" "EVENTLOG"
        }
        
        # Check for PowerShell execution events (potential security concern)
        try {
            $PowerShellEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; StartTime=$AnalysisStartTime; Id=4103,4104} -ErrorAction SilentlyContinue
            
            if ($PowerShellEvents) {
                $PSEventCount = $PowerShellEvents.Count
                $SuspiciousPS = $PowerShellEvents | Where-Object { 
                    $_.Message -match "Invoke-|Download|WebClient|System.Net|Base64|Encode|Hidden|Bypass|ExecutionPolicy" 
                }
                
                $PSRisk = if ($SuspiciousPS.Count -gt 0) { "HIGH" } elseif ($PSEventCount -gt 100) { "MEDIUM" } else { "LOW" }
                $PSRecommendation = if ($SuspiciousPS.Count -gt 0) {
                    "Investigate suspicious PowerShell execution patterns"
                } elseif ($PSEventCount -gt 100) {
                    "High PowerShell usage - review for legitimate business needs"
                } else { "" }
                
                # Build detailed suspicious patterns description
                $SuspiciousPatterns = @()
                if ($SuspiciousPS.Count -gt 0) {
                    $PatternCounts = @{}
                    foreach ($Event in $SuspiciousPS) {
                        if ($Event.Message -match "Invoke-") { $PatternCounts["Invoke Commands"]++ }
                        if ($Event.Message -match "Download|WebClient|System.Net") { $PatternCounts["Network Downloads"]++ }
                        if ($Event.Message -match "Base64|Encode") { $PatternCounts["Encoding/Obfuscation"]++ }
                        if ($Event.Message -match "Hidden|Bypass|ExecutionPolicy") { $PatternCounts["Policy Bypass"]++ }
                    }
                    
                    foreach ($Pattern in $PatternCounts.Keys) {
                        $SuspiciousPatterns += "$Pattern ($($PatternCounts[$Pattern]))"
                    }
                }
                
                $PatternDetails = if ($SuspiciousPatterns.Count -gt 0) {
                    "Suspicious patterns detected: " + ($SuspiciousPatterns -join ", ")
                } else {
                    "No suspicious patterns detected in PowerShell executions"
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Security Events"
                    Item = "PowerShell Execution"
                    Value = "$PSEventCount executions (7 days)"
                    Details = "$PatternDetails. Total suspicious events: $($SuspiciousPS.Count)"
                    RiskLevel = $PSRisk
                    Recommendation = $PSRecommendation
                }
                
                # Add raw PowerShell events to data collection for detailed analysis
                if ($SuspiciousPS.Count -gt 0) {
                    $PSEventDetails = @()
                    foreach ($Event in ($SuspiciousPS | Select-Object -First 10)) {
                        $PSEventDetails += [PSCustomObject]@{
                            TimeGenerated = $Event.TimeCreated
                            EventId = $Event.Id
                            Message = $Event.Message.Substring(0, [Math]::Min(500, $Event.Message.Length))
                            ProcessId = $Event.ProcessId
                            UserId = $Event.UserId
                        }
                    }
                    Add-RawDataCollection -CollectionName "SuspiciousPowerShellEvents" -Data $PSEventDetails
                }
                
                Write-LogMessage "INFO" "PowerShell events: $PSEventCount total, $($SuspiciousPS.Count) suspicious" "EVENTLOG"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve PowerShell events: $($_.Exception.Message)" "EVENTLOG"
        }
        
        # Check for USB device insertion events
        try {
            $USBEvents = Get-WinEvent -FilterHashtable @{LogName="System"; StartTime=$AnalysisStartTime; Id=20001,20003} -ErrorAction SilentlyContinue
            
            if ($USBEvents) {
                $USBCount = $USBEvents.Count
                $USBRisk = if ($USBCount -gt 20) { "MEDIUM" } else { "LOW" }
                $USBRecommendation = if ($USBCount -gt 10) {
                    "Monitor USB device usage for data loss prevention"
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Security Events"
                    Item = "USB Device Activity"
                    Value = "$USBCount USB events (7 days)"
                    Details = "USB device insertion/removal events"
                    RiskLevel = $USBRisk
                    Recommendation = $USBRecommendation
                }
                
                Write-LogMessage "INFO" "USB events: $USBCount device events in last 7 days" "EVENTLOG"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve USB device events: $($_.Exception.Message)" "EVENTLOG"
        }
        
        Write-LogMessage "SUCCESS" "Event log analysis completed - $($Results.Count) items analyzed" "EVENTLOG"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze event logs: $($_.Exception.Message)" "EVENTLOG"
        return @()
    }
}
# Configuration embedded from workstation-audit-config.json at build time
$Config = @{
    version = "1.3.0"
    settings = @{
        collect_browser_data = $False
        collect_startup_programs = $True
        collect_user_folders = $False
        max_processes = 200
        max_services = 300
        eventlog = @{
            analysis_days = 7
            max_events_per_query = 1000
            server_analysis_days = 3
            server_max_events = 500
        }
    }
    output = @{
        formats = @("markdown", "rawjson")
        path = $OutputPath
        timestamp = $true
    }
}

# Main execution
try {
    Write-LogMessage "INFO" "WindowsWorkstationAuditor Web v1.3.0 starting..." "MAIN"
    Write-LogMessage "INFO" "Output directory: $OutputPath" "MAIN"
    
    $AllResults = @()
    $AuditModuleNames = @(
        "Get-SystemInformation", "Get-UserAccountAnalysis", "Get-SoftwareInventory",
        "Get-SecuritySettings", "Get-PatchStatus", "Get-PolicyAnalysis",
        "Get-DiskSpaceAnalysis", "Get-MemoryAnalysis", "Get-PrinterAnalysis", 
        "Get-NetworkAnalysis", "Get-ProcessAnalysis", "Get-EventLogAnalysis"
    )
    
    foreach ($ModuleName in $AuditModuleNames) {
        try {
            Write-LogMessage "INFO" "Executing: $ModuleName" "AUDIT"
            $StartTime = Get-Date
            $Results = & $ModuleName
            $Duration = ((Get-Date) - $StartTime).TotalSeconds
            
            if ($Results -and $Results.Count -gt 0) {
                $AllResults += $Results
                Write-LogMessage "SUCCESS" "$ModuleName completed in $([math]::Round($Duration, 2))s - $($Results.Count) results" "AUDIT"
            } else {
                Write-LogMessage "WARN" "$ModuleName returned no results" "AUDIT"
            }
        }
        catch {
            Write-LogMessage "ERROR" "$ModuleName failed: $($_.Exception.Message)" "AUDIT"
        }
    }
    
    if ($AllResults.Count -gt 0) {
        Write-LogMessage "SUCCESS" "Collected $($AllResults.Count) audit results" "MAIN"
        
        # Export results
        if ($Config.output.formats -contains "markdown") {
            Export-MarkdownReport -Results $AllResults -OutputPath $OutputPath -BaseFileName $Script:BaseFileName
        }
        
        if ($Config.output.formats -contains "rawjson") {
            Export-RawDataJSON -Results $AllResults -OutputPath $OutputPath -BaseFileName $Script:BaseFileName
        }
        
        Write-LogMessage "SUCCESS" "Audit completed - check $OutputPath for results" "MAIN"
    } else {
        Write-LogMessage "ERROR" "No audit results collected" "MAIN"
    }
}
catch {
    Write-LogMessage "ERROR" "Audit failed: $($_.Exception.Message)" "MAIN"
}

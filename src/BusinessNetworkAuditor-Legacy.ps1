# BusinessNetworkAuditor - Windows Workstation Security Audit Tool
# Version 1.3.0
# Requires: PowerShell 5.0+, Local Administrator Rights

param(
    [string]$OutputPath = ".\output",
    [string]$ConfigPath = ".\config",
    [switch]$Verbose
)

# Global variables
$Script:LogFile = ""
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:BaseFileName = "${ComputerName}_$($StartTime.ToString('yyyyMMdd_HHmmss'))"

# Initialize logging system
function Initialize-Logging {
    $LogDirectory = Join-Path $OutputPath "logs"
    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    
    $Script:LogFile = Join-Path $LogDirectory "${Script:BaseFileName}_audit.log"
    
    Write-LogMessage "INFO" "Business Network Auditor v1.3.0 Started"
    Write-LogMessage "INFO" "Computer: $ComputerName"
    Write-LogMessage "INFO" "User: $env:USERNAME"
    Write-LogMessage "INFO" "Base filename: $Script:BaseFileName"
}

# Centralized logging function
function Write-LogMessage {
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

# System Information Collector with Azure Tenant, MDM, and WSUS Detection
function Get-SystemInformation {
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
            Compliance = ""
        }
        
        # Hardware Info
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "Hardware"
            Value = "$($Computer.Manufacturer) $($Computer.Model)"
            Details = "RAM: $([math]::Round($Computer.TotalPhysicalMemory/1GB, 2))GB, Processors: $($Computer.NumberOfProcessors)"
            RiskLevel = "INFO"
            Compliance = ""
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
            Compliance = if (-not $AzureADJoined -and -not $DomainJoined) { "NIST: Consider domain or Azure AD joining for centralized management" } else { "" }
        }
        
        # WSUS Configuration Status
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "WSUS Configuration"
            Value = if ($WSUSConfigured) { "Configured" } else { "Not Configured" }
            Details = if ($WSUSConfigured) { "Server: $WSUSServer" } else { "Using Microsoft Update directly" }
            RiskLevel = "INFO"
            Compliance = ""
        }
        
        # MDM Enrollment Status (only for Azure AD joined systems)
        if ($AzureADJoined) {
            $Results += [PSCustomObject]@{
                Category = "System"
                Item = "MDM Enrollment"
                Value = if ($MDMEnrolled) { "Enrolled" } else { "Not Enrolled" }
                Details = if ($MDMEnrolled) { "Device enrolled in Mobile Device Management" } else { "Device not enrolled in MDM" }
                RiskLevel = if ($MDMEnrolled) { "LOW" } else { "MEDIUM" }
                Compliance = if (-not $MDMEnrolled) { "NIST: Consider MDM enrollment for device management" } else { "" }
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

# User Account Analysis with Azure AD support
function Get-UserAccountAnalysis {
    Write-LogMessage "INFO" "Analyzing user accounts..." "USERS"
    
    try {
        $LocalAdmins = @()
        
        Write-LogMessage "INFO" "Current user: $env:USERNAME" "USERS"
        
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
        
        # Get local users for Guest account check
        $LocalUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True"
        
        $Results = @()
        
        # Local Administrator Count
        $AdminCount = $LocalAdmins.Count
        Write-LogMessage "SUCCESS" "Administrator count: $AdminCount" "USERS"
        $Results += [PSCustomObject]@{
            Category = "Users"
            Item = "Local Administrators"
            Value = $AdminCount
            Details = "Users: $($LocalAdmins -join ', ')"
            RiskLevel = if ($AdminCount -gt 3) { "HIGH" } elseif ($AdminCount -gt 1) { "MEDIUM" } else { "LOW" }
            Compliance = if ($AdminCount -gt 3) { "NIST: Limit administrative access" } else { "" }
        }
        
        # Guest Account Status
        $GuestAccount = $LocalUsers | Where-Object { $_.Name -eq "Guest" }
        if ($GuestAccount) {
            $Results += [PSCustomObject]@{
                Category = "Users"
                Item = "Guest Account"
                Value = if ($GuestAccount.Disabled) { "Disabled" } else { "Enabled" }
                Details = "Guest account status"
                RiskLevel = if ($GuestAccount.Disabled) { "LOW" } else { "HIGH" }
                Compliance = if (-not $GuestAccount.Disabled) { "NIST/HIPAA: Disable guest account" } else { "" }
            }
        }
        
        Write-LogMessage "SUCCESS" "User account analysis completed - Found $AdminCount administrators" "USERS"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze user accounts: $($_.Exception.Message)" "USERS"
        return @()
    }
}

# Software Inventory Collection
function Get-SoftwareInventory {
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
            Compliance = ""
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
                    Compliance = if ($AgeInDays -gt 365) { "NIST: Regular software updates required" } else { "" }
                }
            }
        }
        
        Write-LogMessage "SUCCESS" "Software inventory completed - $($AllSoftware.Count) programs found" "SOFTWARE"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to collect software inventory: $($_.Exception.Message)" "SOFTWARE"
        return @()
    }
}

# Security Settings Analysis
function Get-SecuritySettings {
    Write-LogMessage "INFO" "Analyzing security settings..." "SECURITY"
    
    try {
        $Results = @()
        
        # Windows Defender Status
        try {
            $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Anti-virus Status"
                Value = if ($DefenderStatus.AntivirusEnabled) { "Enabled" } else { "Disabled" }
                Details = "Real-time: $($DefenderStatus.RealTimeProtectionEnabled), Definitions: $($DefenderStatus.AntivirusSignatureLastUpdated)"
                RiskLevel = if ($DefenderStatus.AntivirusEnabled) { "LOW" } else { "HIGH" }
                Compliance = if (-not $DefenderStatus.AntivirusEnabled) { "NIST/HIPAA: Antivirus protection required" } else { "" }
            }
        }
        catch {
            # Check for third-party antivirus via WMI
            try {
                $AntiVirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
                if ($AntiVirusProducts) {
                    foreach ($AV in $AntiVirusProducts) {
                        $Results += [PSCustomObject]@{
                            Category = "Security"
                            Item = "Anti-virus Status"
                            Value = $AV.displayName
                            Details = "Third-party antivirus detected"
                            RiskLevel = "LOW"
                            Compliance = ""
                        }
                    }
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Security"
                        Item = "Anti-virus Status"
                        Value = "None detected"
                        Details = "No antivirus protection found"
                        RiskLevel = "HIGH"
                        Compliance = "NIST/HIPAA: Antivirus protection required"
                    }
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    Category = "Security"
                    Item = "Anti-virus Status"
                    Value = "Unknown"
                    Details = "Could not retrieve status"
                    RiskLevel = "MEDIUM"
                    Compliance = "Verify antivirus protection"
                }
            }
        }
        
        # Windows Firewall Status
        $FirewallProfiles = Get-NetFirewallProfile
        foreach ($Profile in $FirewallProfiles) {
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Firewall - $($Profile.Name)"
                Value = if ($Profile.Enabled) { "Enabled" } else { "Disabled" }
                Details = "Default action: Inbound=$($Profile.DefaultInboundAction), Outbound=$($Profile.DefaultOutboundAction)"
                RiskLevel = if ($Profile.Enabled) { "LOW" } else { "HIGH" }
                Compliance = if (-not $Profile.Enabled) { "NIST: Enable firewall protection" } else { "" }
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
            Compliance = if (-not $UACKey.EnableLUA) { "NIST: Enable UAC for privilege escalation control" } else { "" }
        }
        
        Write-LogMessage "SUCCESS" "Security settings analysis completed" "SECURITY"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze security settings: $($_.Exception.Message)" "SECURITY"
        return @()
    }
}

# Patch Status Analysis with InProgress update detection
function Get-PatchStatus {
    Write-LogMessage "INFO" "Analyzing patch status with InProgress detection..." "PATCHES"
    
    try {
        $Results = @()
        
        # Install PSWindowsUpdate if needed
        $PSWUAvailable = $false
        try {
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Write-LogMessage "INFO" "Installing PSWindowsUpdate module..." "PATCHES"
                Set-ExecutionPolicy RemoteSigned -Scope Process -Force
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Install-Module PSWindowsUpdate -Force -Scope CurrentUser -SkipPublisherCheck
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
                    Compliance = if ($CriticalInProgress.Count -gt 0) { "CRITICAL: Restart required for critical updates" } elseif ($InProgressUpdates.Count -gt 0) { "NIST: Restart required to complete updates" } else { "" }
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
                        Compliance = "IMMEDIATE: Restart to complete critical security updates"
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
                        Compliance = "NIST: Restart system to complete update installation"
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
                        Compliance = "NIST: Install available updates within 30 days"
                    }
                }
                
                Write-LogMessage "SUCCESS" "Patch analysis complete - Available: $($AvailableUpdates.Count), InProgress: $($InProgressUpdates.Count), Critical InProgress: $($CriticalInProgress.Count)" "PATCHES"
                
            }
            catch {
                Write-LogMessage "ERROR" "PSWindowsUpdate patch analysis failed: $($_.Exception.Message)" "PATCHES"
            }
        } else {
            # Fallback method without PSWindowsUpdate
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Update Status"
                Value = "Detection Failed"
                Details = "PSWindowsUpdate module could not be loaded"
                RiskLevel = "HIGH"
                Compliance = "CRITICAL: Cannot verify patch status"
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
                Compliance = if ($RecentHotfixes.Count -eq 0) { "NIST: No recent patches detected - verify update process" } else { "" }
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
                Compliance = "Verify patch installation history"
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
                Compliance = if ($UptimeDays -gt 30) { "NIST: Consider regular restarts for patch application" } else { "" }
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
                Compliance = if ($UpdateService.Status -ne "Running" -and $UpdateService.StartType -eq "Disabled") { "NIST: Windows Update service should not be permanently disabled" } else { "" }
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
                Compliance = "Verify Windows Update service configuration"
            }
        }
        
        # Automatic Updates configuration
        try {
            $AutoUpdateConfig = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue
            if ($AutoUpdateConfig) {
                $AUOptions = switch ($AutoUpdateConfig.AUOptions) {
                    1 { "Keep my computer up to date is disabled" }
                    2 { "Notify before downloading" }
                    3 { "Notify before installing" }
                    4 { "Install automatically" }
                    5 { "Allow users to choose setting" }
                    default { "Unknown configuration" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Patches"
                    Item = "Automatic Updates"
                    Value = $AUOptions
                    Details = "Registry AUOptions: $($AutoUpdateConfig.AUOptions)"
                    RiskLevel = if ($AutoUpdateConfig.AUOptions -in @(3,4)) { "LOW" } elseif ($AutoUpdateConfig.AUOptions -eq 2) { "MEDIUM" } else { "HIGH" }
                    Compliance = if ($AutoUpdateConfig.AUOptions -eq 1) { "NIST: Automatic updates should be enabled" } else { "" }
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Patches"
                    Item = "Automatic Updates"
                    Value = "Default/Managed"
                    Details = "Using default Windows Update settings or managed by policy"
                    RiskLevel = "LOW"
                    Compliance = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check automatic update configuration: $($_.Exception.Message)" "PATCHES"
        }
        
        Write-LogMessage "SUCCESS" "Patch status analysis completed" "PATCHES"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze patch status: $($_.Exception.Message)" "PATCHES"
        return @()
    }
}

# Policy Analysis - Group Policy, Local Policy, Audit Policy, and Security Settings
function Get-PolicyAnalysis {
    Write-LogMessage "INFO" "Analyzing security policies and settings..." "POLICY"
    
    try {
        $Results = @()
        
        # Group Policy Detection and Analysis
        Write-LogMessage "INFO" "Checking Group Policy configuration..." "POLICY"
        try {
            # Check if computer is domain-joined and has GP applied
            $GPResult = & gpresult /r /scope:computer 2>$null
            if ($LASTEXITCODE -eq 0) {
                # Parse GP result for applied policies
                $GPOLines = $GPResult | Where-Object { $_ -match "Applied Group Policy Objects" -or $_ -match "The following GPOs were not applied" }
                $HasGPO = $GPResult | Where-Object { $_ -match "Applied Group Policy Objects" }
                
                if ($HasGPO) {
                    # Extract applied GPOs
                    $AppliedGPOs = @()
                    $InGPOSection = $false
                    foreach ($Line in $GPResult) {
                        if ($Line -match "Applied Group Policy Objects") {
                            $InGPOSection = $true
                            continue
                        }
                        if ($Line -match "The following GPOs were not applied" -or $Line -match "The computer is a part of the following security groups") {
                            $InGPOSection = $false
                            continue
                        }
                        if ($InGPOSection -and $Line.Trim() -ne "" -and $Line -notmatch "^-+$") {
                            $AppliedGPOs += $Line.Trim()
                        }
                    }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "Group Policy Objects"
                        Value = "$($AppliedGPOs.Count) GPOs Applied"
                        Details = "Applied GPOs: $($AppliedGPOs -join '; ')"
                        RiskLevel = "LOW"
                        Compliance = ""
                    }
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "Group Policy Objects"
                        Value = "No GPOs Applied"
                        Details = "Computer may not be receiving domain policies"
                        RiskLevel = "MEDIUM"
                        Compliance = "Consider centralized policy management"
                    }
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Group Policy Objects"
                    Value = "Not Available"
                    Details = "Unable to retrieve Group Policy information"
                    RiskLevel = "LOW"
                    Compliance = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check Group Policy status: $($_.Exception.Message)" "POLICY"
        }
        
        # Local Security Policy Analysis using secedit
        Write-LogMessage "INFO" "Analyzing local security policies..." "POLICY"
        try {
            $TempSecPol = "$env:TEMP\secpol.cfg"
            $SecEditResult = & secedit /export /cfg $TempSecPol /quiet 2>$null
            
            if (Test-Path $TempSecPol) {
                $SecPolContent = Get-Content $TempSecPol
                
                # Password Policy Analysis
                $MinPasswordLength = ($SecPolContent | Where-Object { $_ -match "MinimumPasswordLength" }).Split('=')[1].Trim()
                $PasswordComplexity = ($SecPolContent | Where-Object { $_ -match "PasswordComplexity" }).Split('=')[1].Trim()
                $MaxPasswordAge = ($SecPolContent | Where-Object { $_ -match "MaximumPasswordAge" }).Split('=')[1].Trim()
                $MinPasswordAge = ($SecPolContent | Where-Object { $_ -match "MinimumPasswordAge" }).Split('=')[1].Trim()
                $PasswordHistorySize = ($SecPolContent | Where-Object { $_ -match "PasswordHistorySize" }).Split('=')[1].Trim()
                
                # Account Lockout Policy
                $LockoutThreshold = ($SecPolContent | Where-Object { $_ -match "LockoutBadCount" }).Split('=')[1].Trim()
                $LockoutDuration = ($SecPolContent | Where-Object { $_ -match "LockoutDuration" }).Split('=')[1].Trim()
                $ResetLockoutCounter = ($SecPolContent | Where-Object { $_ -match "ResetLockoutCount" }).Split('=')[1].Trim()
                
                # Password Policy Results
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password Length Requirement"
                    Value = if ($MinPasswordLength) { "$MinPasswordLength characters" } else { "Not configured" }
                    Details = "Minimum password length policy"
                    RiskLevel = if ([int]$MinPasswordLength -ge 12) { "LOW" } elseif ([int]$MinPasswordLength -ge 8) { "MEDIUM" } else { "HIGH" }
                    Compliance = if ([int]$MinPasswordLength -lt 8) { "NIST: Minimum 8 characters required" } elseif ([int]$MinPasswordLength -lt 12) { "NIST: Consider 12+ characters for enhanced security" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password Complexity"
                    Value = if ($PasswordComplexity -eq "1") { "Enabled" } else { "Disabled" }
                    Details = "Requires uppercase, lowercase, numbers, and symbols"
                    RiskLevel = if ($PasswordComplexity -eq "1") { "LOW" } else { "HIGH" }
                    Compliance = if ($PasswordComplexity -ne "1") { "NIST: Enable password complexity requirements" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password History"
                    Value = if ($PasswordHistorySize) { "$PasswordHistorySize passwords remembered" } else { "Not configured" }
                    Details = "Prevents password reuse"
                    RiskLevel = if ([int]$PasswordHistorySize -ge 12) { "LOW" } elseif ([int]$PasswordHistorySize -ge 5) { "MEDIUM" } else { "HIGH" }
                    Compliance = if ([int]$PasswordHistorySize -lt 12) { "NIST: Remember last 12 passwords minimum" } else { "" }
                }
                
                # Account Lockout Policy Results
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Account Lockout Threshold"
                    Value = if ($LockoutThreshold -and $LockoutThreshold -ne "0") { "$LockoutThreshold invalid attempts" } else { "No lockout policy" }
                    Details = "Failed logon attempts before lockout"
                    RiskLevel = if ($LockoutThreshold -and [int]$LockoutThreshold -le 10 -and [int]$LockoutThreshold -gt 0) { "LOW" } elseif ($LockoutThreshold -eq "0") { "HIGH" } else { "MEDIUM" }
                    Compliance = if ($LockoutThreshold -eq "0") { "NIST: Configure account lockout policy" } else { "" }
                }
                
                if ($LockoutThreshold -and $LockoutThreshold -ne "0") {
                    $LockoutDurationMinutes = if ($LockoutDuration) { [math]::Round([int]$LockoutDuration / 60) } else { 0 }
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "Account Lockout Duration"
                        Value = if ($LockoutDuration -eq "-1") { "Until admin unlocks" } else { "$LockoutDurationMinutes minutes" }
                        Details = "How long accounts remain locked"
                        RiskLevel = if ($LockoutDuration -eq "-1" -or $LockoutDurationMinutes -ge 15) { "LOW" } else { "MEDIUM" }
                        Compliance = ""
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
            # Check screen saver settings
            $ScreenSaveActive = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
            $ScreenSaveTimeOut = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
            $ScreenSaverIsSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
            
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
                    Compliance = if (-not $IsSecure) { "NIST: Enable secure screen saver" } elseif ($TimeoutMinutes -gt 15) { "NIST: Screen lock timeout should be 15 minutes or less" } else { "" }
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Screen Lock Policy"
                    Value = "Disabled"
                    Details = "No automatic screen lock configured"
                    RiskLevel = "HIGH"
                    Compliance = "NIST: Configure automatic screen lock"
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
                    Compliance = if ($EnabledAudits -lt $TotalAudits) { "NIST: Enable comprehensive audit logging" } else { "" }
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
                
                # Check critical rights
                $LogonAsService = ($UserRightsContent | Where-Object { $_ -match "SeServiceLogonRight" }).Split('=')[1]
                $LogonLocally = ($UserRightsContent | Where-Object { $_ -match "SeInteractiveLogonRight" }).Split('=')[1]
                $ShutdownSystem = ($UserRightsContent | Where-Object { $_ -match "SeShutdownPrivilege" }).Split('=')[1]
                
                # Check for overly permissive rights
                $DangerousRights = @()
                if ($LogonAsService -and $LogonAsService -match "Everyone|Users") {
                    $DangerousRights += "Service logon rights too broad"
                }
                if ($ShutdownSystem -and $ShutdownSystem -match "Everyone") {
                    $DangerousRights += "Shutdown rights too broad"
                }
                
                if ($DangerousRights.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "User Rights Assignment"
                        Value = "Review Required"
                        Details = $DangerousRights -join "; "
                        RiskLevel = "MEDIUM"
                        Compliance = "NIST: Review user rights assignments for least privilege"
                    }
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "User Rights Assignment"
                        Value = "Appropriately Configured"
                        Details = "No overly permissive rights detected"
                        RiskLevel = "LOW"
                        Compliance = ""
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
                    Compliance = "NIST: Ensure antivirus protection is enabled unless replaced by third-party solution"
                }
            } elseif ($DefenderRealTime -and $DefenderRealTime.DisableRealtimeMonitoring -eq 1) {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Windows Defender Policy"
                    Value = "Real-time Protection Disabled"
                    Details = "Real-time protection disabled by policy"
                    RiskLevel = "HIGH"
                    Compliance = "NIST: Enable real-time antivirus protection"
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Windows Defender Policy"
                    Value = "Not Restricted"
                    Details = "No policy restrictions on Windows Defender"
                    RiskLevel = "LOW"
                    Compliance = ""
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

# Main execution function
function Start-Audit {
    Write-LogMessage "INFO" "Starting Business Network Audit..." "MAIN"
    
    $AllResults = @()
    
    # Run all audit functions
    $AllResults += Get-SystemInformation
    $AllResults += Get-UserAccountAnalysis  
    $AllResults += Get-SoftwareInventory
    $AllResults += Get-SecuritySettings
    $AllResults += Get-PatchStatus
    $AllResults += Get-PolicyAnalysis
    
    # Output results to console
    Write-LogMessage "INFO" "Audit Results Summary:" "MAIN"
    foreach ($Result in $AllResults) {
        $ColorCode = switch ($Result.RiskLevel) {
            "HIGH" { "Red" }
            "MEDIUM" { "Yellow" }
            "LOW" { "Green" }
            default { "White" }
        }
        
        $OutputLine = "$($Result.Category) - $($Result.Item): $($Result.Value)"
        Write-Host $OutputLine -ForegroundColor $ColorCode
        
        if ($Result.Compliance) {
            Write-Host "  COMPLIANCE: $($Result.Compliance)" -ForegroundColor Cyan
        }
    }
    
    # Export to CSV
    try {
        $CSVPath = Join-Path $OutputPath "${Script:BaseFileName}_audit_results.csv"
        $AllResults | Export-Csv -Path $CSVPath -NoTypeInformation
        Write-LogMessage "SUCCESS" "Results exported to: $CSVPath" "MAIN"
    }
    catch {
        Write-LogMessage "ERROR" "Failed to export CSV: $($_.Exception.Message)" "MAIN"
    }
    
    $EndTime = Get-Date
    $Duration = New-TimeSpan -Start $Script:StartTime -End $EndTime
    Write-LogMessage "SUCCESS" "Audit completed in $($Duration.TotalSeconds) seconds" "MAIN"
    
    return $AllResults
}

# Script entry point
try {
    Initialize-Logging
    $AuditResults = Start-Audit
    Write-LogMessage "SUCCESS" "Business Network Auditor completed successfully" "MAIN"
}
catch {
    Write-LogMessage "ERROR" "Audit failed: $($_.Exception.Message)" "MAIN"
    exit 1
}

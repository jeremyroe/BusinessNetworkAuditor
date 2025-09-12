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
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Compliance
        
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
                    Compliance = if ($CriticalInProgress.Count -gt 0) { "CRITICAL: Restart required for critical updates" } elseif ($InProgressUpdates.Count -gt 0) { "Restart required to complete updates" } else { "" }
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
                        Compliance = "Restart system to complete update installation"
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
                        Compliance = "Install available updates within 30 days"
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
                Compliance = "Manually verify patch status"
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
                Compliance = if ($RecentHotfixes.Count -eq 0) { "No recent patches detected - verify update process" } else { "" }
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
                Compliance = if ($UptimeDays -gt 30) { "Consider regular restarts for patch application" } else { "" }
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
                Compliance = if ($UpdateService.Status -ne "Running" -and $UpdateService.StartType -eq "Disabled") { "Windows Update service should not be permanently disabled" } else { "" }
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
                    Compliance = if ($AutoUpdateConfig.AUOptions -eq 1) { "Automatic updates should be enabled" } else { "" }
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
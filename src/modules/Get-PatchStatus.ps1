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
            # SYSTEM/Service account fix: Add system profile module path if not already present
            # This applies to SYSTEM account and computer accounts (ending with $)
            if ($env:USERNAME -eq "SYSTEM" -or $env:USERNAME -like "*$") {
                $SystemModulePath = "$env:SystemRoot\system32\config\systemprofile\Documents\WindowsPowerShell\Modules"
                if ($env:PSModulePath -notlike "*$SystemModulePath*") {
                    $env:PSModulePath = "$env:PSModulePath;$SystemModulePath"
                    Write-LogMessage "INFO" "Added system profile module path to PSModulePath for account: $env:USERNAME" "PATCHES"
                }
            }

            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Write-LogMessage "INFO" "Installing PSWindowsUpdate module..." "PATCHES"
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                # Install NuGet provider automatically to avoid prompts
                # Use AllUsers scope if running as SYSTEM or computer account, CurrentUser otherwise
                $InstallScope = if ($env:USERNAME -eq "SYSTEM" -or $env:USERNAME -like "*$") { "AllUsers" } else { "CurrentUser" }
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
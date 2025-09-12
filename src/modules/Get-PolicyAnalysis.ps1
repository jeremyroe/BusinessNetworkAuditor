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
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Compliance
        
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
                        Compliance = ""
                    }
                    
                    foreach ($GPO in $AppliedGPOs) {
                        if ($GPO -and $GPO.Trim() -ne "" -and $GPO -ne "Local Group Policy") {
                            $Results += [PSCustomObject]@{
                                Category = "Policy"
                                Item = "Domain GPO"
                                Value = $GPO
                                Details = "Active Directory Group Policy Object"
                                RiskLevel = "INFO"
                                Compliance = ""
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
                        Compliance = ""
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
                                
                                # Capture actual setting details for specific CSPs
                                $SettingDetails = @()
                                foreach ($SettingName in ($SettingNames | Select-Object -First 8)) {
                                    $SettingValue = $CSPSettings.$SettingName
                                    if ($SettingValue -ne $null -and $SettingValue -ne "") {
                                        $SettingDetails += "$SettingName=$SettingValue"
                                    } else {
                                        $SettingDetails += "$SettingName"
                                    }
                                }
                                $CSPDetailsMap[$CSP.Name] = @{
                                    Description = $CSP.Description
                                    Settings = $SettingDetails
                                    Count = $SettingNames.Count
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
                Compliance = if (-not $MDMEnrolled) { "Consider MDM enrollment for centralized management" } else { "" }
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
                        Compliance = ""
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
                    Compliance = if ([int]$MinPasswordLength -lt 8) { "Minimum 8 characters required" } elseif ([int]$MinPasswordLength -lt 12) { "Consider 12+ characters for enhanced security" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password Complexity"
                    Value = if ($PasswordComplexity -eq "1") { "Enabled" } else { "Disabled" }
                    Details = "Requires uppercase, lowercase, numbers, and symbols"
                    RiskLevel = if ($PasswordComplexity -eq "1") { "LOW" } else { "HIGH" }
                    Compliance = if ($PasswordComplexity -ne "1") { "Enable password complexity requirements" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password History"
                    Value = if ($PasswordHistorySize) { "$PasswordHistorySize passwords remembered" } else { "Not configured" }
                    Details = "Prevents password reuse"
                    RiskLevel = if ([int]$PasswordHistorySize -ge 12) { "LOW" } elseif ([int]$PasswordHistorySize -ge 5) { "MEDIUM" } else { "HIGH" }
                    Compliance = if ([int]$PasswordHistorySize -lt 12) { "Remember last 12 passwords minimum" } else { "" }
                }
                
                # Account Lockout Policy Results
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Account Lockout Threshold"
                    Value = if ($LockoutThreshold -and $LockoutThreshold -ne "0") { "$LockoutThreshold invalid attempts" } else { "No lockout policy" }
                    Details = "Failed logon attempts before lockout"
                    RiskLevel = if ($LockoutThreshold -and [int]$LockoutThreshold -le 10 -and [int]$LockoutThreshold -gt 0) { "LOW" } elseif ($LockoutThreshold -eq "0") { "HIGH" } else { "MEDIUM" }
                    Compliance = if ($LockoutThreshold -eq "0") { "Configure account lockout policy" } else { "" }
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
                    Compliance = if (-not $IsSecure) { "Enable secure screen saver" } elseif ($TimeoutMinutes -gt 15) { "Screen lock timeout should be 15 minutes or less" } else { "" }
                }
            } else {
                # Handle case where no user context exists (SYSTEM) or screen saver is disabled
                $PolicyStatus = if ($env:USERNAME -eq "SYSTEM") { "Cannot Check (System Context)" } else { "Disabled" }
                $PolicyRisk = if ($env:USERNAME -eq "SYSTEM") { "MEDIUM" } else { "HIGH" }
                $PolicyCompliance = if ($env:USERNAME -eq "SYSTEM") { "Screen lock policy should be enforced via Group Policy" } else { "Configure automatic screen lock" }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Screen Lock Policy"
                    Value = $PolicyStatus
                    Details = if ($env:USERNAME -eq "SYSTEM") { "Running as SYSTEM - user-specific settings not accessible" } else { "No automatic screen lock configured" }
                    RiskLevel = $PolicyRisk
                    Compliance = $PolicyCompliance
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
                    Compliance = if ($EnabledAudits -lt $TotalAudits) { "Enable comprehensive audit logging" } else { "" }
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
                    Compliance = ""
                }
                
                if ($DangerousRights.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "User Rights Assignment"
                        Value = "Issues Found"
                        Details = $DangerousRights -join "; "
                        RiskLevel = "MEDIUM"
                        Compliance = "Review user rights assignments for least privilege"
                    }
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "User Rights Assignment"
                        Value = "Secure Configuration"
                        Details = "Critical rights: $($CheckedRights -join ', ')"
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
                    Compliance = "Ensure antivirus protection is enabled unless replaced by third-party solution"
                }
            } elseif ($DefenderRealTime -and $DefenderRealTime.DisableRealtimeMonitoring -eq 1) {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Windows Defender Policy"
                    Value = "Real-time Protection Disabled"
                    Details = "Real-time protection disabled by policy"
                    RiskLevel = "HIGH"
                    Compliance = "Enable real-time antivirus protection"
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
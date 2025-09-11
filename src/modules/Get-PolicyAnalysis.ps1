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
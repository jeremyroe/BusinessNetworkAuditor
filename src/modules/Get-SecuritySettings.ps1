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
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Compliance
        
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
                                Compliance = "Verify antivirus registration and avoid conflicting AV products"
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
                $Compliance = ""
                
                if (-not $AV.Enabled) {
                    # Check if this is Windows Defender and other AV products are active
                    if ($AV.Name -match "Windows Defender" -and $ActiveAV.Count -gt 0) {
                        $RiskLevel = "LOW" 
                        $Compliance = "Windows Defender properly disabled - other active AV products detected"
                    } else {
                        $RiskLevel = "HIGH"
                        $Compliance = "Antivirus must be enabled and active"
                    }
                } elseif ($AV.UpToDate -eq $false) {
                    $RiskLevel = "MEDIUM"
                    $Compliance = "Antivirus signatures must be current"
                } elseif ($InstanceCount -gt 1) {
                    $RiskLevel = "MEDIUM"
                    $Compliance = "Multiple instances may indicate conflicting installations"
                }
                
                $DisplayName = if ($InstanceCount -gt 1) { "$($AV.Name) (x$InstanceCount)" } else { $AV.Name }
                
                $Results += [PSCustomObject]@{
                    Category = "Security"
                    Item = "Antivirus Product"
                    Value = "$DisplayName - $StatusText"
                    Details = $Details
                    RiskLevel = $RiskLevel
                    Compliance = $Compliance
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
            $SummaryCompliance = ""
            
            if ($UniqueActiveProducts -eq 0) {
                $SummaryRisk = "HIGH"
                $SummaryCompliance = "No active antivirus protection"
            } elseif ($UniqueActiveProducts -gt 1) {
                $SummaryRisk = "MEDIUM"
                $SummaryCompliance = "Multiple active AV products may cause conflicts - review configuration"
            } elseif ($TotalInstances -gt $UniqueDetectedProducts) {
                $SummaryRisk = "MEDIUM"
                $SummaryCompliance = "Multiple instances of same products detected - review for cleanup"
            }
            
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Antivirus Protection Summary"
                Value = "$UniqueActiveProducts active of $UniqueDetectedProducts products"
                Details = $SummaryDetails
                RiskLevel = $SummaryRisk
                Compliance = $SummaryCompliance
            }
            
            Write-LogMessage "SUCCESS" "Enhanced AV detection: $UniqueActiveProducts unique active products, $UniqueDetectedProducts total products, $TotalInstances instances" "SECURITY"
        } else {
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Antivirus Protection"
                Value = "None detected"
                Details = "No antivirus software detected via Security Center, Defender API, or process analysis"
                RiskLevel = "HIGH"
                Compliance = "Antivirus protection required"
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
                Compliance = if (-not $Profile.Enabled) { "Enable firewall protection" } else { "" }
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
            Compliance = if (-not $UACKey.EnableLUA) { "Enable UAC for privilege escalation control" } else { "" }
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
                        
                        $VolumeCompliance = switch ($Volume.VolumeStatus) {
                            "FullyDecrypted" { "Enable BitLocker encryption for data protection" }
                            "DecryptionInProgress" { "Complete BitLocker decryption or re-enable encryption" }
                            "EncryptionInProgress" { "Allow BitLocker encryption to complete" }
                            default { "" }
                        }
                        
                        # Add recovery key escrow compliance
                        if ($Volume.VolumeStatus -eq "FullyEncrypted" -and -not $RecoveryKeyEscrowed) {
                            $VolumeCompliance = "Backup BitLocker recovery key to Azure AD or Active Directory"
                            $VolumeRisk = "MEDIUM"
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Security"
                            Item = "BitLocker Volume"
                            Value = "$($Volume.MountPoint) - $($Volume.VolumeStatus)"
                            Details = "Encryption: $($Volume.EncryptionPercentage)%, Protection: $($Volume.ProtectionStatus), Method: $($Volume.EncryptionMethod), Key Escrow: $EscrowLocation"
                            RiskLevel = $VolumeRisk
                            Compliance = $VolumeCompliance
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
                        Compliance = if ($EncryptedCount -lt $TotalVolumes) { "Encrypt all system and data volumes with BitLocker" } else { "" }
                    }
                    
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Security"
                        Item = "BitLocker Encryption"
                        Value = "No volumes detected"
                        Details = "Unable to retrieve BitLocker volume information"
                        RiskLevel = "MEDIUM"
                        Compliance = "Verify BitLocker configuration and permissions"
                    }
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Security"
                    Item = "BitLocker Encryption"
                    Value = "Not Available"
                    Details = "BitLocker feature not enabled or not supported"
                    RiskLevel = "HIGH"
                    Compliance = "Enable BitLocker feature for disk encryption"
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
                Compliance = "Manual verification required"
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
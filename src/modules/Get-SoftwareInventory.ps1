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
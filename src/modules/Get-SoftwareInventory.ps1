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
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Compliance
        
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
                    Compliance = "NIST: Document and secure remote access tools"
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
            Compliance = ""
        }
        
        Write-LogMessage "SUCCESS" "Software inventory completed - $($AllSoftware.Count) programs found" "SOFTWARE"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to collect software inventory: $($_.Exception.Message)" "SOFTWARE"
        return @()
    }
}
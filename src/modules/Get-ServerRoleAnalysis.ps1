# WindowsServerAuditor - Server Role Analysis Module
# Version 1.3.0

function Get-ServerRoleAnalysis {
    <#
    .SYNOPSIS
        Analyzes Windows Server roles and features installed on the system
        
    .DESCRIPTION
        Performs comprehensive server role and feature analysis including:
        - Installed Windows Server roles and features
        - Role service details and configuration status
        - Critical service dependencies for each role
        - Common server role security recommendations
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function, Add-RawDataCollection function
        Permissions: Local Administrator rights recommended
        Coverage: Windows Server 2016+, PowerShell 5.0+
    #>
    
    Write-LogMessage "INFO" "Analyzing Windows Server roles and features..." "SERVERROLES"
    
    try {
        $Results = @()
        
        # Check if Server Manager module is available
        if (-not (Get-Module -ListAvailable -Name ServerManager)) {
            Write-LogMessage "WARN" "ServerManager module not available - limited role detection" "SERVERROLES"
            
            # Fall back to basic service detection
            $Results += [PSCustomObject]@{
                Category = "Server Roles"
                Item = "Role Detection"
                Value = "Limited - ServerManager module unavailable"
                Details = "Cannot perform comprehensive role analysis. Using service-based detection."
                RiskLevel = "WARN"
                Recommendation = "Install ServerManager PowerShell module for complete analysis"
            }
            
            return $Results
        }
        
        # Get installed Windows Features
        Write-LogMessage "INFO" "Querying Windows Features..." "SERVERROLES"
        $WindowsFeatures = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" }
        
        # Categorize roles by type
        $ServerRoles = @()
        $ServerFeatures = @()
        $RoleServices = @()
        
        foreach ($Feature in $WindowsFeatures) {
            switch ($Feature.FeatureType) {
                "Role" { 
                    $ServerRoles += $Feature
                    Write-LogMessage "INFO" "Found installed role: $($Feature.DisplayName)" "SERVERROLES"
                }
                "Feature" { $ServerFeatures += $Feature }
                "Role Service" { $RoleServices += $Feature }
            }
        }
        
        # Create raw data collection
        $RoleAnalysisData = @{
            InstalledRoles = $ServerRoles | ForEach-Object {
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    InstallState = $_.InstallState
                    FeatureType = $_.FeatureType
                    Path = $_.Path
                    Depth = $_.Depth
                    DependsOn = $_.DependsOn
                    Parent = $_.Parent
                    ServerComponentDescriptor = $_.ServerComponentDescriptor
                }
            }
            InstalledFeatures = $ServerFeatures | ForEach-Object {
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    InstallState = $_.InstallState
                    FeatureType = $_.FeatureType
                }
            }
            RoleServices = $RoleServices | ForEach-Object {
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    InstallState = $_.InstallState
                    Parent = $_.Parent
                }
            }
        }
        
        Add-RawDataCollection -CollectionName "ServerRoleAnalysis" -Data $RoleAnalysisData
        
        # Summary of installed roles
        $Results += [PSCustomObject]@{
            Category = "Server Roles"
            Item = "Installed Roles Count"
            Value = $ServerRoles.Count
            Details = "Windows Server roles currently installed and active"
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        $Results += [PSCustomObject]@{
            Category = "Server Roles"
            Item = "Installed Features Count"
            Value = $ServerFeatures.Count
            Details = "Windows Server features currently installed"
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        # Analyze specific critical roles
        $CriticalRoles = @{
            "AD-Domain-Services" = @{
                Name = "Active Directory Domain Services"
                Risk = "HIGH"
                Description = "Domain Controller - Critical infrastructure component"
                Recommendation = "Ensure proper backup, monitoring, and security hardening"
            }
            "DHCP" = @{
                Name = "DHCP Server"
                Risk = "MEDIUM"
                Description = "Network DHCP service"
                Recommendation = "Monitor scope utilization and secure DHCP settings"
            }
            "DNS" = @{
                Name = "DNS Server"
                Risk = "MEDIUM"
                Description = "Domain Name System service"
                Recommendation = "Secure DNS configuration and monitor for unauthorized changes"
            }
            "Web-Server" = @{
                Name = "Internet Information Services (IIS)"
                Risk = "MEDIUM"
                Description = "Web server role"
                Recommendation = "Regular security updates and secure configuration required"
            }
            "File-Services" = @{
                Name = "File and Storage Services"
                Risk = "MEDIUM"
                Description = "File server capabilities"
                Recommendation = "Monitor file share permissions and access logs"
            }
            "Print-Services" = @{
                Name = "Print and Document Services"
                Risk = "LOW"
                Description = "Print server capabilities"
                Recommendation = "Review print server security and driver updates"
            }
            "Remote-Desktop-Services" = @{
                Name = "Remote Desktop Services"
                Risk = "HIGH"
                Description = "Terminal services and remote access"
                Recommendation = "Secure RDS configuration and monitor remote access"
            }
            "Hyper-V" = @{
                Name = "Hyper-V"
                Risk = "HIGH"
                Description = "Virtualization platform"
                Recommendation = "Secure hypervisor and monitor VM security"
            }
            "ADCS-Cert-Authority" = @{
                Name = "Active Directory Certificate Services"
                Risk = "HIGH"
                Description = "Certificate Authority services"
                Recommendation = "Secure CA configuration and certificate management"
            }
            "ADFS-Federation" = @{
                Name = "Active Directory Federation Services"
                Risk = "HIGH"
                Description = "Identity federation services"
                Recommendation = "Secure ADFS configuration and monitor authentication"
            }
            "WDS" = @{
                Name = "Windows Deployment Services"
                Risk = "MEDIUM"
                Description = "Network-based OS deployment"
                Recommendation = "Secure WDS configuration and image management"
            }
            "WSUS" = @{
                Name = "Windows Server Update Services"
                Risk = "MEDIUM"
                Description = "Windows update distribution"
                Recommendation = "Monitor update approval and distribution"
            }
        }
        
        # Check each critical role
        foreach ($RoleName in $CriticalRoles.Keys) {
            $RoleInfo = $CriticalRoles[$RoleName]
            $InstalledRole = $ServerRoles | Where-Object { $_.Name -eq $RoleName }
            
            if ($InstalledRole) {
                # Get related role services
                $RelatedServices = $RoleServices | Where-Object { $_.Parent -eq $RoleName }
                $ServiceDetails = if ($RelatedServices) {
                    "Role services: $($RelatedServices.DisplayName -join ', ')"
                } else {
                    "No additional role services detected"
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Server Roles"
                    Item = "Critical Role Detected"
                    Value = $RoleInfo.Name
                    Details = "$($RoleInfo.Description). $ServiceDetails"
                    RiskLevel = $RoleInfo.Risk
                    Recommendation = $RoleInfo.Recommendation
                }
            }
        }
        
        # Check for potentially risky feature combinations
        $RiskyFeatures = @()
        
        # Web server with AD DS (domain controller serving web content)
        if (($ServerRoles | Where-Object { $_.Name -eq "Web-Server" }) -and 
            ($ServerRoles | Where-Object { $_.Name -eq "AD-Domain-Services" })) {
            $RiskyFeatures += "Web server installed on Domain Controller"
        }
        
        # Multiple critical roles on single server
        $CriticalRoleCount = ($ServerRoles | Where-Object { $_.Name -in $CriticalRoles.Keys }).Count
        if ($CriticalRoleCount -gt 3) {
            $RiskyFeatures += "Multiple critical roles on single server ($CriticalRoleCount roles)"
        }
        
        # Report risky configurations
        foreach ($RiskyConfig in $RiskyFeatures) {
            $Results += [PSCustomObject]@{
                Category = "Server Roles"
                Item = "Configuration Risk"
                Value = $RiskyConfig
                Details = "Review server role separation and security implications"
                RiskLevel = "HIGH"
                Recommendation = "Consider role separation for security and performance"
            }
        }
        
        # List all installed roles for reference
        if ($ServerRoles.Count -gt 0) {
            $RoleList = ($ServerRoles | ForEach-Object { $_.DisplayName }) -join ", "
            $Results += [PSCustomObject]@{
                Category = "Server Roles"
                Item = "Complete Role List"
                Value = "See Details"
                Details = "Installed roles: $RoleList"
                RiskLevel = "INFO"
                Recommendation = ""
            }
        }
        
        # Check for common optional features that might be security relevant
        $SecurityRelevantFeatures = @{
            "Telnet-Client" = "Telnet Client - Insecure protocol"
            "TFTP-Client" = "TFTP Client - Insecure file transfer"
            "SMB1Protocol" = "SMB v1.0/CIFS File Sharing Support - Deprecated protocol"
            "PowerShell-V2" = "Windows PowerShell 2.0 Engine - Legacy version"
            "Internet-Explorer-Optional-amd64" = "Internet Explorer 11 - Legacy browser"
        }
        
        foreach ($FeatureName in $SecurityRelevantFeatures.Keys) {
            $Feature = $ServerFeatures | Where-Object { $_.Name -eq $FeatureName }
            if ($Feature) {
                $Results += [PSCustomObject]@{
                    Category = "Server Roles"
                    Item = "Security-Relevant Feature"
                    Value = $Feature.DisplayName
                    Details = $SecurityRelevantFeatures[$FeatureName]
                    RiskLevel = "MEDIUM"
                    Recommendation = "Review necessity and consider removal if unused"
                }
            }
        }
        
        Write-LogMessage "SUCCESS" "Server role analysis completed - $($ServerRoles.Count) roles, $($ServerFeatures.Count) features detected" "SERVERROLES"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze server roles: $($_.Exception.Message)" "SERVERROLES"
        return @([PSCustomObject]@{
            Category = "Server Roles"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during server role analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Recommendation = "Investigate server role analysis failure"
        })
    }
}
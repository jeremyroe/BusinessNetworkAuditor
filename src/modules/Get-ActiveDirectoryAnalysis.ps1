# WindowsServerAuditor - Active Directory Analysis Module
# Version 1.3.0

function Get-ActiveDirectoryAnalysis {
    <#
    .SYNOPSIS
        Analyzes Active Directory configuration and objects (read-only discovery)
        
    .DESCRIPTION
        Performs AD discovery and analysis including:
        - Domain Controller role detection
        - User and group counts
        - Domain functional level
        - Forest and domain configuration
        - Password policy settings (read-only queries only)
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Compliance
        
    .NOTES
        Version: 1.3.0
        Dependencies: Write-LogMessage, Add-RawDataCollection
        Permissions: Domain User minimum, Domain Admin recommended
        Safety: READ-ONLY - No AD objects created, modified, or deleted
    #>
    
    Write-LogMessage "INFO" "Analyzing Active Directory configuration..." "ACTIVEDIRECTORY"
    
    try {
        $Results = @()
        
        # Check if AD DS role is installed
        try {
            $ADDSFeature = Get-WindowsFeature -Name "AD-Domain-Services" -ErrorAction SilentlyContinue
            if (-not $ADDSFeature -or $ADDSFeature.InstallState -ne "Installed") {
                Write-LogMessage "INFO" "AD DS role not installed - skipping Active Directory analysis" "ACTIVEDIRECTORY"
                return @([PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "AD DS Status"
                    Value = "Not Installed"
                    Details = "Active Directory Domain Services role is not installed on this system"
                    RiskLevel = "INFO"
                    Compliance = ""
                })
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check AD DS feature status: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Check if ActiveDirectory module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-LogMessage "WARN" "ActiveDirectory PowerShell module not available - limited analysis" "ACTIVEDIRECTORY"
            
            # Check AD services status only
            $ADServices = @("NTDS", "DNS", "Kdc", "W32Time")
            foreach ($ServiceName in $ADServices) {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($Service) {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "AD Service"
                        Value = "$ServiceName - $($Service.Status)"
                        Details = "Active Directory service status"
                        RiskLevel = if ($Service.Status -eq "Running") { "INFO" } else { "HIGH" }
                        Compliance = ""
                    }
                }
            }
            
            $Results += [PSCustomObject]@{
                Category = "Active Directory"
                Item = "Module Limitation"
                Value = "ActiveDirectory module unavailable"
                Details = "Install RSAT-AD-PowerShell for complete AD analysis"
                RiskLevel = "MEDIUM"
                Compliance = "Install ActiveDirectory PowerShell module for detailed analysis"
            }
            
            return $Results
        }
        
        # Import Active Directory module (read-only)
        try {
            Import-Module ActiveDirectory -Force -ErrorAction Stop
            Write-LogMessage "SUCCESS" "ActiveDirectory module loaded" "ACTIVEDIRECTORY"
        }
        catch {
            Write-LogMessage "ERROR" "Failed to import ActiveDirectory module: $($_.Exception.Message)" "ACTIVEDIRECTORY"
            return @([PSCustomObject]@{
                Category = "Active Directory"
                Item = "Module Error"
                Value = "Failed to load ActiveDirectory module"
                Details = $_.Exception.Message
                RiskLevel = "ERROR"
                Compliance = "Resolve Active Directory module loading issue"
            })
        }
        
        # Get domain information (read-only)
        Write-LogMessage "INFO" "Retrieving domain information..." "ACTIVEDIRECTORY"
        
        try {
            $Domain = Get-ADDomain -ErrorAction SilentlyContinue
            
            if ($Domain) {
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Domain Information"
                    Value = $Domain.DNSRoot
                    Details = "NetBIOS: $($Domain.NetBIOSName), Functional Level: $($Domain.DomainMode), PDC: $($Domain.PDCEmulator)"
                    RiskLevel = "INFO"
                    Compliance = ""
                }
                
                # Check domain functional level
                $DomainLevel = $Domain.DomainMode
                $LevelRisk = switch -Regex ($DomainLevel) {
                    "2003|2008" { "HIGH" }
                    "2012" { "MEDIUM" }
                    "2016|2019|2022" { "LOW" }
                    default { "MEDIUM" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Domain Functional Level"
                    Value = $DomainLevel
                    Details = "Domain functional level determines available AD features"
                    RiskLevel = $LevelRisk
                    Compliance = if ($LevelRisk -eq "HIGH") { "Consider upgrading domain functional level for security improvements" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve domain information: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get forest information (read-only)
        try {
            $Forest = Get-ADForest -ErrorAction SilentlyContinue
            
            if ($Forest) {
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Forest Information"
                    Value = $Forest.Name
                    Details = "Functional Level: $($Forest.ForestMode), Domains: $($Forest.Domains.Count), Schema Master: $($Forest.SchemaMaster)"
                    RiskLevel = "INFO"
                    Compliance = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve forest information: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get user counts (read-only, limited query for performance)
        Write-LogMessage "INFO" "Analyzing AD users..." "ACTIVEDIRECTORY"
        
        try {
            # Get user count summary (limited query)
            $AllUsers = Get-ADUser -Filter * -Properties Enabled, PasswordLastSet, LastLogonDate -ResultSetSize 1000 -ErrorAction SilentlyContinue
            
            if ($AllUsers) {
                $EnabledUsers = $AllUsers | Where-Object { $_.Enabled -eq $true }
                $DisabledUsers = $AllUsers | Where-Object { $_.Enabled -eq $false }
                $NeverLoggedOn = $AllUsers | Where-Object { -not $_.LastLogonDate }
                
                # Check for stale accounts (no logon in 90 days)
                $StaleDate = (Get-Date).AddDays(-90)
                $StaleUsers = $AllUsers | Where-Object { $_.LastLogonDate -lt $StaleDate -and $_.Enabled -eq $true }
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory" 
                    Item = "User Account Summary"
                    Value = "$($AllUsers.Count) total users"
                    Details = "Enabled: $($EnabledUsers.Count), Disabled: $($DisabledUsers.Count), Stale (90+ days): $($StaleUsers.Count)"
                    RiskLevel = if ($StaleUsers.Count -gt 10) { "MEDIUM" } else { "INFO" }
                    Compliance = if ($StaleUsers.Count -gt 0) { "Review and disable stale user accounts" } else { "" }
                }
                
                # Check for users with old passwords
                $OldPasswordDate = (Get-Date).AddDays(-180)
                $OldPasswords = $AllUsers | Where-Object { $_.PasswordLastSet -lt $OldPasswordDate -and $_.Enabled -eq $true }
                
                if ($OldPasswords.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Password Age Analysis"
                        Value = "$($OldPasswords.Count) users with old passwords"
                        Details = "Users with passwords older than 180 days"
                        RiskLevel = "MEDIUM"
                        Compliance = "Review password policy and encourage regular password changes"
                    }
                }
                
                # Store limited user data for raw export (no sensitive info)
                $UserSummaryData = @{
                    TotalUsers = $AllUsers.Count
                    EnabledUsers = $EnabledUsers.Count
                    DisabledUsers = $DisabledUsers.Count
                    StaleUsers = $StaleUsers.Count
                    OldPasswordUsers = $OldPasswords.Count
                    NeverLoggedOnUsers = $NeverLoggedOn.Count
                }
                
                Add-RawDataCollection -CollectionName "ADUserSummary" -Data $UserSummaryData
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to analyze AD users: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get group information (read-only, limited query)
        try {
            Write-LogMessage "INFO" "Analyzing AD groups..." "ACTIVEDIRECTORY"
            
            $AllGroups = Get-ADGroup -Filter * -Properties Members -ResultSetSize 500 -ErrorAction SilentlyContinue
            
            if ($AllGroups) {
                # Check privileged groups
                $PrivilegedGroups = @(
                    "Domain Admins", "Enterprise Admins", "Schema Admins", 
                    "Administrators", "Account Operators", "Backup Operators"
                )
                
                $PrivGroupData = @()
                
                foreach ($GroupName in $PrivilegedGroups) {
                    $Group = $AllGroups | Where-Object { $_.Name -eq $GroupName }
                    if ($Group) {
                        $MemberCount = if ($Group.Members) { $Group.Members.Count } else { 0 }
                        $GroupRisk = switch ($GroupName) {
                            "Domain Admins" { if ($MemberCount -gt 5) { "HIGH" } else { "MEDIUM" } }
                            "Enterprise Admins" { if ($MemberCount -gt 2) { "HIGH" } else { "MEDIUM" } }
                            "Schema Admins" { if ($MemberCount -gt 1) { "HIGH" } else { "LOW" } }
                            default { if ($MemberCount -gt 10) { "MEDIUM" } else { "LOW" } }
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Active Directory"
                            Item = "Privileged Group"
                            Value = "$GroupName - $MemberCount members"
                            Details = "High-privilege group membership count"
                            RiskLevel = $GroupRisk
                            Compliance = if ($GroupRisk -eq "HIGH") { "Review and minimize privileged group membership" } else { "" }
                        }
                        
                        $PrivGroupData += @{
                            GroupName = $GroupName
                            MemberCount = $MemberCount
                            RiskLevel = $GroupRisk
                        }
                    }
                }
                
                Add-RawDataCollection -CollectionName "ADPrivilegedGroups" -Data $PrivGroupData
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Group Summary"
                    Value = "$($AllGroups.Count) total groups"
                    Details = "Security groups, distribution lists, and built-in groups"
                    RiskLevel = "INFO"
                    Compliance = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to analyze AD groups: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get password policy (read-only)
        try {
            $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
            
            if ($PasswordPolicy) {
                $PolicyRisk = "LOW"
                $PolicyIssues = @()
                
                # Check password policy settings
                if ($PasswordPolicy.MinPasswordLength -lt 8) {
                    $PolicyRisk = "HIGH"
                    $PolicyIssues += "Minimum length too short"
                }
                
                if ($PasswordPolicy.MaxPasswordAge.Days -gt 90) {
                    $PolicyRisk = "MEDIUM"
                    $PolicyIssues += "Maximum age too long"
                }
                
                if ($PasswordPolicy.ComplexityEnabled -eq $false) {
                    $PolicyRisk = "HIGH"
                    $PolicyIssues += "Complexity not required"
                }
                
                $PolicyDetails = "Min Length: $($PasswordPolicy.MinPasswordLength), Max Age: $($PasswordPolicy.MaxPasswordAge.Days) days, Complexity: $($PasswordPolicy.ComplexityEnabled)"
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Password Policy"
                    Value = if ($PolicyIssues.Count -gt 0) { "Issues detected" } else { "Compliant" }
                    Details = $PolicyDetails
                    RiskLevel = $PolicyRisk
                    Compliance = if ($PolicyIssues.Count -gt 0) { "Strengthen password policy: $($PolicyIssues -join ', ')" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve password policy: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        Write-LogMessage "SUCCESS" "Active Directory analysis completed" "ACTIVEDIRECTORY"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze Active Directory: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        return @([PSCustomObject]@{
            Category = "Active Directory"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during Active Directory analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Compliance = "Investigate Active Directory analysis failure"
        })
    }
}
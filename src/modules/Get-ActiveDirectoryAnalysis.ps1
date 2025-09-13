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
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
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
                    Recommendation = ""
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
                        Recommendation = ""
                    }
                }
            }
            
            $Results += [PSCustomObject]@{
                Category = "Active Directory"
                Item = "Module Limitation"
                Value = "ActiveDirectory module unavailable"
                Details = "Install RSAT-AD-PowerShell for complete AD analysis"
                RiskLevel = "MEDIUM"
                Recommendation = "Install ActiveDirectory PowerShell module for detailed analysis"
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
                Recommendation = "Resolve Active Directory module loading issue"
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
                    Recommendation = ""
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
                    Recommendation = if ($LevelRisk -eq "HIGH") { "Consider upgrading domain functional level for security improvements" } else { "" }
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
                    Recommendation = ""
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
                
                # Enhanced stale account analysis (multiple thresholds)
                $StaleDate90 = (Get-Date).AddDays(-90)
                $StaleDate180 = (Get-Date).AddDays(-180)
                $StaleUsers90 = $AllUsers | Where-Object { $_.LastLogonDate -lt $StaleDate90 -and $_.Enabled -eq $true }
                $StaleUsers180 = $AllUsers | Where-Object { $_.LastLogonDate -lt $StaleDate180 -and $_.Enabled -eq $true }
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory" 
                    Item = "User Account Summary"
                    Value = "$($AllUsers.Count) total users"
                    Details = "Enabled: $($EnabledUsers.Count), Disabled: $($DisabledUsers.Count), Stale 90+ days: $($StaleUsers90.Count), Stale 180+ days: $($StaleUsers180.Count)"
                    RiskLevel = if ($StaleUsers180.Count -gt 5) { "HIGH" } elseif ($StaleUsers90.Count -gt 10) { "MEDIUM" } else { "INFO" }
                    Recommendation = if ($StaleUsers90.Count -gt 0) { "Review and disable stale user accounts - prioritize 180+ day inactive users" } else { "" }
                }
                
                # Separate detailed stale user finding
                if ($StaleUsers90.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Stale User Accounts"
                        Value = "$($StaleUsers90.Count) users inactive 90+ days ($($StaleUsers180.Count) inactive 180+ days)"
                        Details = "Enabled user accounts with no recent logon activity require cleanup review"
                        RiskLevel = if ($StaleUsers180.Count -gt 5) { "HIGH" } elseif ($StaleUsers90.Count -gt 15) { "MEDIUM" } else { "LOW" }
                        Recommendation = "Disable or remove stale user accounts per company retention policy"
                    }
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
                        Recommendation = "Review password policy and encourage regular password changes"
                    }
                }
                
                # Store limited user data for raw export (no sensitive info)
                $UserSummaryData = @{
                    TotalUsers = $AllUsers.Count
                    EnabledUsers = $EnabledUsers.Count
                    DisabledUsers = $DisabledUsers.Count
                    StaleUsers90Days = $StaleUsers90.Count
                    StaleUsers180Days = $StaleUsers180.Count
                    OldPasswordUsers = $OldPasswords.Count
                    NeverLoggedOnUsers = $NeverLoggedOn.Count
                }
                
                Add-RawDataCollection -CollectionName "ADUserSummary" -Data $UserSummaryData
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to analyze AD users: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get computer accounts for stale analysis (read-only, limited query for performance)
        Write-LogMessage "INFO" "Analyzing AD computers..." "ACTIVEDIRECTORY"
        
        try {
            # Get computer account summary (limited query)
            $AllComputers = Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, OperatingSystem, OperatingSystemVersion -ResultSetSize 500 -ErrorAction SilentlyContinue
            
            if ($AllComputers) {
                $EnabledComputers = $AllComputers | Where-Object { $_.Enabled -eq $true }
                $DisabledComputers = $AllComputers | Where-Object { $_.Enabled -eq $false }
                $NeverLoggedOnComputers = $AllComputers | Where-Object { -not $_.LastLogonDate }
                
                # Enhanced stale computer analysis (multiple thresholds) 
                $StaleDate90 = (Get-Date).AddDays(-90)
                $StaleDate180 = (Get-Date).AddDays(-180)
                $StaleComputers90 = $AllComputers | Where-Object { $_.LastLogonDate -lt $StaleDate90 -and $_.Enabled -eq $true }
                $StaleComputers180 = $AllComputers | Where-Object { $_.LastLogonDate -lt $StaleDate180 -and $_.Enabled -eq $true }
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Computer Account Summary"
                    Value = "$($AllComputers.Count) total computers"
                    Details = "Enabled: $($EnabledComputers.Count), Disabled: $($DisabledComputers.Count), Stale 90+ days: $($StaleComputers90.Count), Stale 180+ days: $($StaleComputers180.Count)"
                    RiskLevel = if ($StaleComputers180.Count -gt 3) { "HIGH" } elseif ($StaleComputers90.Count -gt 5) { "MEDIUM" } else { "INFO" }
                    Recommendation = if ($StaleComputers90.Count -gt 0) { "Review and remove stale computer accounts - prioritize 180+ day inactive computers" } else { "" }
                }
                
                # Separate detailed stale computer finding
                if ($StaleComputers90.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Stale Computer Accounts"
                        Value = "$($StaleComputers90.Count) computers inactive 90+ days ($($StaleComputers180.Count) inactive 180+ days)"
                        Details = "Enabled computer accounts with no recent domain logon activity require cleanup review"
                        RiskLevel = if ($StaleComputers180.Count -gt 3) { "HIGH" } elseif ($StaleComputers90.Count -gt 10) { "MEDIUM" } else { "LOW" }
                        Recommendation = "Remove stale computer accounts to maintain AD hygiene and security"
                    }
                }
                
                # Operating system analysis
                $OSCounts = $AllComputers | Where-Object { $_.OperatingSystem } | Group-Object OperatingSystem | Sort-Object Count -Descending
                if ($OSCounts) {
                    $OSBreakdown = ($OSCounts | Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Computer Operating Systems"
                        Value = "$($OSCounts.Count) different OS types"
                        Details = "Top OS types: $OSBreakdown"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                }
                
                # Store computer data for raw export (no sensitive info)
                $ComputerSummaryData = @{
                    TotalComputers = $AllComputers.Count
                    EnabledComputers = $EnabledComputers.Count
                    DisabledComputers = $DisabledComputers.Count
                    StaleComputers90Days = $StaleComputers90.Count
                    StaleComputers180Days = $StaleComputers180.Count
                    NeverLoggedOnComputers = $NeverLoggedOnComputers.Count
                    OperatingSystemBreakdown = $OSCounts | Select-Object Name, Count | ForEach-Object { @{ OS = $_.Name; Count = $_.Count } }
                }
                
                Add-RawDataCollection -CollectionName "ADComputerSummary" -Data $ComputerSummaryData
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to analyze AD computers: $($_.Exception.Message)" "ACTIVEDIRECTORY"
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
                            Recommendation = if ($GroupRisk -eq "HIGH") { "Review and minimize privileged group membership" } else { "" }
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
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to analyze AD groups: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # AD Health Monitoring - DC Diagnostics
        Write-LogMessage "INFO" "Performing AD health diagnostics..." "ACTIVEDIRECTORY"
        
        try {
            # Check if this is a Domain Controller
            $IsDC = $false
            try {
                $DCInfo = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue
                $IsDC = $DCInfo -ne $null
            }
            catch {
                # Not a DC or no permissions
            }
            
            if ($IsDC) {
                Write-LogMessage "INFO" "Domain Controller detected - running DC health checks..." "ACTIVEDIRECTORY"
                
                # Run dcdiag tests (read-only diagnostic)
                try {
                    $DCDiagOutput = & dcdiag.exe /q /c 2>&1
                    $DCDiagExitCode = $LASTEXITCODE
                    
                    if ($DCDiagExitCode -eq 0) {
                        $Results += [PSCustomObject]@{
                            Category = "Active Directory"
                            Item = "Domain Controller Health"
                            Value = "All tests passed"
                            Details = "DCDiag completed successfully with no critical errors"
                            RiskLevel = "LOW"
                            Recommendation = ""
                        }
                        Write-LogMessage "SUCCESS" "DCDiag tests passed" "ACTIVEDIRECTORY"
                    } else {
                        # Parse dcdiag output for specific issues
                        $DCDiagLines = $DCDiagOutput -split "`n" | Where-Object { $_ -match "failed|error|warning" } | Select-Object -First 3
                        $DCDiagSummary = if ($DCDiagLines) { $DCDiagLines -join "; " } else { "Unknown dcdiag issues detected" }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Active Directory"
                            Item = "Domain Controller Health"
                            Value = "Issues detected"
                            Details = "DCDiag found problems: $DCDiagSummary"
                            RiskLevel = "HIGH"
                            Recommendation = "Investigate and resolve Domain Controller health issues"
                        }
                        Write-LogMessage "WARN" "DCDiag detected issues: $DCDiagSummary" "ACTIVEDIRECTORY"
                    }
                }
                catch {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Domain Controller Health"
                        Value = "Cannot run diagnostics"
                        Details = "Unable to execute dcdiag: $($_.Exception.Message)"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Ensure dcdiag.exe is available and accessible"
                    }
                    Write-LogMessage "WARN" "Cannot run dcdiag: $($_.Exception.Message)" "ACTIVEDIRECTORY"
                }
                
                # Check AD replication status
                try {
                    Write-LogMessage "INFO" "Checking AD replication status..." "ACTIVEDIRECTORY"
                    $ReplPartners = Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -ErrorAction SilentlyContinue
                    
                    if ($ReplPartners) {
                        $TotalPartners = $ReplPartners.Count
                        $RecentFailures = $ReplPartners | Where-Object { $_.LastReplicationResult -ne 0 }
                        $OldReplications = $ReplPartners | Where-Object { $_.LastReplicationAttempt -lt (Get-Date).AddHours(-24) }
                        
                        if ($RecentFailures.Count -gt 0) {
                            $FailureDetails = ($RecentFailures | Select-Object -First 3 | ForEach-Object { "$($_.Partner) (Error: $($_.LastReplicationResult))" }) -join ", "
                            $Results += [PSCustomObject]@{
                                Category = "Active Directory"
                                Item = "AD Replication Status"
                                Value = "$($RecentFailures.Count) of $TotalPartners partners have failures"
                                Details = "Replication failures: $FailureDetails"
                                RiskLevel = "HIGH"
                                Recommendation = "Investigate and resolve Active Directory replication failures immediately"
                            }
                            Write-LogMessage "ERROR" "AD replication failures detected: $($RecentFailures.Count) partners" "ACTIVEDIRECTORY"
                        } elseif ($OldReplications.Count -gt 0) {
                            $Results += [PSCustomObject]@{
                                Category = "Active Directory"
                                Item = "AD Replication Status"
                                Value = "$($OldReplications.Count) of $TotalPartners partners have stale replication"
                                Details = "Some replication partners haven't replicated in 24+ hours"
                                RiskLevel = "MEDIUM"
                                Recommendation = "Monitor replication frequency and investigate delayed replication"
                            }
                            Write-LogMessage "WARN" "Stale AD replication detected: $($OldReplications.Count) partners" "ACTIVEDIRECTORY"
                        } else {
                            $Results += [PSCustomObject]@{
                                Category = "Active Directory"
                                Item = "AD Replication Status"
                                Value = "Healthy ($TotalPartners replication partners)"
                                Details = "All replication partners are functioning normally"
                                RiskLevel = "LOW"
                                Recommendation = ""
                            }
                            Write-LogMessage "SUCCESS" "AD replication healthy: $TotalPartners partners" "ACTIVEDIRECTORY"
                        }
                        
                        # Store replication data for raw export
                        $ReplSummaryData = @{
                            TotalPartners = $TotalPartners
                            FailedPartners = $RecentFailures.Count
                            StalePartners = $OldReplications.Count
                            ReplicationPartners = $ReplPartners | Select-Object Partner, LastReplicationAttempt, LastReplicationResult | ForEach-Object { 
                                @{ 
                                    Partner = $_.Partner; 
                                    LastAttempt = $_.LastReplicationAttempt; 
                                    LastResult = $_.LastReplicationResult 
                                } 
                            }
                        }
                        Add-RawDataCollection -CollectionName "ADReplicationStatus" -Data $ReplSummaryData
                    }
                }
                catch {
                    Write-LogMessage "WARN" "Unable to check AD replication: $($_.Exception.Message)" "ACTIVEDIRECTORY"
                }
                
                # Check FSMO roles if this is a DC
                try {
                    Write-LogMessage "INFO" "Checking FSMO role holders..." "ACTIVEDIRECTORY"
                    $Forest = Get-ADForest -ErrorAction SilentlyContinue
                    $Domain = Get-ADDomain -ErrorAction SilentlyContinue
                    
                    if ($Forest -and $Domain) {
                        $FSMORoles = @()
                        
                        # Forest-level FSMO roles
                        if ($Forest.SchemaMaster) { $FSMORoles += "Schema Master: $($Forest.SchemaMaster)" }
                        if ($Forest.DomainNamingMaster) { $FSMORoles += "Domain Naming Master: $($Forest.DomainNamingMaster)" }
                        
                        # Domain-level FSMO roles
                        if ($Domain.PDCEmulator) { $FSMORoles += "PDC Emulator: $($Domain.PDCEmulator)" }
                        if ($Domain.RIDMaster) { $FSMORoles += "RID Master: $($Domain.RIDMaster)" }
                        if ($Domain.InfrastructureMaster) { $FSMORoles += "Infrastructure Master: $($Domain.InfrastructureMaster)" }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Active Directory"
                            Item = "FSMO Role Status"
                            Value = "$($FSMORoles.Count) roles identified"
                            Details = $FSMORoles -join "; "
                            RiskLevel = "INFO"
                            Recommendation = ""
                        }
                        Write-LogMessage "SUCCESS" "FSMO roles identified: $($FSMORoles.Count)" "ACTIVEDIRECTORY"
                    }
                }
                catch {
                    Write-LogMessage "WARN" "Unable to check FSMO roles: $($_.Exception.Message)" "ACTIVEDIRECTORY"
                }
            } else {
                Write-LogMessage "INFO" "Non-DC system - skipping DC-specific health checks" "ACTIVEDIRECTORY"
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "AD Health Monitoring"
                    Value = "Not a Domain Controller"
                    Details = "Advanced AD health monitoring requires Domain Controller role"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "ERROR" "AD health monitoring failed: $($_.Exception.Message)" "ACTIVEDIRECTORY"
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
                    Recommendation = if ($PolicyIssues.Count -gt 0) { "Strengthen password policy: $($PolicyIssues -join ', ')" } else { "" }
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
            Recommendation = "Investigate Active Directory analysis failure"
        })
    }
}
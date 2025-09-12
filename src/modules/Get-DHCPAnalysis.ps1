# WindowsServerAuditor - DHCP Analysis Module
# Version 1.3.0

function Get-DHCPAnalysis {
    <#
    .SYNOPSIS
        Analyzes DHCP server configuration and scope information
        
    .DESCRIPTION
        Performs comprehensive DHCP server analysis including:
        - DHCP service status and configuration
        - DHCP scopes and utilization
        - Reservations and exclusions
        - DHCP options and security settings
        - Lease duration and renewal settings
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Compliance
        
    .NOTES
        Requires: Write-LogMessage function, Add-RawDataCollection function
        Permissions: Local Administrator rights and DHCP Admin rights
        Coverage: Windows Server DHCP role
    #>
    
    Write-LogMessage "INFO" "Analyzing DHCP server configuration..." "DHCP"
    
    try {
        $Results = @()
        
        # Check if DHCP role is installed
        try {
            $DHCPFeature = Get-WindowsFeature -Name "DHCP" -ErrorAction SilentlyContinue
            if (-not $DHCPFeature -or $DHCPFeature.InstallState -ne "Installed") {
                Write-LogMessage "INFO" "DHCP Server role not installed - skipping DHCP analysis" "DHCP"
                return @([PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Server Status"
                    Value = "Not Installed"
                    Details = "DHCP Server role is not installed on this system"
                    RiskLevel = "INFO"
                    Compliance = ""
                })
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check DHCP feature status: $($_.Exception.Message)" "DHCP"
        }
        
        # Check if DhcpServer module is available
        if (-not (Get-Module -ListAvailable -Name DhcpServer)) {
            Write-LogMessage "WARN" "DhcpServer PowerShell module not available - limited analysis" "DHCP"
            
            # Fall back to service-based detection
            $DHCPService = Get-Service -Name "DHCPServer" -ErrorAction SilentlyContinue
            if ($DHCPService) {
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Service"
                    Value = $DHCPService.Status
                    Details = "DHCP Server service detected but PowerShell module unavailable for detailed analysis"
                    RiskLevel = if ($DHCPService.Status -eq "Running") { "INFO" } else { "HIGH" }
                    Compliance = "Install DhcpServer PowerShell module for complete DHCP analysis"
                }
            }
            return $Results
        }
        
        # Import DHCP Server module
        try {
            Import-Module DhcpServer -Force -ErrorAction Stop
            Write-LogMessage "SUCCESS" "DhcpServer module loaded" "DHCP"
        }
        catch {
            Write-LogMessage "ERROR" "Failed to import DhcpServer module: $($_.Exception.Message)" "DHCP"
            return @([PSCustomObject]@{
                Category = "DHCP"
                Item = "Module Error"
                Value = "Failed to load DhcpServer module"
                Details = $_.Exception.Message
                RiskLevel = "ERROR"
                Compliance = "Resolve DHCP module loading issue"
            })
        }
        
        # Get DHCP server settings
        Write-LogMessage "INFO" "Retrieving DHCP server configuration..." "DHCP"
        
        try {
            $DHCPServerSettings = Get-DhcpServerSetting -ErrorAction SilentlyContinue
            $DHCPServer = $env:COMPUTERNAME
            
            if ($DHCPServerSettings) {
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Server Status"
                    Value = "Active"
                    Details = "DHCP Server is configured and accessible"
                    RiskLevel = "INFO"
                    Compliance = ""
                }
                
                # DHCP Server Settings
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "Conflict Detection"
                    Value = if ($DHCPServerSettings.ConflictDetectionAttempts -gt 0) { "Enabled ($($DHCPServerSettings.ConflictDetectionAttempts) attempts)" } else { "Disabled" }
                    Details = "Number of ping attempts to detect IP address conflicts before lease assignment"
                    RiskLevel = if ($DHCPServerSettings.ConflictDetectionAttempts -eq 0) { "MEDIUM" } else { "LOW" }
                    Compliance = if ($DHCPServerSettings.ConflictDetectionAttempts -eq 0) { "Enable conflict detection for network stability" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Audit Logging"
                    Value = if ($DHCPServerSettings.AuditLogEnable) { "Enabled" } else { "Disabled" }
                    Details = "DHCP audit logging status for tracking lease assignments and renewals"
                    RiskLevel = if (-not $DHCPServerSettings.AuditLogEnable) { "MEDIUM" } else { "LOW" }
                    Compliance = if (-not $DHCPServerSettings.AuditLogEnable) { "Enable DHCP audit logging for security monitoring" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve DHCP server settings: $($_.Exception.Message)" "DHCP"
        }
        
        # Get DHCP Scopes
        Write-LogMessage "INFO" "Analyzing DHCP scopes..." "DHCP"
        
        try {
            $DHCPScopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
            
            if ($DHCPScopes) {
                $ScopeData = @()
                
                foreach ($Scope in $DHCPScopes) {
                    Write-LogMessage "INFO" "Analyzing scope: $($Scope.Name) ($($Scope.ScopeId))" "DHCP"
                    
                    # Get scope statistics
                    try {
                        $ScopeStats = Get-DhcpServerv4ScopeStatistics -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue
                        $UtilizationPercent = if ($ScopeStats.InUse -and $ScopeStats.Free) {
                            [math]::Round(($ScopeStats.InUse / ($ScopeStats.InUse + $ScopeStats.Free)) * 100, 2)
                        } else { 0 }
                        
                        # Determine risk level based on utilization
                        $UtilizationRisk = switch ($UtilizationPercent) {
                            {$_ -ge 90} { "HIGH" }
                            {$_ -ge 80} { "MEDIUM" }
                            {$_ -ge 70} { "LOW" }
                            default { "INFO" }
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "DHCP"
                            Item = "Scope Utilization"
                            Value = "$($Scope.Name) - $UtilizationPercent%"
                            Details = "Scope: $($Scope.ScopeId), Range: $($Scope.StartRange) - $($Scope.EndRange), In Use: $($ScopeStats.InUse), Available: $($ScopeStats.Free)"
                            RiskLevel = $UtilizationRisk
                            Compliance = if ($UtilizationPercent -ge 80) { "Consider expanding DHCP scope or reviewing lease duration" } else { "" }
                        }
                        
                        # Get reservations for this scope
                        try {
                            $Reservations = Get-DhcpServerv4Reservation -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue
                            $ReservationCount = if ($Reservations) { $Reservations.Count } else { 0 }
                            
                            $Results += [PSCustomObject]@{
                                Category = "DHCP"
                                Item = "Scope Reservations"
                                Value = "$($Scope.Name) - $ReservationCount reservations"
                                Details = "Static IP reservations in scope $($Scope.ScopeId)"
                                RiskLevel = "INFO"
                                Compliance = ""
                            }
                        }
                        catch {
                            Write-LogMessage "WARN" "Unable to get reservations for scope $($Scope.ScopeId): $($_.Exception.Message)" "DHCP"
                        }
                        
                        # Get exclusions for this scope
                        try {
                            $Exclusions = Get-DhcpServerv4ExclusionRange -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue
                            $ExclusionCount = if ($Exclusions) { $Exclusions.Count } else { 0 }
                            
                            if ($ExclusionCount -gt 0) {
                                $ExclusionRanges = ($Exclusions | ForEach-Object { "$($_.StartRange)-$($_.EndRange)" }) -join ", "
                                $Results += [PSCustomObject]@{
                                    Category = "DHCP"
                                    Item = "Scope Exclusions"
                                    Value = "$($Scope.Name) - $ExclusionCount ranges"
                                    Details = "Excluded ranges: $ExclusionRanges"
                                    RiskLevel = "INFO"
                                    Compliance = ""
                                }
                            }
                        }
                        catch {
                            Write-LogMessage "WARN" "Unable to get exclusions for scope $($Scope.ScopeId): $($_.Exception.Message)" "DHCP"
                        }
                        
                        # Check lease duration
                        $LeaseDurationDays = $Scope.LeaseDuration.TotalDays
                        $LeaseDurationRisk = if ($LeaseDurationDays -gt 30) { "MEDIUM" } elseif ($LeaseDurationDays -lt 1) { "MEDIUM" } else { "LOW" }
                        
                        $Results += [PSCustomObject]@{
                            Category = "DHCP"
                            Item = "Lease Duration"
                            Value = "$($Scope.Name) - $([math]::Round($LeaseDurationDays, 1)) days"
                            Details = "DHCP lease duration for scope $($Scope.ScopeId)"
                            RiskLevel = $LeaseDurationRisk
                            Compliance = if ($LeaseDurationDays -gt 30) { "Consider shorter lease duration for better IP management" } elseif ($LeaseDurationDays -lt 1) { "Very short lease duration may cause frequent renewals" } else { "" }
                        }
                        
                        # Store scope data for raw export
                        $ScopeData += @{
                            ScopeId = $Scope.ScopeId
                            Name = $Scope.Name
                            Description = $Scope.Description
                            StartRange = $Scope.StartRange
                            EndRange = $Scope.EndRange
                            SubnetMask = $Scope.SubnetMask
                            LeaseDuration = $Scope.LeaseDuration
                            State = $Scope.State
                            Type = $Scope.Type
                            Statistics = @{
                                InUse = $ScopeStats.InUse
                                Available = $ScopeStats.Free
                                Reserved = $ScopeStats.Reserved
                                Pending = $ScopeStats.Pending
                                UtilizationPercent = $UtilizationPercent
                            }
                            Reservations = $Reservations | ForEach-Object {
                                @{
                                    IPAddress = $_.IPAddress
                                    ClientId = $_.ClientId
                                    Name = $_.Name
                                    Description = $_.Description
                                    Type = $_.Type
                                }
                            }
                            Exclusions = $Exclusions | ForEach-Object {
                                @{
                                    StartRange = $_.StartRange
                                    EndRange = $_.EndRange
                                }
                            }
                        }
                    }
                    catch {
                        Write-LogMessage "WARN" "Unable to get statistics for scope $($Scope.ScopeId): $($_.Exception.Message)" "DHCP"
                        
                        $Results += [PSCustomObject]@{
                            Category = "DHCP"
                            Item = "Scope Configuration"
                            Value = "$($Scope.Name)"
                            Details = "Range: $($Scope.StartRange) - $($Scope.EndRange), Status: $($Scope.State) (Statistics unavailable)"
                            RiskLevel = "INFO"
                            Compliance = ""
                        }
                    }
                }
                
                # Add raw data collection
                Add-RawDataCollection -CollectionName "DHCPScopes" -Data $ScopeData
                
                # Summary
                $TotalScopes = $DHCPScopes.Count
                $ActiveScopes = ($DHCPScopes | Where-Object { $_.State -eq "Active" }).Count
                
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Scope Summary"
                    Value = "$TotalScopes total scopes ($ActiveScopes active)"
                    Details = "Total configured DHCP scopes on this server"
                    RiskLevel = "INFO"
                    Compliance = ""
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Scopes"
                    Value = "No scopes configured"
                    Details = "DHCP Server role is installed but no scopes are configured"
                    RiskLevel = "MEDIUM"
                    Compliance = "Configure DHCP scopes if this server should provide DHCP services"
                }
            }
        }
        catch {
            Write-LogMessage "ERROR" "Failed to analyze DHCP scopes: $($_.Exception.Message)" "DHCP"
            $Results += [PSCustomObject]@{
                Category = "DHCP"
                Item = "Scope Analysis Error"
                Value = "Failed"
                Details = "Unable to retrieve DHCP scope information: $($_.Exception.Message)"
                RiskLevel = "ERROR"
                Compliance = "Investigate DHCP scope access permissions"
            }
        }
        
        # Check DHCP Options (Server-level)
        try {
            $ServerOptions = Get-DhcpServerv4OptionValue -All -ErrorAction SilentlyContinue
            if ($ServerOptions) {
                $ImportantOptions = @{
                    3 = "Router (Default Gateway)"
                    6 = "DNS Servers"
                    15 = "Domain Name"
                    44 = "WINS Servers"
                    46 = "WINS Node Type"
                }
                
                foreach ($Option in $ServerOptions) {
                    if ($ImportantOptions.ContainsKey($Option.OptionId)) {
                        $OptionName = $ImportantOptions[$Option.OptionId]
                        $OptionValue = $Option.Value -join ", "
                        
                        $Results += [PSCustomObject]@{
                            Category = "DHCP"
                            Item = "Server DHCP Option"
                            Value = "$OptionName"
                            Details = "Option $($Option.OptionId): $OptionValue"
                            RiskLevel = "INFO"
                            Compliance = ""
                        }
                    }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve DHCP server options: $($_.Exception.Message)" "DHCP"
        }
        
        Write-LogMessage "SUCCESS" "DHCP analysis completed" "DHCP"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze DHCP configuration: $($_.Exception.Message)" "DHCP"
        return @([PSCustomObject]@{
            Category = "DHCP"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during DHCP analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Compliance = "Investigate DHCP analysis failure"
        })
    }
}
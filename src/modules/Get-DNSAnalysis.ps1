# WindowsServerAuditor - DNS Analysis Module
# Version 1.3.0

function Get-DNSAnalysis {
    <#
    .SYNOPSIS
        Analyzes DNS server configuration and zone information (read-only)
        
    .DESCRIPTION
        Performs DNS server discovery and analysis including:
        - DNS service status and configuration
        - DNS zones and record counts
        - Forwarder configuration
        - DNS security settings (read-only queries only)
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Compliance
        
    .NOTES
        Version: 1.3.0
        Dependencies: Write-LogMessage, Add-RawDataCollection
        Permissions: DNS Admin rights recommended for complete analysis
        Safety: READ-ONLY - No configuration changes made
    #>
    
    Write-LogMessage "INFO" "Analyzing DNS server configuration..." "DNS"
    
    try {
        $Results = @()
        
        # Check if DNS Server role is installed
        try {
            $DNSFeature = Get-WindowsFeature -Name "DNS" -ErrorAction SilentlyContinue
            if (-not $DNSFeature -or $DNSFeature.InstallState -ne "Installed") {
                Write-LogMessage "INFO" "DNS Server role not installed - skipping DNS analysis" "DNS"
                return @([PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Server Status"
                    Value = "Not Installed"
                    Details = "DNS Server role is not installed on this system"
                    RiskLevel = "INFO"
                    Compliance = ""
                })
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check DNS feature status: $($_.Exception.Message)" "DNS"
        }
        
        # Check if DnsServer module is available
        if (-not (Get-Module -ListAvailable -Name DnsServer)) {
            Write-LogMessage "WARN" "DnsServer PowerShell module not available - limited analysis" "DNS"
            
            # Check DNS service status only
            $DNSService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
            if ($DNSService) {
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Service"
                    Value = $DNSService.Status
                    Details = "DNS Server service detected but PowerShell module unavailable for detailed analysis"
                    RiskLevel = if ($DNSService.Status -eq "Running") { "INFO" } else { "HIGH" }
                    Compliance = "Install DnsServer PowerShell module for complete DNS analysis"
                }
            }
            return $Results
        }
        
        # Import DNS Server module (read-only)
        try {
            Import-Module DnsServer -Force -ErrorAction Stop
            Write-LogMessage "SUCCESS" "DnsServer module loaded" "DNS"
        }
        catch {
            Write-LogMessage "ERROR" "Failed to import DnsServer module: $($_.Exception.Message)" "DNS"
            return @([PSCustomObject]@{
                Category = "DNS"
                Item = "Module Error"
                Value = "Failed to load DnsServer module"
                Details = $_.Exception.Message
                RiskLevel = "ERROR"
                Compliance = "Resolve DNS module loading issue"
            })
        }
        
        # Get DNS server configuration (read-only)
        Write-LogMessage "INFO" "Retrieving DNS server configuration..." "DNS"
        
        try {
            # DNS server settings
            $DNSServerSettings = Get-DnsServerSetting -ErrorAction SilentlyContinue
            
            if ($DNSServerSettings) {
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Server Status"
                    Value = "Active"
                    Details = "DNS Server is configured and accessible"
                    RiskLevel = "INFO"
                    Compliance = ""
                }
                
                # Check recursion settings
                $RecursionStatus = if ($DNSServerSettings.EnableRecursion) { "Enabled" } else { "Disabled" }
                $RecursionRisk = if ($DNSServerSettings.EnableRecursion) { "MEDIUM" } else { "LOW" }
                
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Recursion"
                    Value = $RecursionStatus
                    Details = "DNS recursion allows the server to perform lookups for clients"
                    RiskLevel = $RecursionRisk
                    Compliance = if ($DNSServerSettings.EnableRecursion) { "Consider disabling recursion on public-facing DNS servers" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve DNS server settings: $($_.Exception.Message)" "DNS"
        }
        
        # Get DNS zones (read-only enumeration)
        Write-LogMessage "INFO" "Analyzing DNS zones..." "DNS"
        
        try {
            $DNSZones = Get-DnsServerZone -ErrorAction SilentlyContinue
            
            if ($DNSZones) {
                $ZoneData = @()
                
                # Count zones by type
                $PrimaryZones = $DNSZones | Where-Object { $_.ZoneType -eq "Primary" }
                $SecondaryZones = $DNSZones | Where-Object { $_.ZoneType -eq "Secondary" }
                $ForwardZones = $DNSZones | Where-Object { $_.IsReverseLookupZone -eq $false }
                $ReverseZones = $DNSZones | Where-Object { $_.IsReverseLookupZone -eq $true }
                
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Zone Summary"
                    Value = "$($DNSZones.Count) total zones"
                    Details = "Primary: $($PrimaryZones.Count), Secondary: $($SecondaryZones.Count), Forward: $($ForwardZones.Count), Reverse: $($ReverseZones.Count)"
                    RiskLevel = "INFO"
                    Compliance = ""
                }
                
                # Analyze each zone (limited to first 10 for performance)
                $ZonesToAnalyze = $DNSZones | Select-Object -First 10
                
                foreach ($Zone in $ZonesToAnalyze) {
                    Write-LogMessage "INFO" "Analyzing zone: $($Zone.ZoneName)" "DNS"
                    
                    try {
                        # Get record count (read-only query)
                        $ResourceRecords = Get-DnsServerResourceRecord -ZoneName $Zone.ZoneName -ErrorAction SilentlyContinue
                        $RecordCount = if ($ResourceRecords) { $ResourceRecords.Count } else { 0 }
                        
                        # Determine zone risk level
                        $ZoneRisk = switch ($Zone.ZoneType) {
                            "Primary" { "INFO" }
                            "Secondary" { "LOW" }
                            "Stub" { "LOW" }
                            default { "INFO" }
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "DNS"
                            Item = "DNS Zone"
                            Value = "$($Zone.ZoneName) ($($Zone.ZoneType))"
                            Details = "Records: $RecordCount, Reverse lookup: $($Zone.IsReverseLookupZone), Dynamic updates: $($Zone.DynamicUpdate)"
                            RiskLevel = $ZoneRisk
                            Compliance = ""
                        }
                        
                        # Store zone data for raw export
                        $ZoneData += @{
                            ZoneName = $Zone.ZoneName
                            ZoneType = $Zone.ZoneType
                            IsReverseLookupZone = $Zone.IsReverseLookupZone
                            DynamicUpdate = $Zone.DynamicUpdate
                            RecordCount = $RecordCount
                            ZoneFile = $Zone.ZoneFile
                            IsDsIntegrated = $Zone.IsDsIntegrated
                        }
                        
                        # Check for potentially risky configurations
                        if ($Zone.DynamicUpdate -eq "NonsecureAndSecure") {
                            $Results += [PSCustomObject]@{
                                Category = "DNS"
                                Item = "Dynamic Update Risk"
                                Value = "$($Zone.ZoneName) - Nonsecure updates allowed"
                                Details = "Zone allows both secure and nonsecure dynamic updates"
                                RiskLevel = "MEDIUM"
                                Compliance = "Consider restricting to secure dynamic updates only"
                            }
                        }
                    }
                    catch {
                        Write-LogMessage "WARN" "Unable to analyze zone $($Zone.ZoneName): $($_.Exception.Message)" "DNS"
                    }
                }
                
                # Add zone data to raw collection
                Add-RawDataCollection -CollectionName "DNSZones" -Data $ZoneData
            } else {
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Zones"
                    Value = "No zones configured"
                    Details = "DNS Server role is installed but no zones are configured"
                    RiskLevel = "MEDIUM"
                    Compliance = "Configure DNS zones if this server should provide DNS services"
                }
            }
        }
        catch {
            Write-LogMessage "ERROR" "Failed to analyze DNS zones: $($_.Exception.Message)" "DNS"
            $Results += [PSCustomObject]@{
                Category = "DNS"
                Item = "Zone Analysis Error"
                Value = "Failed"
                Details = "Unable to retrieve DNS zone information: $($_.Exception.Message)"
                RiskLevel = "ERROR"
                Compliance = "Investigate DNS zone access permissions"
            }
        }
        
        # Check DNS forwarders (read-only)
        try {
            $DNSForwarders = Get-DnsServerForwarder -ErrorAction SilentlyContinue
            
            if ($DNSForwarders -and $DNSForwarders.IPAddress -and $DNSForwarders.IPAddress.Count -gt 0) {
                $ForwarderList = $DNSForwarders.IPAddress -join ", "
                $ForwarderTimeout = $DNSForwarders.Timeout
                
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Forwarders"
                    Value = "$($DNSForwarders.IPAddress.Count) forwarders configured"
                    Details = "Forwarders: $ForwarderList, Timeout: $ForwarderTimeout seconds"
                    RiskLevel = "INFO"
                    Compliance = ""
                }
                
                # Check for public DNS forwarders
                $PublicDNS = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "4.2.2.2", "208.67.222.222")
                $PublicForwarders = $DNSForwarders.IPAddress | Where-Object { $_ -in $PublicDNS }
                
                if ($PublicForwarders) {
                    $Results += [PSCustomObject]@{
                        Category = "DNS"
                        Item = "Public DNS Forwarders"
                        Value = "$($PublicForwarders.Count) public forwarders detected"
                        Details = "Public DNS servers: $($PublicForwarders -join ', ')"
                        RiskLevel = "MEDIUM"
                        Compliance = "Consider using internal or ISP DNS forwarders for better control"
                    }
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Forwarders"
                    Value = "No forwarders configured"
                    Details = "DNS server is not configured to forward queries"
                    RiskLevel = "LOW"
                    Compliance = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve DNS forwarder configuration: $($_.Exception.Message)" "DNS"
        }
        
        Write-LogMessage "SUCCESS" "DNS analysis completed" "DNS"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze DNS configuration: $($_.Exception.Message)" "DNS"
        return @([PSCustomObject]@{
            Category = "DNS"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during DNS analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Compliance = "Investigate DNS analysis failure"
        })
    }
}
# WindowsWorkstationAuditor - Memory Analysis Module
# Version 1.3.0

function Get-MemoryAnalysis {
    <#
    .SYNOPSIS
        Analyzes system memory usage, virtual memory, and performance counters
        
    .DESCRIPTION
        Collects comprehensive memory information including RAM usage, virtual memory
        configuration, page file settings, and memory performance analysis.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Compliance
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (WMI and performance counter access)
    #>
    
    Write-LogMessage "INFO" "Analyzing memory usage and performance..." "MEMORY"
    
    try {
        $Results = @()
        
        # Get physical memory information
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem
        $Computer = Get-CimInstance -ClassName Win32_ComputerSystem
        
        $TotalMemoryGB = [math]::Round($Computer.TotalPhysicalMemory / 1GB, 2)
        $FreeMemoryGB = [math]::Round($OS.FreePhysicalMemory / 1KB / 1MB, 2)
        $UsedMemoryGB = $TotalMemoryGB - $FreeMemoryGB
        $MemoryUsagePercent = [math]::Round(($UsedMemoryGB / $TotalMemoryGB) * 100, 1)
        
        # Determine memory usage risk level
        $MemoryRiskLevel = if ($MemoryUsagePercent -gt 85) { "HIGH" }
                          elseif ($MemoryUsagePercent -gt 75) { "MEDIUM" }
                          else { "LOW" }
        
        $MemoryCompliance = if ($MemoryUsagePercent -gt 80) {
            "High memory usage may impact system performance"
        } else { "" }
        
        $Results += [PSCustomObject]@{
            Category = "Memory"
            Item = "Physical Memory Usage"
            Value = "$MemoryUsagePercent% used"
            Details = "Total: $TotalMemoryGB GB, Used: $UsedMemoryGB GB, Free: $FreeMemoryGB GB"
            RiskLevel = $MemoryRiskLevel
            Compliance = $MemoryCompliance
        }
        
        Write-LogMessage "INFO" "Physical Memory: $MemoryUsagePercent% used ($UsedMemoryGB GB / $TotalMemoryGB GB)" "MEMORY"
        
        # Get virtual memory (page file) information
        try {
            $PageFiles = Get-CimInstance -ClassName Win32_PageFileUsage
            if ($PageFiles) {
                foreach ($PageFile in $PageFiles) {
                    $PageFileSizeGB = [math]::Round($PageFile.AllocatedBaseSize / 1024, 2)
                    $PageFileUsedGB = [math]::Round($PageFile.CurrentUsage / 1024, 2)
                    $PageFileUsagePercent = if ($PageFileSizeGB -gt 0) { 
                        [math]::Round(($PageFileUsedGB / $PageFileSizeGB) * 100, 1) 
                    } else { 0 }
                    
                    $PageFileRisk = if ($PageFileUsagePercent -gt 80) { "HIGH" }
                                   elseif ($PageFileUsagePercent -gt 60) { "MEDIUM" }
                                   else { "LOW" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Memory"
                        Item = "Virtual Memory"
                        Value = "$PageFileUsagePercent% used"
                        Details = "Page File: $($PageFile.Name), Size: $PageFileSizeGB GB, Used: $PageFileUsedGB GB"
                        RiskLevel = $PageFileRisk
                        Compliance = if ($PageFileUsagePercent -gt 70) { "Monitor virtual memory usage" } else { "" }
                    }
                    
                    Write-LogMessage "INFO" "Page File $($PageFile.Name): $PageFileUsagePercent% used ($PageFileUsedGB GB / $PageFileSizeGB GB)" "MEMORY"
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Memory"
                    Item = "Virtual Memory"
                    Value = "No page file configured"
                    Details = "System has no virtual memory page file"
                    RiskLevel = "MEDIUM"
                    Compliance = "Consider configuring virtual memory for system stability"
                }
                Write-LogMessage "WARN" "No page file configured on system" "MEMORY"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve page file information: $($_.Exception.Message)" "MEMORY"
        }
        
        # Get memory performance counters
        try {
            $AvailableBytes = (Get-Counter "\Memory\Available Bytes" -SampleInterval 1 -MaxSamples 1).CounterSamples[0].CookedValue
            $AvailableMB = [math]::Round($AvailableBytes / 1MB, 0)
            
            $CommittedBytes = (Get-Counter "\Memory\Committed Bytes" -SampleInterval 1 -MaxSamples 1).CounterSamples[0].CookedValue
            $CommittedMB = [math]::Round($CommittedBytes / 1MB, 0)
            
            $Results += [PSCustomObject]@{
                Category = "Memory"
                Item = "Available Memory"
                Value = "$AvailableMB MB available"
                Details = "System has $AvailableMB MB available for allocation"
                RiskLevel = if ($AvailableMB -lt 512) { "HIGH" } elseif ($AvailableMB -lt 1024) { "MEDIUM" } else { "LOW" }
                Compliance = if ($AvailableMB -lt 1024) { "Low available memory may impact performance" } else { "" }
            }
            
            $Results += [PSCustomObject]@{
                Category = "Memory"
                Item = "Committed Memory"
                Value = "$CommittedMB MB committed"
                Details = "System has committed $CommittedMB MB of virtual memory"
                RiskLevel = "INFO"
                Compliance = ""
            }
            
            Write-LogMessage "INFO" "Memory Performance: Available: $AvailableMB MB, Committed: $CommittedMB MB" "MEMORY"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve memory performance counters: $($_.Exception.Message)" "MEMORY"
        }
        
        Write-LogMessage "SUCCESS" "Memory analysis completed - Total RAM: $TotalMemoryGB GB, Usage: $MemoryUsagePercent%" "MEMORY"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze memory: $($_.Exception.Message)" "MEMORY"
        return @()
    }
}
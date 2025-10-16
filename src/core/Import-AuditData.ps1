# NetworkAuditAggregator - JSON Import Module
# Version 1.0.0

function Import-AuditData {
    <#
    .SYNOPSIS
        Imports and consolidates JSON audit files from multiple systems
        
    .DESCRIPTION
        Scans the import directory for audit JSON files, validates their format,
        and consolidates findings into a unified data structure for reporting.
        
    .PARAMETER ImportPath
        Directory containing JSON audit files
        
    .OUTPUTS
        PSCustomObject with SystemCount, FindingCount, Systems, and AllFindings
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImportPath
    )
    
    Write-Verbose "Scanning for audit files in: $ImportPath"
    
    # Initialize result structure
    $Result = [PSCustomObject]@{
        SystemCount = 0
        FindingCount = 0
        Systems = @()
        AllFindings = @()
        ImportedFiles = @()
        Errors = @()
    }
    
    # Ensure import directory exists
    if (-not (Test-Path $ImportPath)) {
        Write-Warning "Import directory does not exist: $ImportPath"
        return $Result
    }
    
    # Find JSON audit files (system audits and dark web checks)
    $SystemFiles = Get-ChildItem -Path $ImportPath -Filter "*_raw_data.json" -File
    $DarkWebFiles = Get-ChildItem -Path $ImportPath -Filter "darkweb-check-*.json" -File
    $JsonFiles = @($SystemFiles) + @($DarkWebFiles)
    Write-Verbose "Found $($JsonFiles.Count) audit files ($($SystemFiles.Count) system, $($DarkWebFiles.Count) dark web)"
    
    foreach ($JsonFile in $JsonFiles) {
        try {
            Write-Verbose "Processing: $($JsonFile.Name)"
            
            # Read and parse JSON (handle BOM characters)
            $JsonContent = Get-Content $JsonFile.FullName -Raw -Encoding UTF8
            # Remove BOM if present
            if ($JsonContent.Length -gt 0 -and $JsonContent[0] -eq [char]0xFEFF) {
                $JsonContent = $JsonContent.Substring(1)
            }
            $AuditData = $JsonContent | ConvertFrom-Json
            
            # Determine file type and validate structure
            $IsDarkWebFile = $JsonFile.Name -like "darkweb-check-*"

            if ($IsDarkWebFile) {
                # Validate dark web file structure
                if (-not $AuditData.Results -or -not $AuditData.Summary) {
                    Write-Warning "Invalid dark web file format: $($JsonFile.Name) - Missing Results or Summary"
                    $Result.Errors += "Invalid format: $($JsonFile.Name)"
                    continue
                }
            } else {
                # Validate system audit file structure - support both old and new formats
                $HasOldFormat = $AuditData.metadata -and $AuditData.compliance_framework.findings
                $HasNewFormat = $AuditData.metadata -and $AuditData.categories

                if (-not $HasOldFormat -and -not $HasNewFormat) {
                    Write-Warning "Invalid audit file format: $($JsonFile.Name) - Missing metadata or findings structure"
                    $Result.Errors += "Invalid format: $($JsonFile.Name)"
                    continue
                }
            }
            
            # Extract system information based on file type
            if ($IsDarkWebFile) {
                $SystemInfo = [PSCustomObject]@{
                    ComputerName = "Dark Web Check"
                    AuditTimestamp = $AuditData.CheckDate
                    ToolVersion = "DarkWebChecker v1.0"
                    FileName = $JsonFile.Name
                    FileSize = [math]::Round($JsonFile.Length / 1KB, 1)
                    FindingCount = $AuditData.Summary.BreachesFound
                    OperatingSystem = "Dark Web Analysis"
                    SystemType = "Breach Monitor"
                    Domain = ""
                    LastBootTime = ""
                }
            } else {
                # Count findings based on format
                $TotalFindings = 0
                if ($AuditData.compliance_framework.findings) {
                    $TotalFindings = $AuditData.compliance_framework.findings.Count
                } elseif ($AuditData.categories) {
                    # Count findings across all categories
                    $AuditData.categories.PSObject.Properties | ForEach-Object {
                        if ($_.Value.findings) {
                            $TotalFindings += $_.Value.findings.Count
                        }
                    }
                }

                $SystemInfo = [PSCustomObject]@{
                    ComputerName = $AuditData.metadata.computer_name
                    AuditTimestamp = $AuditData.metadata.audit_timestamp
                    ToolVersion = $AuditData.metadata.tool_version
                    FileName = $JsonFile.Name
                    FileSize = [math]::Round($JsonFile.Length / 1KB, 1)
                    FindingCount = $TotalFindings
                    OperatingSystem = ""
                    SystemType = "Unknown"
                    Domain = ""
                    LastBootTime = ""
                }
            }
            
            # Extract additional system details (only for system audit files)
            if (-not $IsDarkWebFile) {
                if ($AuditData.system_context -and $AuditData.system_context.os_info) {
                    $SystemInfo.OperatingSystem = $AuditData.system_context.os_info.caption
                    $SystemInfo.Domain = $AuditData.system_context.domain
                    $SystemInfo.LastBootTime = $AuditData.system_context.os_info.last_boot_time
                }

                # Determine system type from server roles or OS
                if ($AuditData.system_context.os_info.caption -like "*Server*") {
                    $SystemInfo.SystemType = "Server"
                } else {
                    $SystemInfo.SystemType = "Workstation"
                }
            }
            
            # Add system to collection
            $Result.Systems += $SystemInfo
            $Result.SystemCount++
            
            # Process findings based on file type
            if ($IsDarkWebFile) {
                # Process dark web results (limit to max 10 results as requested)
                $DarkWebFindings = $AuditData.Results | Where-Object { $_.Item -like "*Domain Breach*" } | Select-Object -First 10

                foreach ($Finding in $DarkWebFindings) {
                    $EnrichedFinding = [PSCustomObject]@{
                        Category = $Finding.Category
                        Item = $Finding.Item
                        Value = $Finding.Value
                        Details = $Finding.Details
                        RiskLevel = $Finding.RiskLevel
                        Recommendation = $Finding.Recommendation
                        SystemName = "Dark Web Check"
                        SystemType = "Breach Monitor"
                        AuditDate = $SystemInfo.AuditTimestamp
                        FindingId = "DW-$(Get-Random)"
                        Framework = "Dark Web"
                    }

                    $Result.AllFindings += $EnrichedFinding
                    $Result.FindingCount++
                }
            } else {
                # Process system audit findings - handle both old and new formats
                if ($AuditData.compliance_framework.findings) {
                    # Old format: compliance_framework.findings array
                    foreach ($Finding in $AuditData.compliance_framework.findings) {
                        if (-not $Finding.category -or -not $Finding.item) {
                            Write-Verbose "Skipping finding with missing category or item in $($JsonFile.Name)"
                            continue
                        }

                        $EnrichedFinding = [PSCustomObject]@{
                            Category = if ($Finding.category) { [string]$Finding.category } else { "Unknown" }
                            Item = if ($Finding.item) { [string]$Finding.item } else { "Unknown" }
                            Value = ""
                            Details = if ($Finding.requirement) { [string]$Finding.requirement } else { "No details available" }
                            RiskLevel = if ($Finding.risk_level) { [string]$Finding.risk_level } else { "INFO" }
                            Recommendation = if ($Finding.requirement) { [string]$Finding.requirement } else { "No recommendation available" }
                            SystemName = if ($SystemInfo.ComputerName) { [string]$SystemInfo.ComputerName } else { "Unknown" }
                            SystemType = if ($SystemInfo.SystemType) { [string]$SystemInfo.SystemType } else { "Unknown" }
                            AuditDate = if ($SystemInfo.AuditTimestamp) { [string]$SystemInfo.AuditTimestamp } else { "Unknown" }
                            FindingId = if ($Finding.finding_id) { [string]$Finding.finding_id } else { "UNKNOWN-$(Get-Random)" }
                            Framework = if ($Finding.framework) { [string]$Finding.framework } else { "Unknown" }
                        }

                        $Result.AllFindings += $EnrichedFinding
                        $Result.FindingCount++
                    }
                } elseif ($AuditData.categories) {
                    # New format: categories with nested findings
                    $AuditData.categories.PSObject.Properties | ForEach-Object {
                        $CategoryName = $_.Name
                        $CategoryData = $_.Value

                        if ($CategoryData.findings) {
                            foreach ($Finding in $CategoryData.findings) {
                                if (-not $Finding.item_name) {
                                    Write-Verbose "Skipping finding with missing item_name in $($JsonFile.Name)"
                                    continue
                                }

                                $EnrichedFinding = [PSCustomObject]@{
                                    Category = if ($Finding.category) { [string]$Finding.category } else { [string]$CategoryName }
                                    Item = if ($Finding.item_name) { [string]$Finding.item_name } else { "Unknown" }
                                    Value = if ($Finding.value) { [string]$Finding.value } else { "" }
                                    Details = if ($Finding.details) { [string]$Finding.details } else { "No details available" }
                                    RiskLevel = if ($Finding.risk_level) { [string]$Finding.risk_level } else { "INFO" }
                                    Recommendation = if ($Finding.recommendation_note) { [string]$Finding.recommendation_note } else { "" }
                                    SystemName = if ($SystemInfo.ComputerName) { [string]$SystemInfo.ComputerName } else { "Unknown" }
                                    SystemType = if ($SystemInfo.SystemType) { [string]$SystemInfo.SystemType } else { "Unknown" }
                                    AuditDate = if ($SystemInfo.AuditTimestamp) { [string]$SystemInfo.AuditTimestamp } else { "Unknown" }
                                    FindingId = if ($Finding.id) { [string]$Finding.id } else { "UNKNOWN-$(Get-Random)" }
                                    Framework = "WindowsAudit"
                                }

                                $Result.AllFindings += $EnrichedFinding
                                $Result.FindingCount++
                            }
                        }
                    }
                }
            }
            
            $Result.ImportedFiles += $JsonFile.Name
            if ($IsDarkWebFile) {
                Write-Verbose "  > Imported $($DarkWebFindings.Count) dark web findings"
            } else {
                Write-Verbose "  > Imported $($SystemInfo.FindingCount) findings from $($SystemInfo.ComputerName)"
            }
            
        }
        catch {
            Write-Warning "Failed to process $($JsonFile.Name): $($_.Exception.Message)"
            $Result.Errors += "Processing error: $($JsonFile.Name) - $($_.Exception.Message)"
        }
    }
    
    # Generate summary statistics
    if ($Result.SystemCount -gt 0) {
        $Result | Add-Member -NotePropertyName "RiskSummary" -NotePropertyValue @{
            HighRisk = ($Result.AllFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
            MediumRisk = ($Result.AllFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count  
            LowRisk = ($Result.AllFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
            Info = ($Result.AllFindings | Where-Object { $_.RiskLevel -eq "INFO" }).Count
        }
        
        $Result | Add-Member -NotePropertyName "CategoryBreakdown" -NotePropertyValue (
            $Result.AllFindings | Group-Object Category | 
            ForEach-Object { [PSCustomObject]@{ Category = $_.Name; Count = $_.Count } }
        )
        
        Write-Verbose "Risk Summary: HIGH=$($Result.RiskSummary.HighRisk), MEDIUM=$($Result.RiskSummary.MediumRisk), LOW=$($Result.RiskSummary.LowRisk), INFO=$($Result.RiskSummary.Info)"
    }
    
    return $Result
}
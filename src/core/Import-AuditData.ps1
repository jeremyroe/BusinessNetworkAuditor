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
                # Validate system audit file structure
                if (-not $AuditData.metadata -or -not $AuditData.compliance_framework.findings) {
                    Write-Warning "Invalid audit file format: $($JsonFile.Name) - Missing metadata or compliance_framework.findings"
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
                $SystemInfo = [PSCustomObject]@{
                    ComputerName = $AuditData.metadata.computer_name
                    AuditTimestamp = $AuditData.metadata.audit_timestamp
                    ToolVersion = $AuditData.metadata.tool_version
                    FileName = $JsonFile.Name
                    FileSize = [math]::Round($JsonFile.Length / 1KB, 1)
                    FindingCount = $AuditData.compliance_framework.findings.Count
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
                # Process system audit findings
                foreach ($Finding in $AuditData.compliance_framework.findings) {
                    # Map the compliance framework structure to expected format
                    $EnrichedFinding = [PSCustomObject]@{
                        Category = $Finding.category
                        Item = $Finding.item
                        Value = "" # Not available in compliance framework
                        Details = $Finding.requirement
                        RiskLevel = $Finding.risk_level
                        Recommendation = $Finding.requirement
                        SystemName = $SystemInfo.ComputerName
                        SystemType = $SystemInfo.SystemType
                        AuditDate = $SystemInfo.AuditTimestamp
                        FindingId = $Finding.finding_id
                        Framework = $Finding.framework
                    }

                    $Result.AllFindings += $EnrichedFinding
                    $Result.FindingCount++
                }
            }
            
            $Result.ImportedFiles += $JsonFile.Name
            if ($IsDarkWebFile) {
                Write-Verbose "  → Imported $($DarkWebFindings.Count) dark web findings"
            } else {
                Write-Verbose "  → Imported $($AuditData.compliance_framework.findings.Count) findings from $($SystemInfo.ComputerName)"
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
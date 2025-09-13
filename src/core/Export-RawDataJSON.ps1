# WindowsWorkstationAuditor - Raw Data JSON Export Module
# Version 1.3.0

function Export-RawDataJSON {
    <#
    .SYNOPSIS
        Exports comprehensive audit data to structured JSON for aggregation tools
        
    .DESCRIPTION
        Creates a detailed JSON export with complete data structures, raw collections,
        metadata, and standardized schema for use by aggregation and analysis tools.
        
    .PARAMETER Results
        Array of audit results from modules
        
    .PARAMETER RawData
        Hashtable of raw data collections from modules (optional)
        
    .PARAMETER OutputPath
        Directory path for the JSON output
        
    .PARAMETER BaseFileName
        Base filename for the export (without extension)
    #>
    param(
        [array]$Results,
        [hashtable]$RawData = @{},
        [string]$OutputPath,
        [string]$BaseFileName
    )
    
    if (-not $Results -or $Results.Count -eq 0) {
        Write-LogMessage "WARN" "No results to export to raw JSON" "EXPORT"
        return
    }
    
    $JSONPath = Join-Path $OutputPath "${BaseFileName}_raw_data.json"
    
    try {
        # Build comprehensive data structure
        $AuditData = [ordered]@{
            metadata = [ordered]@{
                tool_name = "WindowsWorkstationAuditor"
                tool_version = "1.3.0"
                schema_version = "1.0"
                computer_name = $env:COMPUTERNAME
                audit_timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                audit_duration_seconds = if ($Script:StartTime) { ((Get-Date) - $Script:StartTime).TotalSeconds } else { 0 }
                total_findings = $Results.Count
            }
            
            risk_summary = [ordered]@{
                high_risk_count = ($Results | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
                medium_risk_count = ($Results | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
                low_risk_count = ($Results | Where-Object { $_.RiskLevel -eq "LOW" }).Count
                info_count = ($Results | Where-Object { $_.RiskLevel -eq "INFO" }).Count
                recommendation_findings = ($Results | Where-Object { $_.Recommendation -and $_.Recommendation.Trim() -ne "" }).Count
            }
            
            categories = [ordered]@{}
            
            raw_collections = [ordered]@{}
            
            recommendation_framework = [ordered]@{
                primary = "NIST"
                findings = @()
            }
        }
        
        # Process results by category
        $Categories = $Results | Group-Object Category
        
        foreach ($Category in $Categories) {
            $CategoryName = $Category.Name
            $CategoryItems = $Category.Group
            
            $AuditData.categories[$CategoryName] = [ordered]@{
                total_items = $CategoryItems.Count
                risk_breakdown = [ordered]@{
                    high = ($CategoryItems | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
                    medium = ($CategoryItems | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
                    low = ($CategoryItems | Where-Object { $_.RiskLevel -eq "LOW" }).Count
                    info = ($CategoryItems | Where-Object { $_.RiskLevel -eq "INFO" }).Count
                }
                findings = @()
            }
            
            # Add each finding with enhanced structure
            foreach ($Item in $CategoryItems) {
                $Finding = [ordered]@{
                    id = [System.Guid]::NewGuid().ToString()
                    item_name = $Item.Item
                    value = $Item.Value
                    details = $Item.Details
                    risk_level = $Item.RiskLevel
                    recommendation_note = $Item.Recommendation
                    category = $Item.Category
                    timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
                
                $AuditData.categories[$CategoryName].findings += $Finding
                
                # Add to recommendation findings if applicable
                if ($Item.Recommendation -and $Item.Recommendation.Trim() -ne "") {
                    $RecommendationFinding = [ordered]@{
                        finding_id = $Finding.id
                        framework = "NIST"
                        recommendation = $Item.Recommendation
                        category = $CategoryName
                        item = $Item.Item
                        risk_level = $Item.RiskLevel
                    }
                    $AuditData.recommendation_framework.findings += $RecommendationFinding
                }
            }
        }
        
        # Add raw data collections if provided
        foreach ($DataType in $RawData.Keys) {
            $AuditData.raw_collections[$DataType] = $RawData[$DataType]
        }
        
        # Add system context data
        $AuditData.system_context = [ordered]@{
            powershell_version = $PSVersionTable.PSVersion.ToString()
            execution_policy = (Get-ExecutionPolicy).ToString()
            current_user = $env:USERNAME
            domain = $env:USERDOMAIN
            os_info = [ordered]@{}
        }
        
        # Try to get OS information
        try {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ($OS) {
                $AuditData.system_context.os_info = [ordered]@{
                    caption = $OS.Caption
                    version = $OS.Version
                    build_number = $OS.BuildNumber
                    architecture = $OS.OSArchitecture
                    install_date = if ($OS.InstallDate) { $OS.InstallDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { $null }
                    last_boot_time = if ($OS.LastBootUpTime) { $OS.LastBootUpTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { $null }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve OS information for JSON export: $($_.Exception.Message)" "EXPORT"
        }
        
        # Export with proper formatting
        $JSONContent = $AuditData | ConvertTo-Json -Depth 10 -Compress:$false
        $JSONContent | Set-Content -Path $JSONPath -Encoding UTF8
        
        Write-LogMessage "SUCCESS" "Raw data JSON exported: $JSONPath" "EXPORT"
        return $JSONPath
    }
    catch {
        Write-LogMessage "ERROR" "Failed to export raw JSON: $($_.Exception.Message)" "EXPORT"
        return $null
    }
}

function Add-RawDataCollection {
    <#
    .SYNOPSIS
        Helper function for modules to register raw data collections
        
    .DESCRIPTION
        Allows audit modules to register detailed data collections that should
        be included in the raw JSON export for aggregation tools.
        
    .PARAMETER CollectionName
        Name of the data collection
        
    .PARAMETER Data
        Raw data to be included in export
        
    .PARAMETER Global:RawDataCollections
        Global hashtable to store collections (created if doesn't exist)
    #>
    param(
        [string]$CollectionName,
        [object]$Data
    )
    
    if (-not (Get-Variable -Name "RawDataCollections" -Scope Global -ErrorAction SilentlyContinue)) {
        $Global:RawDataCollections = @{}
    }
    
    $Global:RawDataCollections[$CollectionName] = $Data
    Write-LogMessage "INFO" "Added raw data collection: $CollectionName ($($Data.Count) items)" "EXPORT"
}
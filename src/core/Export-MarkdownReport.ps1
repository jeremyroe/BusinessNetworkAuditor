# WindowsWorkstationAuditor - Markdown Report Export Module
# Version 1.3.0

function Export-MarkdownReport {
    <#
    .SYNOPSIS
        Exports audit results to a technician-friendly markdown report
        
    .DESCRIPTION
        Creates a comprehensive markdown report with executive summary,
        detailed findings, action items, and full data visibility for technicians.
        
    .PARAMETER Results
        Array of audit results to include in the report
        
    .PARAMETER OutputPath
        Directory path for the markdown report output
        
    .PARAMETER BaseFileName
        Base filename for the report (without extension)
    #>
    param(
        [array]$Results,
        [string]$OutputPath,
        [string]$BaseFileName
    )

    if (-not $Results -or $Results.Count -eq 0) {
        Write-LogMessage "WARN" "No results to export to markdown report" "EXPORT"
        return
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Write-LogMessage "ERROR" "OutputPath is null or empty - cannot create report" "EXPORT"
        throw "OutputPath parameter is required but was null or empty"
    }

    $ReportPath = Join-Path $OutputPath "${BaseFileName}_technician_report.md"
    
    try {
        # Build report content
        $ReportContent = @()
        
        # Header
        #region Report Header Generation
        # Auto-detect if this is a server audit based on results content or OS type
        $IsServerAudit = $false
        
        # Method 1: Check if server-specific results are present
        $ServerIndicators = @("Server Roles", "DHCP", "DNS", "Active Directory")
        $HasServerResults = $Results | Where-Object { $_.Category -in $ServerIndicators }
        
        # Method 2: Check OS type via WMI
        try {
            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $IsWindowsServer = $OSInfo.ProductType -ne 1  # ProductType: 1=Workstation, 2=DC, 3=Server
        }
        catch {
            $IsWindowsServer = $false
        }
        
        # Determine audit type
        $IsServerAudit = ($HasServerResults.Count -gt 0) -or $IsWindowsServer
        
        # Generate appropriate header
        if ($IsServerAudit) {
            $ReportContent += "# Windows Server IT Assessment Report"
            $ReportTitle = "WindowsServerAuditor v1.3.0"
        } else {
            $ReportContent += "# Windows Workstation Security Audit Report" 
            $ReportTitle = "WindowsWorkstationAuditor v1.3.0"
        }
        
        $ReportContent += ""
        $ReportContent += "**Computer:** $env:COMPUTERNAME"
        $ReportContent += "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $ReportContent += "**Tool Version:** $ReportTitle"
        #endregion
        $ReportContent += ""
        
        # Executive Summary
        $HighRisk = $Results | Where-Object { $_.RiskLevel -eq "HIGH" }
        $MediumRisk = $Results | Where-Object { $_.RiskLevel -eq "MEDIUM" }
        $LowRisk = $Results | Where-Object { $_.RiskLevel -eq "LOW" }
        $InfoItems = $Results | Where-Object { $_.RiskLevel -eq "INFO" }
        
        $ReportContent += "## Executive Summary"
        $ReportContent += ""
        $ReportContent += "| Risk Level | Count | Priority |"
        $ReportContent += "|------------|--------|----------|"
        $ReportContent += "| HIGH | $($HighRisk.Count) | Immediate Action Required |"
        $ReportContent += "| MEDIUM | $($MediumRisk.Count) | Review and Plan Remediation |"
        $ReportContent += "| LOW | $($LowRisk.Count) | Monitor and Maintain |"
        $ReportContent += "| INFO | $($InfoItems.Count) | Informational |"
        $ReportContent += ""

        # Security Strengths Section (GREEN indicators for positive findings)
        if ($LowRisk.Count -gt 0 -or $InfoItems.Count -gt 0) {
            $ReportContent += "## Security Strengths"
            $ReportContent += ""
            $ReportContent += "> **Positive security findings and properly configured systems**"
            $ReportContent += ""

            # Group positive findings by category
            $PositiveFindings = $LowRisk + $InfoItems
            $StrengthsByCategory = $PositiveFindings | Group-Object Category | Sort-Object Name

            foreach ($CategoryGroup in $StrengthsByCategory) {
                $CategoryName = $CategoryGroup.Name
                $CategoryCount = $CategoryGroup.Count

                $ReportContent += "### $CategoryName ($CategoryCount findings)"
                $ReportContent += ""

                # Show actual system findings from audit data only
                if ($CategoryName -eq "System") {
                    $TopFindings = $CategoryGroup.Group | Select-Object -First 3
                    foreach ($Finding in $TopFindings) {
                        $ReportContent += "- **$($Finding.Item)**: $($Finding.Details)"
                    }
                }
                elseif ($CategoryName -eq "Patching") {
                    # Show actual patching findings from audit data only
                    $TopFindings = $CategoryGroup.Group | Select-Object -First 3
                    foreach ($Finding in $TopFindings) {
                        $ReportContent += "- **$($Finding.Item)**: $($Finding.Details)"
                    }
                }
                elseif ($CategoryName -eq "Dark Web Analysis") {
                    # Show actual dark web findings from audit data only
                    $TopFindings = $CategoryGroup.Group | Select-Object -First 3
                    foreach ($Finding in $TopFindings) {
                        $ReportContent += "- **$($Finding.Item)**: $($Finding.Details)"
                    }
                }
                else {
                    # Show top 3 positive findings for other categories
                    $TopFindings = $CategoryGroup.Group | Select-Object -First 3
                    foreach ($Finding in $TopFindings) {
                        $ReportContent += "- **$($Finding.Item)**: $($Finding.Details)"
                    }
                }
                $ReportContent += ""
            }

            $ReportContent += "---"
            $ReportContent += ""
        }
        
        # Critical Action Items
        if ($HighRisk.Count -gt 0 -or $MediumRisk.Count -gt 0) {
            $ReportContent += "## Critical Action Items"
            $ReportContent += ""
            
            if ($HighRisk.Count -gt 0) {
                $ReportContent += "### HIGH PRIORITY (Immediate Action Required)"
                $ReportContent += ""
                foreach ($Item in $HighRisk) {
                    $ReportContent += "- **$($Item.Category) - $($Item.Item):** $($Item.Value)"
                    $ReportContent += "  - Details: $($Item.Details)"
                    if ($Item.Recommendation) {
                        $ReportContent += "  - Recommendation: $($Item.Recommendation)"
                    }
                    $ReportContent += ""
                }
            }
            
            if ($MediumRisk.Count -gt 0) {
                $ReportContent += "### MEDIUM PRIORITY (Review and Plan)"
                $ReportContent += ""
                foreach ($Item in $MediumRisk) {
                    $ReportContent += "- **$($Item.Category) - $($Item.Item):** $($Item.Value)"
                    $ReportContent += "  - Details: $($Item.Details)"
                    if ($Item.Recommendation) {
                        $ReportContent += "  - Recommendation: $($Item.Recommendation)"
                    }
                    $ReportContent += ""
                }
            }
        }
        
        # Additional Information (LOW and INFO items only, excluding Security Events to avoid repetition)
        $AdditionalItems = $Results | Where-Object { $_.RiskLevel -in @("LOW", "INFO") -and $_.Category -ne "Security Events" }
        $AdditionalCategories = $AdditionalItems | Group-Object Category | Sort-Object Name
        
        if ($AdditionalCategories.Count -gt 0) {
            $ReportContent += "## Additional Information"
            $ReportContent += ""
            
            foreach ($Category in $AdditionalCategories) {
                $CategoryName = $Category.Name
                $CategoryItems = $Category.Group
                
                $ReportContent += "### $CategoryName"
                $ReportContent += ""
                
                foreach ($Item in $CategoryItems) {
                    $RiskIcon = switch ($Item.RiskLevel) {
                        "LOW" { "[LOW]" }
                        default { "[INFO]" }
                    }
                    
                    $ReportContent += "**$RiskIcon $($Item.Item):** $($Item.Value)"
                    $ReportContent += ""
                    $ReportContent += "- **Details:** $($Item.Details)"
                    if ($Item.Recommendation) {
                        $ReportContent += "- **Recommendation:** $($Item.Recommendation)"
                    }
                    $ReportContent += ""
                }
            }
        }
        
        # System Information Section with Enhanced Details
        $SystemInfo = $Results | Where-Object { $_.Category -eq "System" }
        if ($SystemInfo) {
            $ReportContent += "## System Configuration Details"
            $ReportContent += ""
            foreach ($Item in $SystemInfo) {
                $ReportContent += "- **$($Item.Item):** $($Item.Value) - $($Item.Details)"
            }
            $ReportContent += ""
        }
        
        # Recommendation Summary
        $RecommendationItems = $Results | Where-Object { $_.Recommendation -and $_.Recommendation.Trim() -ne "" }
        if ($RecommendationItems.Count -gt 0) {
            $ReportContent += "## Recommendations"
            $ReportContent += ""
            $RecommendationItems | Group-Object Recommendation | ForEach-Object {
                $ReportContent += "- **$($_.Name)**"
                $ReportContent += "  - Affected Items: $($_.Count)"
                $ReportContent += ""
            }
        }
        
        # Footer
        $ReportContent += "---"
        $ReportContent += ""
        $ReportContent += "*This report was generated by WindowsWorkstationAuditor v1.3.0*"
        $ReportContent += ""
        $ReportContent += "*For detailed data analysis and aggregation, refer to the corresponding JSON export.*"
        
        # Write report to file
        $ReportContent | Set-Content -Path $ReportPath -Encoding UTF8
        
        Write-LogMessage "SUCCESS" "Markdown report exported: $ReportPath" "EXPORT"
        return $ReportPath
    }
    catch {
        Write-LogMessage "ERROR" "Failed to export markdown report: $($_.Exception.Message)" "EXPORT"
        return $null
    }
}
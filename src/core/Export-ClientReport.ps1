# NetworkAuditAggregator - Client Report Export
# Version 1.0.0

function Export-ClientReport {
    <#
    .SYNOPSIS
        Exports consolidated analysis to professional HTML report
        
    .DESCRIPTION
        Generates client-ready HTML report with executive summary, scoring matrix,
        and risk analysis sections matching professional consulting format.
        
    .PARAMETER ExecutiveSummary
        Executive summary data from Generate-ExecutiveSummary
        
    .PARAMETER ScoringMatrix
        Scoring matrix data from Generate-ScoringMatrix
        
    .PARAMETER RiskAnalysis
        Risk analysis data from Generate-RiskAnalysis
        
    .PARAMETER OutputPath
        Directory for generated report
        
    .PARAMETER ClientName
        Client name for report customization
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ExecutiveSummary,
        
        [Parameter(Mandatory = $true)] 
        [PSCustomObject]$ScoringMatrix,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RiskAnalysis,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientName
    )
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Generate report filename
    $ReportDate = Get-Date -Format "yyyy-MM-dd"
    $SafeClientName = $ClientName -replace '[^\w\s-]', '' -replace '\s+', '-'
    $ReportFileName = "$SafeClientName-IT-Assessment-Report-$ReportDate.html"
    $ReportPath = Join-Path $OutputPath $ReportFileName
    
    Write-Verbose "Generating client report: $ReportFileName"
    
    # Generate HTML content
    $HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$ClientName - IT Assessment Report</title>
    <style>
        $(Get-ReportStyles)
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>$ClientName</h1>
            <h2>IT Assessment & Recommendations</h2>
            <p class="report-date">$($ExecutiveSummary.AssessmentDate)</p>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2 class="section-header">Executive Summary</h2>
            
            <div class="summary-metrics">
                <div class="metric-box">
                    <div class="metric-value">$($ExecutiveSummary.SystemsAssessed)</div>
                    <div class="metric-label">Systems Assessed</div>
                </div>
                <div class="metric-box high-risk">
                    <div class="metric-value">$($ExecutiveSummary.RiskDistribution.HighRisk)</div>
                    <div class="metric-label">High Risk</div>
                </div>
                <div class="metric-box medium-risk">
                    <div class="metric-value">$($ExecutiveSummary.RiskDistribution.MediumRisk)</div>
                    <div class="metric-label">Medium Risk</div>
                </div>
                <div class="metric-box low-risk">
                    <div class="metric-value">$($ExecutiveSummary.RiskDistribution.LowRisk)</div>
                    <div class="metric-label">Low Risk</div>
                </div>
            </div>
            
            <div class="environment-overview">
                <h3>Environment Overview</h3>
                <p><strong>Assessment Scope:</strong> $($ExecutiveSummary.EnvironmentOverview.AssessmentScope) 
                   ($($ExecutiveSummary.EnvironmentOverview.Workstations) workstations, $($ExecutiveSummary.EnvironmentOverview.Servers) servers)</p>
                <p><strong>Total Findings:</strong> $($ExecutiveSummary.TotalFindings) items identified across all systems</p>
                <p><strong>Priority Actions:</strong> $($ExecutiveSummary.PriorityRecommendations.Count) immediate recommendations</p>
            </div>
        </div>
        
        <!-- Scoring Summary -->
        <div class="section">
            <h2 class="section-header">Scoring Summary</h2>
            <div class="scoring-note">
                <p><strong>Client Adherence Rating Scale:</strong></p>
                <ul>
                    <li>5 - Adhere to the best practice</li>
                    <li>4 - Strong adherence, minimal gaps identified</li>
                    <li>3 - Adhere in some areas, but not all</li>
                    <li>2 - Limited adherence to the best practice(s), several gaps identified</li>
                    <li>1 - No adherence to the best practice(s)</li>
                </ul>
            </div>
            
            <table class="scoring-table">
                <thead>
                    <tr>
                        <th>Component</th>
                        <th>Section Criticality</th>
                        <th>Client Adherence</th>
                        <th>Overview</th>
                    </tr>
                </thead>
                <tbody>
                    $(Generate-ScoringTableRows -Components $ScoringMatrix.Components)
                </tbody>
            </table>
        </div>
        
        <!-- Risk Analysis -->
        <div class="section">
            <h2 class="section-header">Risk Analysis</h2>
            
            $(Generate-RiskSection -Title "High Risk" -Color "high-risk" -Findings $RiskAnalysis.HighRiskFindings)
            
            $(Generate-RiskSection -Title "Medium Risk" -Color "medium-risk" -Findings $RiskAnalysis.MediumRiskFindings)
            
            $(Generate-RiskSection -Title "Low Risk" -Color "low-risk" -Findings $RiskAnalysis.LowRiskFindings)
        </div>
        
        <!-- Systems Snapshot -->
        <div class="section">
            <h2 class="section-header">Systems Overview</h2>
            <table class="systems-table">
                <thead>
                    <tr>
                        <th>Computer</th>
                        <th>Overall Grade</th>
                        <th>Security</th>
                        <th>Users</th>
                        <th>Network</th>
                        <th>Patching</th>
                        <th>System</th>
                        <th>High Risk Items</th>
                    </tr>
                </thead>
                <tbody>
                    $(Generate-SystemsTableRows -Systems $RiskAnalysis.SystemsSnapshot)
                </tbody>
            </table>
        </div>
        
        <!-- Priority Recommendations -->
        <div class="section">
            <h2 class="section-header">Priority Recommendations</h2>
            <table class="recommendations-table">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Category</th>
                        <th>Recommendation</th>
                        <th>Timeframe</th>
                        <th>Impact</th>
                    </tr>
                </thead>
                <tbody>
                    $(Generate-RecommendationsTableRows -Recommendations $ExecutiveSummary.PriorityRecommendations)
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Report generated on $(Get-Date -Format 'MMMM dd, yyyy') by BusinessNetworkAggregator v1.0.0</p>
        </div>
    </div>
</body>
</html>
"@
    
    # Write HTML file
    $HtmlContent | Set-Content -Path $ReportPath -Encoding UTF8
    
    Write-Verbose "Report exported to: $ReportPath"
    return $ReportPath
}

function Get-ReportStyles {
    return @"
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; padding: 40px 20px; background: #2c3e50; color: white; }
        .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
        .header h2 { margin: 10px 0; font-size: 1.4em; font-weight: 300; opacity: 0.9; }
        .report-date { margin: 20px 0 0 0; font-size: 1.1em; opacity: 0.8; }
        
        .section { padding: 30px; border-bottom: 1px solid #eee; }
        .section-header { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        
        .summary-metrics { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .metric-box { flex: 1; text-align: center; padding: 20px; border-radius: 8px; min-width: 120px; }
        .metric-box { background: #ecf0f1; }
        .metric-box.high-risk { background: #e74c3c; color: white; }
        .metric-box.medium-risk { background: #f39c12; color: white; }
        .metric-box.low-risk { background: #f1c40f; }
        .metric-value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .metric-label { font-size: 0.9em; opacity: 0.8; }
        
        .environment-overview { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px; }
        .environment-overview h3 { margin-top: 0; color: #2c3e50; }
        
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border: 1px solid #ddd; }
        th { background: #34495e; color: white; font-weight: 600; }
        tr:nth-child(even) { background: #f8f9fa; }
        
        .risk-section { margin: 30px 0; }
        .risk-header { padding: 15px; border-radius: 8px 8px 0 0; color: white; font-weight: bold; font-size: 1.2em; }
        .risk-header.high-risk { background: #e74c3c; }
        .risk-header.medium-risk { background: #f39c12; }
        .risk-header.low-risk { background: #f1c40f; color: #2c3e50; }
        .risk-content { border: 1px solid #ddd; border-top: none; padding: 20px; background: white; }
        .risk-item { margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #eee; }
        .risk-item:last-child { border-bottom: none; }
        .risk-title { font-weight: bold; color: #2c3e50; margin-bottom: 5px; }
        .risk-description { margin-bottom: 10px; color: #666; }
        .risk-recommendation { background: #e8f4f8; padding: 10px; border-radius: 4px; font-style: italic; }
        
        .systems-table th, .systems-table td { text-align: center; padding: 8px; }
        .grade-A { background: #2ecc71; color: white; font-weight: bold; }
        .grade-B { background: #3498db; color: white; font-weight: bold; }
        .grade-C { background: #f39c12; color: white; font-weight: bold; }
        .grade-D { background: #e67e22; color: white; font-weight: bold; }
        .grade-F { background: #e74c3c; color: white; font-weight: bold; }
        
        .footer { text-align: center; padding: 20px; background: #ecf0f1; color: #7f8c8d; font-size: 0.9em; }
        
        @media print {
            .container { box-shadow: none; }
            .section { page-break-inside: avoid; }
        }
"@
}

function Generate-ScoringTableRows {
    param([array]$Components)
    
    $rows = ""
    foreach ($component in $Components) {
        $adherenceClass = "adherence-$($component.ClientAdherence)"
        $rows += @"
        <tr>
            <td><strong>$($component.Component)</strong></td>
            <td>$($component.SectionCriticality)</td>
            <td class="$adherenceClass"><strong>$($component.ClientAdherence)</strong></td>
            <td>$($component.Overview)<br><small style="color: #666;">$($component.Details)</small></td>
        </tr>
"@
    }
    return $rows
}

function Generate-RiskSection {
    param([string]$Title, [string]$Color, [array]$Findings)
    
    if ($Findings.Count -eq 0) { return "" }
    
    $content = @"
    <div class="risk-section">
        <div class="risk-header $Color">$Title</div>
        <div class="risk-content">
"@
    
    foreach ($finding in $Findings) {
        $content += @"
            <div class="risk-item">
                <div class="risk-title">$($finding.RiskFactor)</div>
                <div class="risk-description">$($finding.Description)</div>
                <div class="risk-recommendation"><strong>Recommendation:</strong> $($finding.Recommendation)</div>
                <small><strong>Affected Systems ($($finding.AffectedCount)):</strong> $($finding.AffectedSystems)</small>
            </div>
"@
    }
    
    $content += @"
        </div>
    </div>
"@
    
    return $content
}

function Generate-SystemsTableRows {
    param([array]$Systems)
    
    $rows = ""
    foreach ($system in $Systems) {
        $rows += @"
        <tr>
            <td><strong>$($system.ComputerName)</strong><br><small>$($system.OperatingSystem)</small></td>
            <td class="grade-$($system.OverallGrade)">$($system.OverallGrade)</td>
            <td class="grade-$($system.SecurityGrade)">$($system.SecurityGrade)</td>
            <td class="grade-$($system.UsersGrade)">$($system.UsersGrade)</td>
            <td class="grade-$($system.NetworkGrade)">$($system.NetworkGrade)</td>
            <td class="grade-$($system.PatchingGrade)">$($system.PatchingGrade)</td>
            <td class="grade-$($system.SystemGrade)">$($system.SystemGrade)</td>
            <td>$($system.HighRiskCount)</td>
        </tr>
"@
    }
    return $rows
}

function Generate-RecommendationsTableRows {
    param([array]$Recommendations)
    
    $rows = ""
    foreach ($rec in $Recommendations) {
        $priorityClass = if ($rec.Priority -eq 1) { "high-risk" } elseif ($rec.Priority -le 2) { "medium-risk" } else { "low-risk" }
        $rows += @"
        <tr>
            <td class="$priorityClass" style="text-align: center; font-weight: bold; color: white;">$($rec.Priority)</td>
            <td><strong>$($rec.Category)</strong></td>
            <td>$($rec.Recommendation)</td>
            <td>$($rec.Timeframe)</td>
            <td>$($rec.Impact)</td>
        </tr>
"@
    }
    return $rows
}
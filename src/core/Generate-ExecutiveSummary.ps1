# NetworkAuditAggregator - Executive Summary Generator
# Version 1.0.0

function Generate-ExecutiveSummary {
    <#
    .SYNOPSIS
        Generates executive-level summary of IT assessment findings
        
    .DESCRIPTION
        Analyzes consolidated audit data to produce high-level metrics, 
        key findings, and priority recommendations suitable for executive reporting.
        
    .PARAMETER ImportedData
        Consolidated audit data from Import-AuditData
        
    .PARAMETER ClientName
        Client name for report customization
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ImportedData,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientName
    )
    
    Write-Verbose "Generating executive summary for $($ImportedData.SystemCount) systems"
    
    # Initialize summary object
    $Summary = [PSCustomObject]@{
        ClientName = $ClientName
        AssessmentDate = (Get-Date).ToString("MMMM yyyy")
        SystemsAssessed = $ImportedData.SystemCount
        TotalFindings = $ImportedData.FindingCount
        RiskDistribution = $ImportedData.RiskSummary
        KeyFindings = @()
        PriorityRecommendations = @()
        EnvironmentOverview = @{}
        TechnicalHighlights = @{}
    }
    
    # Environment Overview Analysis
    $WorkstationCount = ($ImportedData.Systems | Where-Object { $_.SystemType -like "*Workstation*" -or $_.SystemType -eq "Unknown" }).Count
    $ServerCount = ($ImportedData.Systems | Where-Object { $_.SystemType -like "*Server*" }).Count
    $DomainControllers = ($ImportedData.AllFindings | Where-Object { $_.Category -eq "System" -and $_.Item -eq "Server Roles" -and $_.Value -like "*Domain Controller*" }).Count
    
    $Summary.EnvironmentOverview = @{
        TotalSystems = $ImportedData.SystemCount
        Workstations = $WorkstationCount
        Servers = $ServerCount
        DomainControllers = $DomainControllers
        AssessmentScope = if ($ImportedData.SystemCount -eq 1) { "Single system" } 
                          elseif ($ImportedData.SystemCount -le 5) { "Small environment" }
                          elseif ($ImportedData.SystemCount -le 20) { "Medium environment" }
                          else { "Large environment" }
    }
    
    # Key Findings Analysis (HIGH and MEDIUM risk items)
    $CriticalFindings = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") } | 
        Group-Object Category, Item | 
        ForEach-Object {
            [PSCustomObject]@{
                Category = $_.Group[0].Category
                Issue = $_.Group[0].Item
                AffectedSystems = $_.Count
                RiskLevel = $_.Group[0].RiskLevel
                Description = $_.Group[0].Details
                Recommendation = $_.Group[0].Recommendation
            }
        } | Sort-Object { if ($_.RiskLevel -eq "HIGH") { 1 } else { 2 } }, AffectedSystems -Descending
    
    $Summary.KeyFindings = $CriticalFindings | Select-Object -First 10
    
    # Technical Highlights
    $SecurityFindings = $ImportedData.AllFindings | Where-Object { $_.Category -in @("Security", "Users", "Network") }
    $PatchFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Patching" -and $_.RiskLevel -eq "HIGH" }
    $SoftwareFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Software" }
    
    $Summary.TechnicalHighlights = @{
        SecurityIssues = $SecurityFindings.Count
        CriticalPatches = $PatchFindings.Count
        SoftwareInventory = $SoftwareFindings.Count
        SystemsWithAdminIssues = ($ImportedData.AllFindings | Where-Object { 
            $_.Category -eq "Users" -and $_.Item -like "*Administrator*" -and $_.RiskLevel -in @("HIGH", "MEDIUM") 
        } | Select-Object -Unique SystemName).Count
        NetworkRisks = ($ImportedData.AllFindings | Where-Object { 
            $_.Category -eq "Network" -and $_.RiskLevel -eq "HIGH" 
        }).Count
    }
    
    # Priority Recommendations (based on risk level and system impact)
    $RecommendationPriorities = @()
    
    # High-impact recommendations based on findings
    if ($Summary.RiskDistribution.HighRisk -gt 0) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 1
            Category = "Critical Security"
            Recommendation = "Address $($Summary.RiskDistribution.HighRisk) high-risk security findings immediately"
            Timeframe = "1-2 weeks"
            Impact = "High"
            AffectedSystems = ($ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "HIGH" } | Select-Object -Unique SystemName).Count
        }
    }
    
    if ($PatchFindings.Count -gt 0) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 2  
            Category = "Patch Management"
            Recommendation = "Deploy critical security updates to $($PatchFindings.Count) systems"
            Timeframe = "2-4 weeks"
            Impact = "High"
            AffectedSystems = ($PatchFindings | Select-Object -Unique SystemName).Count
        }
    }
    
    if ($Summary.TechnicalHighlights.SystemsWithAdminIssues -gt 0) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 3
            Category = "Access Management"  
            Recommendation = "Review administrator account configurations on $($Summary.TechnicalHighlights.SystemsWithAdminIssues) systems"
            Timeframe = "1-3 weeks"
            Impact = "Medium"
            AffectedSystems = $Summary.TechnicalHighlights.SystemsWithAdminIssues
        }
    }
    
    if ($Summary.RiskDistribution.MediumRisk -gt 10) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 4
            Category = "IT Hygiene"
            Recommendation = "Address $($Summary.RiskDistribution.MediumRisk) medium-risk findings for improved security posture"
            Timeframe = "1-2 months"
            Impact = "Medium"
            AffectedSystems = ($ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" } | Select-Object -Unique SystemName).Count
        }
    }
    
    $Summary.PriorityRecommendations = $RecommendationPriorities
    
    Write-Verbose "Executive summary generated: $($Summary.KeyFindings.Count) key findings, $($Summary.PriorityRecommendations.Count) priority recommendations"
    
    return $Summary
}
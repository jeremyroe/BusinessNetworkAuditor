# NetworkAuditAggregator - Risk Analysis Generator
# Version 1.0.0

function Generate-RiskAnalysis {
    <#
    .SYNOPSIS
        Generates color-coded risk analysis matching client report format
        
    .DESCRIPTION
        Analyzes consolidated findings to create risk-based sections with
        specific recommendations, similar to the "High Risk" and "Low Risk" 
        sections in professional client reports.
        
    .PARAMETER ImportedData
        Consolidated audit data from Import-AuditData
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ImportedData
    )
    
    Write-Verbose "Generating risk analysis from $($ImportedData.FindingCount) findings"
    
    # Initialize risk analysis structure
    $RiskAnalysis = [PSCustomObject]@{
        HighRiskFindings = @()
        MediumRiskFindings = @()
        LowRiskFindings = @()
        SystemsSnapshot = @()
        RiskSummary = @{
            TotalRisks = 0
            CriticalSystems = 0
            ImmediateActions = 0
        }
    }
    
    # Process HIGH risk findings
    $HighRiskItems = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "HIGH" } |
        Group-Object Category, Item | 
        ForEach-Object {
            $Finding = $_.Group[0]
            $AffectedSystems = $_.Group | Select-Object -Unique SystemName
            
            [PSCustomObject]@{
                RiskFactor = $Finding.Item
                Category = $Finding.Category  
                Description = $Finding.Details
                Recommendation = $Finding.Recommendation
                AffectedCount = $AffectedSystems.Count
                AffectedSystems = ($AffectedSystems.SystemName -join ", ")
                Severity = "Critical"
            }
        } | Sort-Object AffectedCount -Descending
    
    $RiskAnalysis.HighRiskFindings = $HighRiskItems
    
    # Process MEDIUM risk findings  
    $MediumRiskItems = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" } |
        Group-Object Category, Item |
        ForEach-Object {
            $Finding = $_.Group[0]
            $AffectedSystems = $_.Group | Select-Object -Unique SystemName
            
            [PSCustomObject]@{
                RiskFactor = $Finding.Item
                Category = $Finding.Category
                Description = $Finding.Details  
                Recommendation = $Finding.Recommendation
                AffectedCount = $AffectedSystems.Count
                AffectedSystems = ($AffectedSystems.SystemName -join ", ")
                Severity = "Moderate"
            }
        } | Sort-Object AffectedCount -Descending | Select-Object -First 10
    
    $RiskAnalysis.MediumRiskFindings = $MediumRiskItems
    
    # Process LOW risk findings (informational)
    $LowRiskItems = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "LOW" } |
        Group-Object Category, Item |
        ForEach-Object {
            $Finding = $_.Group[0]
            $AffectedSystems = $_.Group | Select-Object -Unique SystemName
            
            [PSCustomObject]@{
                RiskFactor = $Finding.Item
                Category = $Finding.Category
                Description = $Finding.Details
                Recommendation = $Finding.Recommendation  
                AffectedCount = $AffectedSystems.Count
                AffectedSystems = ($AffectedSystems.SystemName -join ", ")
                Severity = "Low"
            }
        } | Sort-Object AffectedCount -Descending | Select-Object -First 5
    
    $RiskAnalysis.LowRiskFindings = $LowRiskItems
    
    # Generate Systems Snapshot (similar to Computer Snapshot table)
    foreach ($System in $ImportedData.Systems) {
        $SystemFindings = $ImportedData.AllFindings | Where-Object { $_.SystemName -eq $System.ComputerName }
        
        # Calculate grades for each category
        $Grades = @{
            Security = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Security" })
            Users = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Users" })
            Network = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Network" })
            Patching = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Patching" })
            System = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "System" })
        }
        
        # Calculate overall grade
        $OverallGrade = Get-OverallGrade -Grades $Grades
        
        $SystemSnapshot = [PSCustomObject]@{
            ComputerName = $System.ComputerName
            OverallGrade = $OverallGrade
            SecurityGrade = $Grades.Security
            UsersGrade = $Grades.Users  
            NetworkGrade = $Grades.Network
            PatchingGrade = $Grades.Patching
            SystemGrade = $Grades.System
            OperatingSystem = $System.OperatingSystem
            SystemType = $System.SystemType
            HighRiskCount = ($SystemFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
            MediumRiskCount = ($SystemFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
            FindingsCount = $SystemFindings.Count
        }
        
        $RiskAnalysis.SystemsSnapshot += $SystemSnapshot
    }
    
    # Calculate risk summary
    $RiskAnalysis.RiskSummary = @{
        TotalRisks = $RiskAnalysis.HighRiskFindings.Count + $RiskAnalysis.MediumRiskFindings.Count
        CriticalSystems = ($RiskAnalysis.SystemsSnapshot | Where-Object { $_.OverallGrade -in @("C", "D", "F") }).Count
        ImmediateActions = $RiskAnalysis.HighRiskFindings.Count
        SystemsNeedingAttention = ($RiskAnalysis.SystemsSnapshot | Where-Object { $_.HighRiskCount -gt 0 }).Count
    }
    
    Write-Verbose "Risk analysis completed: $($RiskAnalysis.HighRiskFindings.Count) high-risk, $($RiskAnalysis.MediumRiskFindings.Count) medium-risk findings"
    
    return $RiskAnalysis
}

function Get-SystemGrade {
    <#
    .SYNOPSIS
        Calculates letter grade (A-F) for a system category based on risk findings
    #>
    param([array]$Findings)
    
    if (-not $Findings -or $Findings.Count -eq 0) { return "A" }
    
    $HighRisk = ($Findings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $MediumRisk = ($Findings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $TotalFindings = $Findings.Count
    
    # Grading based on risk distribution
    if ($HighRisk -gt 0) {
        if ($HighRisk -ge 3) { return "F" }
        elseif ($HighRisk -eq 2) { return "D" } 
        else { return "C" }
    }
    elseif ($MediumRisk -gt 0) {
        if ($MediumRisk -ge 3) { return "C" }
        elseif ($MediumRisk -eq 2) { return "B" }
        else { return "B" }
    }
    else {
        return "A"
    }
}

function Get-OverallGrade {
    <#
    .SYNOPSIS  
        Calculates overall system grade from category grades
    #>
    param([hashtable]$Grades)
    
    $GradeValues = @{ "A" = 4; "B" = 3; "C" = 2; "D" = 1; "F" = 0 }
    $GradeLetters = @{ 4 = "A"; 3 = "B"; 2 = "C"; 1 = "D"; 0 = "F" }
    
    $TotalValue = 0
    $GradeCount = 0
    
    foreach ($Grade in $Grades.Values) {
        $TotalValue += $GradeValues[$Grade]
        $GradeCount++
    }
    
    if ($GradeCount -eq 0) { return "A" }
    
    $Average = [math]::Round($TotalValue / $GradeCount)
    return $GradeLetters[$Average]
}
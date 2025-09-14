# NetworkAuditAggregator - Scoring Matrix Generator  
# Version 1.0.0

function Generate-ScoringMatrix {
    <#
    .SYNOPSIS
        Generates component-based scoring matrix similar to client report format
        
    .DESCRIPTION
        Analyzes audit findings to create scoring matrix with criticality levels
        and adherence ratings (1-5 scale) matching professional report format.
        
    .PARAMETER ImportedData
        Consolidated audit data from Import-AuditData
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ImportedData
    )
    
    Write-Verbose "Generating scoring matrix for $($ImportedData.SystemCount) systems"
    
    # Initialize scoring components
    $ScoringComponents = @()
    
    # Network Infrastructure Component
    $NetworkFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Network" }
    $NetworkRisks = $NetworkFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $NetworkAdherence = Get-AdherenceScore -TotalFindings $NetworkFindings.Count -RiskFindings $NetworkRisks.Count
    
    $ScoringComponents += [PSCustomObject]@{
        Component = "Network Infrastructure"
        SectionCriticality = "High"
        ClientAdherence = $NetworkAdherence
        Overview = "Network security, firewall configuration, and infrastructure hardening"
        Details = if ($NetworkRisks.Count -gt 0) { "Issues found: $($NetworkRisks.Count) network risks identified" } else { "Network infrastructure appears well-configured" }
    }
    
    # Desktop/User Infrastructure Component  
    $UserFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Users" }
    $UserRisks = $UserFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $UserAdherence = Get-AdherenceScore -TotalFindings $UserFindings.Count -RiskFindings $UserRisks.Count
    
    $AdminIssues = $UserFindings | Where-Object { $_.Item -like "*Administrator*" -and $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $ScoringComponents += [PSCustomObject]@{
        Component = "Desktop/User Infrastructure" 
        SectionCriticality = "High"
        ClientAdherence = $UserAdherence
        Overview = "User account management, administrative privileges, and access control"
        Details = if ($AdminIssues.Count -gt 0) { "Administrator account issues on $($AdminIssues.Count) systems" } 
                  else { "User account configurations meet security standards" }
    }
    
    # Security Component
    $SecurityFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Security" }  
    $SecurityRisks = $SecurityFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $SecurityAdherence = Get-AdherenceScore -TotalFindings $SecurityFindings.Count -RiskFindings $SecurityRisks.Count
    
    $AntivirusIssues = $SecurityFindings | Where-Object { $_.Item -like "*Antivirus*" -or $_.Item -like "*Anti-virus*" }
    $ScoringComponents += [PSCustomObject]@{
        Component = "Security Controls"
        SectionCriticality = "High"  
        ClientAdherence = $SecurityAdherence
        Overview = "Antivirus protection, security software, and threat detection capabilities"
        Details = if ($AntivirusIssues.Count -gt 0) { "Antivirus configuration requires attention" }
                  else { "Security controls properly implemented" }
    }
    
    # Patch Management Component
    $PatchFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Patching" }
    $PatchRisks = $PatchFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $PatchAdherence = Get-AdherenceScore -TotalFindings $PatchFindings.Count -RiskFindings $PatchRisks.Count
    
    $ScoringComponents += [PSCustomObject]@{
        Component = "Patch Management"
        SectionCriticality = "High"
        ClientAdherence = $PatchAdherence  
        Overview = "Operating system updates, security patches, and software currency"
        Details = if ($PatchRisks.Count -gt 0) { "$($PatchRisks.Count) systems need critical updates" }
                  else { "Systems are current with security updates" }
    }
    
    # Management Infrastructure Component
    $SystemFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "System" }
    $SystemRisks = $SystemFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $ManagementAdherence = Get-AdherenceScore -TotalFindings $SystemFindings.Count -RiskFindings $SystemRisks.Count
    
    $ScoringComponents += [PSCustomObject]@{
        Component = "Management Infrastructure"
        SectionCriticality = "High"
        ClientAdherence = $ManagementAdherence
        Overview = "System monitoring, centralized management, and operational oversight"  
        Details = "Centralized management capabilities assessed across $($ImportedData.SystemCount) systems"
    }
    
    # Applications Component
    $SoftwareFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Software" }
    $SoftwareRisks = $SoftwareFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $ApplicationAdherence = Get-AdherenceScore -TotalFindings $SoftwareFindings.Count -RiskFindings $SoftwareRisks.Count
    
    $RemoteAccessTools = $SoftwareFindings | Where-Object { $_.Details -like "*remote access*" -or $_.Item -like "*TeamViewer*" -or $_.Item -like "*AnyDesk*" }
    $ScoringComponents += [PSCustomObject]@{
        Component = "Applications"
        SectionCriticality = "Medium"
        ClientAdherence = $ApplicationAdherence
        Overview = "Software inventory, remote access tools, and application management"
        Details = if ($RemoteAccessTools.Count -gt 0) { "Remote access software detected on $($RemoteAccessTools.Count) systems" }
                  else { "Application inventory completed" }
    }
    
    # Calculate overall score
    $OverallScore = [math]::Round(($ScoringComponents | Measure-Object ClientAdherence -Average).Average, 1)
    
    $ScoringMatrix = [PSCustomObject]@{
        OverallScore = $OverallScore
        Components = $ScoringComponents
        ScoreDistribution = @{
            Excellent = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 5 }).Count
            Good = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 4 }).Count  
            Fair = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 3 }).Count
            Poor = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 2 }).Count
            Critical = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 1 }).Count
        }
    }
    
    Write-Verbose "Scoring matrix completed: Overall score $OverallScore/5.0"
    
    return $ScoringMatrix
}

function Get-AdherenceScore {
    <#
    .SYNOPSIS
        Calculates adherence score (1-5) based on risk findings ratio
    #>
    param(
        [int]$TotalFindings,
        [int]$RiskFindings
    )
    
    if ($TotalFindings -eq 0) { return 5 }
    
    $RiskRatio = $RiskFindings / $TotalFindings
    
    switch ($true) {
        ($RiskRatio -eq 0) { return 5 }      # No risks - Excellent
        ($RiskRatio -le 0.1) { return 4 }    # ≤10% risks - Good  
        ($RiskRatio -le 0.3) { return 3 }    # ≤30% risks - Fair
        ($RiskRatio -le 0.6) { return 2 }    # ≤60% risks - Poor
        default { return 1 }                  # >60% risks - Critical
    }
}
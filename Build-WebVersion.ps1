# Build Self-Contained Web Version of WindowsWorkstationAuditor
# This script combines all modules into a single file for web execution

param(
    [string]$OutputFile = "WindowsWorkstationAuditor-Complete.ps1"
)

Write-Host "Building self-contained web version..." -ForegroundColor Green

$WebScript = @"
# WindowsWorkstationAuditor - Self-Contained Web Version
# Version 1.3.0 - Complete Standalone Script
# Platform: Windows 10/11, Windows Server 2016+
# Requires: PowerShell 5.0+
# Usage: iex (irm https://your-url/WindowsWorkstationAuditor-Complete.ps1)

param(
    [string]`$OutputPath = "`$env:USERPROFILE\WindowsAudit",
    [switch]`$Verbose
)

# Global variables
`$Script:LogFile = ""
`$Script:StartTime = Get-Date
`$Script:ComputerName = `$env:COMPUTERNAME
`$Script:BaseFileName = "`${ComputerName}_`$(`$StartTime.ToString('yyyyMMdd_HHmmss'))"

# Ensure output directory exists
if (-not (Test-Path `$OutputPath)) {
    New-Item -ItemType Directory -Path `$OutputPath -Force | Out-Null
}

`$LogDirectory = Join-Path `$OutputPath "logs"
if (-not (Test-Path `$LogDirectory)) {
    New-Item -ItemType Directory -Path `$LogDirectory -Force | Out-Null
}
`$Script:LogFile = Join-Path `$LogDirectory "`${Script:BaseFileName}_audit.log"

"@

# Add core functions
Write-Host "Adding core functions..." -ForegroundColor Yellow

$CoreFiles = @(
    "src\core\Write-LogMessage.ps1",
    "src\core\Initialize-Logging.ps1",
    "src\core\Export-MarkdownReport.ps1",
    "src\core\Export-RawDataJSON.ps1"
)

foreach ($File in $CoreFiles) {
    if (Test-Path $File) {
        Write-Host "  Adding $File" -ForegroundColor Gray
        $Content = Get-Content $File -Raw
        # Remove the function wrapper to just get the content
        $Content = $Content -replace '^[#\s]*.*?(?=function)', '' -replace '^function\s+[\w-]+\s*{', '' 
        $Content = $Content.TrimEnd().TrimEnd('}')
        $WebScript += "`n`n# === $File ===`n$Content"
    }
}

# Add all audit modules
Write-Host "Adding audit modules..." -ForegroundColor Yellow

$ModuleFiles = @(
    "src\modules\Get-SystemInformation.ps1",
    "src\modules\Get-UserAccountAnalysis.ps1", 
    "src\modules\Get-SoftwareInventory.ps1",
    "src\modules\Get-SecuritySettings.ps1",
    "src\modules\Get-PatchStatus.ps1",
    "src\modules\Get-PolicyAnalysis.ps1",
    "src\modules\Get-DiskSpaceAnalysis.ps1",
    "src\modules\Get-MemoryAnalysis.ps1",
    "src\modules\Get-PrinterAnalysis.ps1",
    "src\modules\Get-NetworkAnalysis.ps1",
    "src\modules\Get-ProcessAnalysis.ps1",
    "src\modules\Get-EventLogAnalysis.ps1"
)

foreach ($File in $ModuleFiles) {
    if (Test-Path $File) {
        Write-Host "  Adding $File" -ForegroundColor Gray
        $Content = Get-Content $File -Raw
        $WebScript += "`n`n# === $File ===`n$Content"
    }
}

# Add main execution logic with embedded config
$MainLogic = @"

# Default configuration for web execution
`$Config = @{
    version = "1.3.0"
    output = @{
        formats = @("markdown", "rawjson")
        path = `$OutputPath
        timestamp = `$true
    }
}

# Main execution
try {
    Write-LogMessage "INFO" "WindowsWorkstationAuditor Web v1.3.0 starting..." "MAIN"
    Write-LogMessage "INFO" "Output directory: `$OutputPath" "MAIN"
    
    `$AllResults = @()
    `$AuditModuleNames = @(
        "Get-SystemInformation", "Get-UserAccountAnalysis", "Get-SoftwareInventory",
        "Get-SecuritySettings", "Get-PatchStatus", "Get-PolicyAnalysis",
        "Get-DiskSpaceAnalysis", "Get-MemoryAnalysis", "Get-PrinterAnalysis", 
        "Get-NetworkAnalysis", "Get-ProcessAnalysis", "Get-EventLogAnalysis"
    )
    
    foreach (`$ModuleName in `$AuditModuleNames) {
        try {
            Write-LogMessage "INFO" "Executing: `$ModuleName" "AUDIT"
            `$StartTime = Get-Date
            `$Results = & `$ModuleName
            `$Duration = ((Get-Date) - `$StartTime).TotalSeconds
            
            if (`$Results -and `$Results.Count -gt 0) {
                `$AllResults += `$Results
                Write-LogMessage "SUCCESS" "`$ModuleName completed in `$([math]::Round(`$Duration, 2))s - `$(`$Results.Count) results" "AUDIT"
            } else {
                Write-LogMessage "WARN" "`$ModuleName returned no results" "AUDIT"
            }
        }
        catch {
            Write-LogMessage "ERROR" "`$ModuleName failed: `$(`$_.Exception.Message)" "AUDIT"
        }
    }
    
    if (`$AllResults.Count -gt 0) {
        Write-LogMessage "SUCCESS" "Collected `$(`$AllResults.Count) audit results" "MAIN"
        
        # Export results
        Export-AuditResults -Results `$AllResults -Config `$Config
        
        Write-LogMessage "SUCCESS" "Audit completed - check `$OutputPath for results" "MAIN"
    } else {
        Write-LogMessage "ERROR" "No audit results collected" "MAIN"
    }
}
catch {
    Write-LogMessage "ERROR" "Audit failed: `$(`$_.Exception.Message)" "MAIN"
}
"@

$WebScript += $MainLogic

# Write the complete file
$WebScript | Set-Content -Path $OutputFile -Encoding UTF8

Write-Host "Web version created: $OutputFile" -ForegroundColor Green
Write-Host "File size: $([math]::Round((Get-Item $OutputFile).Length / 1KB, 1)) KB" -ForegroundColor Yellow
Write-Host ""
Write-Host "Usage: iex (irm https://your-url/$OutputFile)" -ForegroundColor Cyan
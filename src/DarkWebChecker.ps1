# Dark Web Checker - Domain Breach Analysis Tool
# Version 1.0.0
# Standalone tool for checking email domains against known data breaches

param(
    [Parameter(Mandatory=$false)]
    [string]$Domains,


    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\output",

    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = ".\config\hibp-api-config.json",

    [Parameter(Mandatory=$false)]
    [switch]$DetailedLogging,


    [Parameter(Mandatory=$false)]
    [switch]$Help,

    [Parameter(Mandatory=$false)]
    [switch]$DemoMode
)

# Display help information
if ($Help) {
    Write-Host @"

Dark Web Checker - Domain Breach Analysis Tool
===============================================

DESCRIPTION:
    Checks email domains for compromised accounts and data breaches.
    Identifies breached accounts, sources, and provides risk assessment.

USAGE:
    .\DarkWebChecker.ps1 -Domains "company.com,subsidiary.org"
    .\DarkWebChecker.ps1                                     (prompts for domains)
    .\DarkWebChecker.ps1 -Domains "company.com" -ExportJson

PARAMETERS:
    -Domains        Comma-separated list of email domains to check (optional - will prompt if not provided)
    -OutputPath     Directory for output files (default: .\output)
    -ConfigPath     Path to breach database API configuration file
    -DetailedLogging Enable detailed logging
    -DemoMode       Run in demo mode with simulated results (no API key required)
    -Help           Show this help message

SETUP OPTIONS:
    Option A - Full API Access (Recommended):
    1. Copy config\hibp-api-config.example.json to config\hibp-api-config.json
    2. Add your paid API key to the configuration file
    3. Ensure internet connectivity for API calls

    Option B - Basic Access (Free):
    1. No configuration required
    2. Uses subscription-free breach data only (limited results)
    3. Ensure internet connectivity for API calls

EXAMPLES:
    .\DarkWebChecker.ps1 -Domains "acme.com"                 (basic free mode)
    .\DarkWebChecker.ps1 -DetailedLogging                    (will prompt for domains)
    .\DarkWebChecker.ps1 -Domains "test.com" -DemoMode       (offline test mode)

"@ -ForegroundColor Cyan
    exit 0
}

# Global variables
$Script:StartTime = Get-Date
$Script:OutputDirectory = $OutputPath

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

# Simple logging function for standalone script
function Write-LogMessage {
    param(
        [string]$Level,
        [string]$Message,
        [string]$Category = "DARKWEB"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] [$Category] $Message"

    switch ($Level) {
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        default   { Write-Host $LogEntry }
    }

    if ($DetailedLogging) {
        # Also log to file if detailed logging enabled
        $LogFile = Join-Path $OutputDirectory "darkweb-check-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        $LogEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }
}

# Load required modules
$ModulePath = Join-Path $PSScriptRoot "modules\Get-DarkWebAnalysis.ps1"
if (Test-Path $ModulePath) {
    . $ModulePath
    Write-LogMessage "SUCCESS" "Loaded Dark Web Analysis module" "INIT"
} else {
    Write-LogMessage "ERROR" "Dark Web Analysis module not found at: $ModulePath" "INIT"
    Write-Host "Please ensure you're running this script from the src directory or that the modules directory exists." -ForegroundColor Red
    exit 1
}

# Load markdown export module
$MarkdownModulePath = Join-Path $PSScriptRoot "core\Export-MarkdownReport.ps1"
if (Test-Path $MarkdownModulePath) {
    . $MarkdownModulePath
    Write-LogMessage "SUCCESS" "Loaded Markdown Export module" "INIT"
} else {
    Write-LogMessage "WARN" "Markdown Export module not found - JSON export only" "INIT"
}

# Main execution
Write-Host @"

========================================
Dark Web Checker - Domain Analysis
========================================
Start Time: $($Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))

"@ -ForegroundColor Green

try {
    # Get domains from parameter or prompt user
    if (-not $Domains) {
        Write-Host "No domains specified. Please enter the email domains to check for breaches." -ForegroundColor Yellow
        Write-Host "Enter domains separated by commas (e.g., company.com, subsidiary.org):" -ForegroundColor Cyan
        $Domains = Read-Host "Domains"

        if (-not $Domains) {
            Write-Host "No domains provided. Exiting." -ForegroundColor Red
            exit 1
        }
    }

    Write-Host "Checking domains: $Domains" -ForegroundColor Green

    # Execute the dark web analysis
    if ($DemoMode) {
        Write-Host "`n[DEMO MODE] Running with simulated data - no API calls will be made" -ForegroundColor Magenta
        $Results = Get-DarkWebAnalysis -Domains $Domains -ConfigPath $ConfigPath -DemoMode
    } else {
        $Results = Get-DarkWebAnalysis -Domains $Domains -ConfigPath $ConfigPath
    }

    if ($Results.Count -eq 0) {
        Write-LogMessage "WARN" "No results returned from analysis" "SCAN"
        exit 1
    }

    # Display results in console
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $BreachCount = 0
    $CleanDomains = 0
    $ErrorCount = 0

    foreach ($Result in $Results) {
        $Color = switch ($Result.RiskLevel) {
            "HIGH"   { "Red" }
            "MEDIUM" { "Yellow" }
            "LOW"    { "DarkYellow" }
            "INFO"   { "Cyan" }
            default  { "White" }
        }

        Write-Host "`n[$($Result.RiskLevel)] $($Result.Item)" -ForegroundColor $Color
        Write-Host "  Value: $($Result.Value)" -ForegroundColor White
        Write-Host "  Details: $($Result.Details)" -ForegroundColor Gray
        Write-Host "  Recommendation: $($Result.Recommendation)" -ForegroundColor Gray

        # Count result types
        if ($Result.Item -like "*Domain Breach*") {
            $BreachCount++
        } elseif ($Result.Value -like "*Clean*") {
            $CleanDomains++
        } elseif ($Result.Value -like "*Error*" -or $Result.Value -like "*Exception*") {
            $ErrorCount++
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Breaches Found: $BreachCount" -ForegroundColor $(if ($BreachCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Clean Domains: $CleanDomains" -ForegroundColor Green
    Write-Host "Errors: $ErrorCount" -ForegroundColor $(if ($ErrorCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Total Results: $($Results.Count)" -ForegroundColor Cyan

    # Automatic export to JSON and Markdown (like other audit modules)
    $BaseFileName = "darkweb-check-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    # Export JSON
    $JsonFile = Join-Path $OutputDirectory "$BaseFileName.json"
    $ExportData = @{
        CheckDate = $Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
        Summary = @{
            BreachesFound = $BreachCount
            CleanDomains = $CleanDomains
            Errors = $ErrorCount
            TotalResults = $Results.Count
        }
        Results = $Results
    }
    $ExportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonFile -Encoding UTF8
    Write-LogMessage "SUCCESS" "JSON results exported to: $JsonFile" "EXPORT"

    # Export Markdown if module is available
    if (Get-Command Export-MarkdownReport -ErrorAction SilentlyContinue) {
        Export-MarkdownReport -Results $Results -OutputPath $OutputDirectory -BaseFileName $BaseFileName
        Write-LogMessage "SUCCESS" "Markdown report exported to: $OutputDirectory" "EXPORT"
    } else {
        Write-LogMessage "WARN" "Markdown export not available - JSON export completed" "EXPORT"
    }

    $EndTime = Get-Date
    $Duration = $EndTime - $Script:StartTime
    Write-Host "`nCheck completed in $($Duration.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Green

    # Exit with appropriate code
    if ($BreachCount -gt 0) {
        Write-Host "WARNING: Breaches detected! Review results and take appropriate action." -ForegroundColor Red
        exit 2  # Exit code 2 indicates breaches found
    } elseif ($ErrorCount -gt 0) {
        Write-Host "WARNING: Some errors occurred during check." -ForegroundColor Yellow
        exit 3  # Exit code 3 indicates errors occurred
    } else {
        Write-Host "All domains clean - no breaches detected." -ForegroundColor Green
        exit 0  # Success
    }
}
catch {
    Write-LogMessage "ERROR" "Check failed: $($_.Exception.Message)" "DARKWEB"
    Write-Host "`nFATAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
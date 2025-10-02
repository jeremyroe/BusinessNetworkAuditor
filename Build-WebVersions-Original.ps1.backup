# Build Self-Contained Web Versions for All Platforms
# This script builds web deployment versions for Windows and macOS audit tools

param(
    [ValidateSet("Windows", "macOS", "All")]
    [string]$Platform = "All",
    [ValidateSet("Workstation", "Server", "All")]
    [string]$Type = "All",
    [string]$OutputDir = "."
)

function Build-WindowsWebVersion {
    param(
        [string]$Type,
        [string]$OutputDir
    )
    
    Write-Host "Building Windows $Type web version..." -ForegroundColor Green
    
    $SourceScript = "src\Windows${Type}Auditor.ps1"
    $OutputFile = "$OutputDir\Windows${Type}Auditor-Web.ps1"
    
    if (-not (Test-Path $SourceScript)) {
        Write-Warning "Source script not found: $SourceScript"
        return
    }
    
    # Read the main script
    $MainScript = Get-Content $SourceScript -Raw
    
    # Get all module files
    $ModuleFiles = Get-ChildItem "src\modules\*.ps1" | Sort-Object Name
    $CoreFiles = Get-ChildItem "src\core\*.ps1" | Sort-Object Name
    
    # Read configuration
    $ConfigFile = "config\$($Type.ToLower())-audit-config.json"
    $ConfigContent = ""
    if (Test-Path $ConfigFile) {
        $ConfigContent = Get-Content $ConfigFile -Raw
    }
    
    # Build the web version
    $WebScript = @"
# Windows${Type}Auditor - Self-Contained Web Version
# Version 1.3.0 - $Type Audit Script
# Platform: Windows 10/11$(if ($Type -eq "Server") { ", Windows Server 2016+" })
# Requires: PowerShell 5.0+
# Usage: iex (irm https://your-url/Windows${Type}Auditor-Web.ps1)

param(
    [string]`$OutputPath = "`$env:USERPROFILE\WindowsAudit",
    [switch]`$Verbose
)

# Embedded Configuration
`$Script:EmbeddedConfig = @'
$ConfigContent
'@

# Global variables
`$Script:LogFile = ""
`$Script:StartTime = Get-Date
`$Script:ComputerName = `$env:COMPUTERNAME
`$Script:BaseFileName = "`${ComputerName}_`$(`$StartTime.ToString('yyyyMMdd_HHmmss'))"

# Ensure output directory exists
if (-not (Test-Path `$OutputPath)) {
    New-Item -ItemType Directory -Path `$OutputPath -Force | Out-Null
}

"@

    # Add core functions
    foreach ($CoreFile in $CoreFiles) {
        $Content = Get-Content $CoreFile.FullName -Raw
        $WebScript += "`n# Embedded Core: $($CoreFile.Name)`n"
        $WebScript += $Content + "`n"
    }
    
    # Add modules
    foreach ($ModuleFile in $ModuleFiles) {
        $Content = Get-Content $ModuleFile.FullName -Raw
        $WebScript += "`n# Embedded Module: $($ModuleFile.Name)`n"
        $WebScript += $Content + "`n"
    }
    
    # Add main script logic (excluding param block and module imports)
    $MainScriptLines = $MainScript -split "`n"
    $InParamBlock = $false
    $SkipLine = $false
    
    $WebScript += "`n# Main Script Logic`n"
    
    foreach ($Line in $MainScriptLines) {
        if ($Line -match "^param\(") {
            $InParamBlock = $true
            continue
        }
        if ($InParamBlock -and $Line -match "^\)") {
            $InParamBlock = $false
            continue
        }
        if ($InParamBlock) {
            continue
        }
        if ($Line -match "^\s*\.\s+.*\.ps1") {
            continue
        }
        
        $WebScript += $Line + "`n"
    }
    
    # Write the web version
    $WebScript | Set-Content -Path $OutputFile -Encoding UTF8
    
    Write-Host "✓ Created: $OutputFile ($([math]::Round((Get-Item $OutputFile).Length / 1KB))KB)" -ForegroundColor Green
}

function Build-macOSWebVersion {
    param(
        [string]$OutputDir
    )
    
    Write-Host "Building macOS Workstation web version..." -ForegroundColor Green
    
    $SourceScript = "src/macOSWorkstationAuditor.sh"
    $OutputFile = "$OutputDir/macOSWorkstationAuditor-Web.sh"
    
    if (-not (Test-Path $SourceScript)) {
        Write-Warning "Source script not found: $SourceScript"
        return
    }
    
    # Read the main script
    $MainScript = Get-Content $SourceScript -Raw
    
    # Get all module files
    $ModuleFiles = Get-ChildItem "src/modules/*.sh" | Sort-Object Name
    
    # Read configuration
    $ConfigFile = "config/macos-audit-config.json"
    $ConfigContent = ""
    if (Test-Path $ConfigFile) {
        $ConfigContent = Get-Content $ConfigFile -Raw
    }
    
    # Build the web version
    $WebScript = @"
#!/bin/bash

# macOSWorkstationAuditor - Self-Contained Web Version
# Version 1.0.0 - macOS Workstation Audit Script
# Platform: macOS 12+ (Monterey and later)
# Requires: bash 3.2+, standard macOS utilities
# Usage: curl -s https://your-url/macOSWorkstationAuditor-Web.sh | bash

# Parameters can be set via environment variables:
# OUTPUT_PATH - Custom output directory (default: ~/macOSAudit)
# VERBOSE - Set to "true" for verbose output

# Set default output path
OUTPUT_PATH_DEFAULT="`$HOME/macOSAudit"
OUTPUT_PATH="`${OUTPUT_PATH:-`$OUTPUT_PATH_DEFAULT}"

# Embedded Configuration
read -r -d '' EMBEDDED_CONFIG << 'EOF'
$ConfigContent
EOF

# Global variables
START_TIME=`$(date +%s)
COMPUTER_NAME=`$(hostname | cut -d. -f1)
BASE_FILENAME="`${COMPUTER_NAME}_`$(date '+%Y%m%d_%H%M%S')"
CONFIG_VERSION="1.0.0"

# Ensure output directory exists
mkdir -p "`$OUTPUT_PATH" 2>/dev/null
mkdir -p "`$OUTPUT_PATH/logs" 2>/dev/null

"@

    # Add modules (embed them)
    foreach ($ModuleFile in $ModuleFiles) {
        $Content = Get-Content $ModuleFile.FullName -Raw
        $WebScript += "`n# Embedded Module: $($ModuleFile.Name)`n"
        $WebScript += $Content + "`n"
    }
    
    # Add main script logic with modifications for web deployment
    $MainScriptLines = $MainScript -split "`n"
    
    $WebScript += "`n# Main Script Logic (Modified for Web Deployment)`n"
    $WebScript += "`n# Override load_module function for web version (modules already embedded)`n"
    $WebScript += "load_module() {`n"
    $WebScript += "    local module_name=`"`$1`"`n"
    $WebScript += "    log_message `"SUCCESS`" `"Module available: `$module_name`" `"MODULE`"`n"
    $WebScript += "    return 0`n"
    $WebScript += "}`n`n"
    
    $SkippingFunction = $false
    
    foreach ($Line in $MainScriptLines) {
        if ($Line -match "^\s*source\s+" -or $Line -match "^\s*\.\s+") {
            continue
        }
        if ($Line -match "^#!/bin/bash") {
            continue
        }
        
        # Skip the original load_module function definition
        if ($Line -match "^load_module\(\)") {
            $SkippingFunction = $true
            continue
        }
        
        if ($SkippingFunction) {
            if ($Line -match "^}") {
                $SkippingFunction = $false
            }
            continue
        }
        
        $WebScript += $Line + "`n"
    }
    
    # Write the web version
    $WebScript | Set-Content -Path $OutputFile -Encoding UTF8 -NoNewline
    
    # Make the script executable on Unix-like systems
    if ($IsLinux -or $IsMacOS -or (Get-Command "chmod" -ErrorAction SilentlyContinue)) {
        & chmod +x $OutputFile 2>$null
    }
    
    Write-Host "✓ Created: $OutputFile ($([math]::Round((Get-Item $OutputFile).Length / 1KB))KB)" -ForegroundColor Green
}

# Main execution
Write-Host "Building Web Deployment Versions" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

if ($Platform -eq "All" -or $Platform -eq "Windows") {
    if ($Type -eq "All" -or $Type -eq "Workstation") {
        Build-WindowsWebVersion -Type "Workstation" -OutputDir $OutputDir
    }
    if ($Type -eq "All" -or $Type -eq "Server") {
        Build-WindowsWebVersion -Type "Server" -OutputDir $OutputDir
    }
}

if ($Platform -eq "All" -or $Platform -eq "macOS") {
    Build-macOSWebVersion -OutputDir $OutputDir
}

Write-Host "`nWeb versions built successfully!" -ForegroundColor Green
Write-Host "Upload the generated files to your web server for remote deployment." -ForegroundColor Yellow
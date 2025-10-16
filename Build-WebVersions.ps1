# Build Self-Contained Web Versions for All Platforms - Manifest-Based
# Version 2.0.0 - Uses build-manifest.json for intelligent module discovery
# This script builds web deployment versions for Windows and macOS audit tools

param(
    [ValidateSet("Windows", "macOS", "All")]
    [string]$Platform = "All",
    [ValidateSet("Workstation", "Server", "All")]
    [string]$Type = "All",
    [string]$OutputDir = ".",
    [string]$ManifestPath = "config/build-manifest.json"
)

function Get-BuildManifest {
    param([string]$ManifestPath)

    if (-not (Test-Path $ManifestPath)) {
        throw "Build manifest not found: $ManifestPath"
    }

    try {
        $ManifestContent = Get-Content $ManifestPath -Raw -Encoding UTF8
        return $ManifestContent | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse build manifest: $($_.Exception.Message)"
    }
}

function Get-OrderedModules {
    param(
        [object]$Manifest,
        [string]$Platform,
        [string]$ModuleType
    )

    $AllModules = @()

    if ($Platform -eq "Windows") {
        # Add core modules first (foundation -> data -> analysis -> reporting -> export)
        $AllModules += $Manifest.platforms.windows.core_modules | Sort-Object order

        # Add analysis modules (by category and order)
        $AllModules += $Manifest.platforms.windows.analysis_modules | Sort-Object order
    }
    elseif ($Platform -eq "macOS") {
        # Add shell modules for macOS
        $AllModules += $Manifest.platforms.macos.shell_modules | Sort-Object order
    }

    return $AllModules
}

function Test-ModuleExists {
    param(
        [string]$FilePath,
        [string]$ModuleName
    )

    if (-not (Test-Path $FilePath)) {
        Write-Warning "Module file not found: $FilePath (Module: $ModuleName)"
        return $false
    }
    return $true
}

function Build-WindowsWebVersion {
    param(
        [string]$Type,
        [string]$OutputDir,
        [object]$Manifest
    )

    Write-Host "Building Windows $Type web version using manifest..." -ForegroundColor Green

    # Get source script and output paths from manifest
    $SourceScript = $Manifest.build_settings.windows.main_scripts.$($Type.ToLower())
    $OutputFile = "$OutputDir\Windows${Type}Auditor-Web.ps1"

    if (-not (Test-Path $SourceScript)) {
        Write-Warning "Source script not found: $SourceScript"
        return
    }

    # Read the main script
    $MainScript = Get-Content $SourceScript -Raw

    # Get ordered modules from manifest
    $OrderedModules = Get-OrderedModules -Manifest $Manifest -Platform "Windows"

    Write-Host "  → Loading $($OrderedModules.Count) modules in dependency order" -ForegroundColor Cyan

    # Read configuration from manifest
    $ConfigFile = $Manifest.build_settings.windows.config_files.$($Type.ToLower())
    $ConfigContent = ""
    if (Test-Path $ConfigFile) {
        $ConfigContent = Get-Content $ConfigFile -Raw
        Write-Host "  → Embedded configuration from $ConfigFile" -ForegroundColor Cyan
    }

    # Build the web version header
    $WebScript = @"
# Windows${Type}Auditor - Self-Contained Web Version
# Version 2.0.0 - $Type Audit Script (Manifest-Based Build)
# Platform: Windows 10/11$(if ($Type -eq "Server") { ", Windows Server 2008-2022+" })
# Requires: PowerShell 5.0+
# Usage: iex (irm https://your-url/Windows${Type}Auditor-Web.ps1)
# Built: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# Modules: $($OrderedModules.Count) embedded modules in dependency order

param(
    [string]`$OutputPath = "`$env:USERPROFILE\WindowsAudit",
    [switch]`$Verbose
)

# Enable TLS 1.2 for older PowerShell versions (Windows Server 2008-2012 compatibility)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Host "WARNING: Failed to enable TLS 1.2 - continuing anyway" -ForegroundColor Yellow
}

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

# === EMBEDDED MODULES (DEPENDENCY ORDER) ===

"@

    # Embed modules in dependency order
    $EmbeddedCount = 0
    foreach ($Module in $OrderedModules) {
        if (Test-ModuleExists -FilePath $Module.file -ModuleName $Module.name) {
            $Content = Get-Content $Module.file -Raw
            $WebScript += "`n# [$($Module.category.ToUpper())] $($Module.name) - $($Module.description)`n"
            $WebScript += "# Dependencies: $($Module.dependencies -join ', ')`n"
            $WebScript += "# Order: $($Module.order)`n"
            $WebScript += $Content + "`n"
            $EmbeddedCount++
            Write-Host "    ✓ [$($Module.category)] $($Module.name)" -ForegroundColor Green
        }
    }

    Write-Host "  → Successfully embedded $EmbeddedCount modules" -ForegroundColor Cyan

    # Add main script logic (excluding param block and module imports)
    $MainScriptLines = $MainScript -split "`n"
    $SkipUntilBanner = $true
    $InModuleLoadBlock = $false
    $InConfigLoadBlock = $false

    $WebScript += "`n# === MAIN SCRIPT LOGIC ===`n"
    $WebScript += "`n# Parse embedded configuration`n"
    $WebScript += "try {`n"
    $WebScript += "    `$Config = `$Script:EmbeddedConfig | ConvertFrom-Json`n"
    $WebScript += "    Write-Host `"Loaded embedded configuration (version: `$(`$Config.version))`" -ForegroundColor Green`n"
    $WebScript += "} catch {`n"
    $WebScript += "    Write-Host `"ERROR: Failed to parse embedded configuration: `$(`$_.Exception.Message)`" -ForegroundColor Red`n"
    $WebScript += "    exit 1`n"
    $WebScript += "}`n`n"

    foreach ($Line in $MainScriptLines) {
        # Skip everything until we hit the banner/pre-flight checks
        if ($SkipUntilBanner) {
            if ($Line -match "^#\s*Pre-flight checks" -or $Line -match "^Write-Host.*Auditor.*Assessment") {
                $SkipUntilBanner = $false
                $WebScript += $Line + "`n"
                continue
            }
            continue
        }
        # Skip direct dot-source imports
        if ($Line -match "^\s*\.\s+.*\.ps1") {
            continue
        }

        # Skip core module loading block
        if ($Line -match "^\s*#\s*Load core (functions|modules)" -or $Line -match "^\s*\`$CoreModules\s*=") {
            $InModuleLoadBlock = $true
            continue
        }
        if ($InModuleLoadBlock -eq $true) {
            if ($Line -match "^if.*Initialize-Logging") {
                $InModuleLoadBlock = $false
                $WebScript += $Line + "`n"
                continue
            }
            continue
        }

        # Skip external config file loading block (but keep $ServerAuditModules)
        if ($Line -match "^\s*#\s*Load configuration") {
            $InConfigLoadBlock = $true
            continue
        }
        if ($InConfigLoadBlock -eq $true) {
            # End at Module execution order comment or the $ServerAuditModules line
            if ($Line -match "^#\s*Module execution order" -or $Line -match "^\`$ServerAuditModules\s*=") {
                $InConfigLoadBlock = $false
                $WebScript += $Line + "`n"
                continue
            }
            continue
        }

        # Skip audit module file loading block (the foreach that loads from .\src\modules)
        if ($Line -match "^\s*#\s*Load all audit modules") {
            $InModuleLoadBlock = 2  # Use different value to avoid conflict
            continue
        }
        if ($InModuleLoadBlock -eq 2) {
            # End when we hit "Execute audit modules" comment
            if ($Line -match "^\s*#\s*Execute audit modules") {
                $InModuleLoadBlock = $false
                $WebScript += $Line + "`n"
                continue
            }
            continue
        }

        $WebScript += $Line + "`n"
    }

    # Ensure output directory exists
    $OutputDir = Split-Path $OutputFile -Parent
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    # Write the web version
    $WebScript | Set-Content -Path $OutputFile -Encoding UTF8

    $FileSize = [math]::Round((Get-Item $OutputFile).Length / 1KB)
    Write-Host "✓ Created: $OutputFile (${FileSize}KB, $EmbeddedCount modules)" -ForegroundColor Green

    return @{
        Success = $true
        OutputFile = $OutputFile
        FileSize = $FileSize
        ModuleCount = $EmbeddedCount
    }
}

function Build-macOSWebVersion {
    param(
        [string]$OutputDir,
        [object]$Manifest
    )

    Write-Host "Building macOS Workstation web version using manifest..." -ForegroundColor Green

    # Get source script from manifest
    $SourceScript = $Manifest.build_settings.macos.main_scripts.workstation
    $OutputFile = "$OutputDir/macOSWorkstationAuditor-Web.sh"

    if (-not (Test-Path $SourceScript)) {
        Write-Warning "Source script not found: $SourceScript"
        return
    }

    # Read the main script
    $MainScript = Get-Content $SourceScript -Raw

    # Get ordered modules from manifest
    $OrderedModules = Get-OrderedModules -Manifest $Manifest -Platform "macOS"

    Write-Host "  → Loading $($OrderedModules.Count) shell modules in order" -ForegroundColor Cyan

    # Read configuration from manifest
    $ConfigFile = $Manifest.build_settings.macos.config_files.workstation
    $ConfigContent = ""
    if (Test-Path $ConfigFile) {
        $ConfigContent = Get-Content $ConfigFile -Raw
        Write-Host "  → Embedded configuration from $ConfigFile" -ForegroundColor Cyan
    }

    # Build the web version
    $WebScript = @"
#!/bin/bash

# macOSWorkstationAuditor - Self-Contained Web Version
# Version 2.0.0 - macOS Workstation Audit Script (Manifest-Based Build)
# Platform: macOS 12+ (Monterey and later)
# Requires: bash 3.2+, standard macOS utilities
# Usage: curl -s https://your-url/macOSWorkstationAuditor-Web.sh | bash
# Built: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# Modules: $($OrderedModules.Count) embedded shell modules

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
CONFIG_VERSION="2.0.0"

# Ensure output directory exists
mkdir -p "`$OUTPUT_PATH" 2>/dev/null
mkdir -p "`$OUTPUT_PATH/logs" 2>/dev/null

# === EMBEDDED MODULES ===

"@

    # Embed modules in order
    $EmbeddedCount = 0
    foreach ($Module in $OrderedModules) {
        if (Test-ModuleExists -FilePath $Module.file -ModuleName $Module.name) {
            $Content = Get-Content $Module.file -Raw
            $WebScript += "`n# [$($Module.category.ToUpper())] $($Module.name) - $($Module.description)`n"
            $WebScript += "# Order: $($Module.order)`n"
            $WebScript += $Content + "`n"
            $EmbeddedCount++
            Write-Host "    ✓ [$($Module.category)] $($Module.name)" -ForegroundColor Green
        }
    }

    Write-Host "  → Successfully embedded $EmbeddedCount modules" -ForegroundColor Cyan

    # Add main script logic with modifications for web deployment
    $MainScriptLines = $MainScript -split "`n"

    $WebScript += "`n# === MAIN SCRIPT LOGIC (MODIFIED FOR WEB DEPLOYMENT) ===`n"
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

    # Ensure output directory exists
    $OutputDir = Split-Path $OutputFile -Parent
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    # Write the web version
    $WebScript | Set-Content -Path $OutputFile -Encoding UTF8 -NoNewline

    # Make the script executable on Unix-like systems
    if ($IsLinux -or $IsMacOS -or (Get-Command "chmod" -ErrorAction SilentlyContinue)) {
        & chmod +x $OutputFile 2>$null
    }

    $FileSize = [math]::Round((Get-Item $OutputFile).Length / 1KB)
    Write-Host "✓ Created: $OutputFile (${FileSize}KB, $EmbeddedCount modules)" -ForegroundColor Green

    return @{
        Success = $true
        OutputFile = $OutputFile
        FileSize = $FileSize
        ModuleCount = $EmbeddedCount
    }
}

# === MAIN EXECUTION ===

Write-Host "Build System 2.0 - Manifest-Based Web Deployment Builder" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

try {
    # Load the build manifest
    Write-Host "Loading build manifest: $ManifestPath" -ForegroundColor Yellow
    $Manifest = Get-BuildManifest -ManifestPath $ManifestPath
    Write-Host "✓ Manifest loaded successfully (Version: $($Manifest.version))" -ForegroundColor Green

    $BuildResults = @()

    if ($Platform -eq "All" -or $Platform -eq "Windows") {
        if ($Type -eq "All" -or $Type -eq "Workstation") {
            $Result = Build-WindowsWebVersion -Type "Workstation" -OutputDir $OutputDir -Manifest $Manifest
            $BuildResults += $Result
        }
        if ($Type -eq "All" -or $Type -eq "Server") {
            $Result = Build-WindowsWebVersion -Type "Server" -OutputDir $OutputDir -Manifest $Manifest
            $BuildResults += $Result
        }
    }

    if ($Platform -eq "All" -or $Platform -eq "macOS") {
        $Result = Build-macOSWebVersion -OutputDir $OutputDir -Manifest $Manifest
        $BuildResults += $Result
    }

    # Summary
    $SuccessfulBuilds = $BuildResults | Where-Object { $_.Success }
    $TotalSize = ($SuccessfulBuilds | Measure-Object FileSize -Sum).Sum
    $TotalModules = ($SuccessfulBuilds | Measure-Object ModuleCount -Sum).Sum

    Write-Host "`n🎉 Web versions built successfully!" -ForegroundColor Green
    Write-Host "   → $($SuccessfulBuilds.Count) files created (${TotalSize}KB total)" -ForegroundColor Green
    Write-Host "   → $TotalModules total modules embedded across all builds" -ForegroundColor Green
    Write-Host "   → Upload the generated files to your web server for remote deployment" -ForegroundColor Yellow

    if ($BuildResults.Count -ne $SuccessfulBuilds.Count) {
        Write-Warning "Some builds failed. Check the output above for details."
    }
}
catch {
    Write-Error "Build failed: $($_.Exception.Message)"
    exit 1
}
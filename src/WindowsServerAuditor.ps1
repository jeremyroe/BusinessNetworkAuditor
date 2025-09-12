# WindowsServerAuditor - Windows Server IT Assessment Tool
# Version 1.3.0 - Modular Architecture
# Platform: Windows Server 2016+ (use WindowsWorkstationAuditor.ps1 for workstations)
# Requires: PowerShell 5.0+, Local Administrator Rights (recommended)

param(
    [string]$OutputPath = ".\output",
    [string]$ConfigPath = ".\config",
    [switch]$Verbose,
    [switch]$Force
)

# Global variables
$Script:LogFile = ""
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:BaseFileName = "${ComputerName}_$($StartTime.ToString('yyyyMMdd_HHmmss'))"

# Module loading system
function Import-AuditModule {
    <#
    .SYNOPSIS
        Dynamically imports audit modules with dependency management
        
    .DESCRIPTION
        Loads PowerShell audit modules from the modules directory,
        handling dependencies and providing error handling.
        
    .PARAMETER ModuleName
        Name of the module to import (without .ps1 extension)
        
    .PARAMETER ModulePath
        Path to the modules directory
    #>
    param(
        [string]$ModuleName,
        [string]$ModulePath = ".\src\modules"
    )
    
    try {
        $ModuleFile = Join-Path $ModulePath "$ModuleName.ps1"
        if (Test-Path $ModuleFile) {
            # Dot-source the module file to load functions
            . $ModuleFile
            Write-LogMessage "SUCCESS" "Loaded module: $ModuleName" "MODULE"
            return $true
        } else {
            Write-LogMessage "ERROR" "Module file not found: $ModuleFile" "MODULE"
            return $false
        }
    }
    catch {
        Write-LogMessage "ERROR" "Failed to load module ${ModuleName}: $($_.Exception.Message)" "MODULE"
        return $false
    }
}

# Pre-flight checks
Write-Host "WindowsServerAuditor v1.3.0 - Windows Server IT Assessment Tool" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

# Check if running on Windows Server
$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if ($OSInfo.ProductType -eq 1) {
    Write-Host "WARNING: This system appears to be a workstation, not a server." -ForegroundColor Yellow
    Write-Host "Consider using WindowsWorkstationAuditor.ps1 instead." -ForegroundColor Yellow
    if (-not $Force) {
        Write-Host "Use -Force parameter to continue anyway." -ForegroundColor Yellow
        exit 1
    }
}

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "ERROR: PowerShell 5.0 or higher is required. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    exit 1
}

# Create output directory structure
if (-not (Test-Path $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Failed to create output directory: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Load core functions
Write-Host "Loading core functions..." -ForegroundColor Yellow

$CoreModules = @(
    "Write-LogMessage",
    "Initialize-Logging", 
    "Export-MarkdownReport",
    "Export-RawDataJSON"
)

foreach ($CoreModule in $CoreModules) {
    $CoreModuleFile = ".\src\core\$CoreModule.ps1"
    if (Test-Path $CoreModuleFile) {
        try {
            . $CoreModuleFile
            Write-Host "  [OK] Loaded $CoreModule" -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERROR] Failed to load $CoreModule : $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "  [ERROR] Core module not found: $CoreModuleFile" -ForegroundColor Red
        exit 1
    }
}

# Initialize logging
if (-not (Initialize-Logging -LogDirectory (Join-Path $OutputPath "logs") -LogFileName "${Script:BaseFileName}_server_audit.log")) {
    Write-Host "ERROR: Failed to initialize logging system" -ForegroundColor Red
    exit 1
}

Write-LogMessage "INFO" "WindowsServerAuditor v1.3.0 starting..." "MAIN"
Write-LogMessage "INFO" "Server: $($env:COMPUTERNAME)" "MAIN" 
Write-LogMessage "INFO" "OS: $($OSInfo.Caption) $($OSInfo.Version)" "MAIN"
Write-LogMessage "INFO" "Output directory: $OutputPath" "MAIN"

# Load configuration
$ConfigFile = Join-Path $ConfigPath "server-audit-config.json"
if (Test-Path $ConfigFile) {
    try {
        $Config = Get-Content $ConfigFile | ConvertFrom-Json
        Write-LogMessage "SUCCESS" "Configuration loaded from: $ConfigFile" "CONFIG"
    }
    catch {
        Write-LogMessage "ERROR" "Failed to load configuration: $($_.Exception.Message)" "CONFIG"
        Write-LogMessage "INFO" "Using default configuration" "CONFIG"
        $Config = $null
    }
} else {
    Write-LogMessage "WARN" "Configuration file not found: $ConfigFile" "CONFIG" 
    Write-LogMessage "INFO" "Using default configuration" "CONFIG"
    $Config = $null
}

# Default configuration for servers
if (-not $Config) {
    $Config = @{
        version = "1.3.0"
        modules = @{
            # Core system modules (reused from workstation)
            system = @{ enabled = $true; timeout = 30 }
            memory = @{ enabled = $true; timeout = 15 }
            disk = @{ enabled = $true; timeout = 20 }
            network = @{ enabled = $true; timeout = 30 }
            process = @{ enabled = $true; timeout = 30 }
            patches = @{ enabled = $true; timeout = 60 }
            software = @{ enabled = $true; timeout = 45 }
            security = @{ enabled = $true; timeout = 20 }
            eventlog = @{ enabled = $true; timeout = 45 }
            users = @{ enabled = $true; timeout = 20 }
            
            # Server-specific modules
            serverroles = @{ enabled = $true; timeout = 30 }
            dhcp = @{ enabled = $true; timeout = 20 }
            dns = @{ enabled = $true; timeout = 20 }
            fileshares = @{ enabled = $true; timeout = 15 }
            activedirectory = @{ enabled = $true; timeout = 45 }
            iis = @{ enabled = $true; timeout = 20 }
            services = @{ enabled = $true; timeout = 15 }
        }
        output = @{
            formats = @("markdown", "rawjson")
            path = $OutputPath
            timestamp = $true
        }
    }
}

# Module execution order for servers
$ServerAuditModules = @(
    # Core system analysis (reused modules)
    @{Name="Get-SystemInformation"; Config="system"}
    @{Name="Get-MemoryAnalysis"; Config="memory"}
    @{Name="Get-DiskSpaceAnalysis"; Config="disk"}
    @{Name="Get-PatchStatus"; Config="patches"}
    @{Name="Get-ProcessAnalysis"; Config="process"}
    @{Name="Get-SoftwareInventory"; Config="software"}
    @{Name="Get-SecuritySettings"; Config="security"}
    @{Name="Get-NetworkAnalysis"; Config="network"}
    @{Name="Get-EventLogAnalysis"; Config="eventlog"}
    @{Name="Get-UserAccountAnalysis"; Config="users"}
    
    # Server-specific analysis (new modules)
    @{Name="Get-ServerRoleAnalysis"; Config="serverroles"}
    @{Name="Get-DHCPAnalysis"; Config="dhcp"}
    @{Name="Get-DNSAnalysis"; Config="dns"}
    @{Name="Get-FileShareAnalysis"; Config="fileshares"}
    @{Name="Get-ActiveDirectoryAnalysis"; Config="activedirectory"}
    @{Name="Get-IISAnalysis"; Config="iis"}
    @{Name="Get-ServerServiceAnalysis"; Config="services"}
)

# Load all audit modules at script level to ensure global scope
Write-LogMessage "INFO" "Loading audit modules..." "MAIN"
$AuditModuleFiles = @(
    # Core system analysis (reused from workstation)
    "Get-SystemInformation",
    "Get-MemoryAnalysis",
    "Get-DiskSpaceAnalysis", 
    "Get-PatchStatus",
    "Get-ProcessAnalysis",
    "Get-SoftwareInventory",
    "Get-SecuritySettings",
    "Get-NetworkAnalysis",
    "Get-EventLogAnalysis",
    "Get-UserAccountAnalysis",
    
    # Server-specific modules
    "Get-ServerRoleAnalysis",
    "Get-DHCPAnalysis",
    "Get-DNSAnalysis",
    "Get-FileShareAnalysis",
    "Get-ActiveDirectoryAnalysis"
    # Note: IIS module not yet created
)

foreach ($ModuleName in $AuditModuleFiles) {
    $ModuleFile = ".\src\modules\$ModuleName.ps1"
    if (Test-Path $ModuleFile) {
        try {
            . $ModuleFile
            Write-LogMessage "SUCCESS" "Loaded module: $ModuleName" "MODULE"
        }
        catch {
            Write-LogMessage "ERROR" "Failed to load module $ModuleName : $($_.Exception.Message)" "MODULE"
        }
    } else {
        Write-LogMessage "WARN" "Module file not found: $ModuleFile" "MODULE"
    }
}

# Execute audit modules  
Write-LogMessage "INFO" "Starting server audit modules..." "MAIN"
$AllResults = @()
$ModuleResults = @{}

foreach ($Module in $ServerAuditModules) {
    $ModuleName = $Module.Name
    $ModuleConfig = $Module.Config
    
    # Check if module is enabled in config
    if ($Config.modules.$ModuleConfig.enabled -eq $false) {
        Write-LogMessage "INFO" "Module $ModuleName is disabled - skipping" "MODULE"
        continue
    }
    
    # Set timeout for module execution
    $TimeoutSeconds = $Config.modules.$ModuleConfig.timeout
    if (-not $TimeoutSeconds) { $TimeoutSeconds = 30 }
    
    try {
        # Load the module (skip import since modules are loaded at script level)
        if (Get-Command $ModuleName -ErrorAction SilentlyContinue) {
            Write-LogMessage "INFO" "Executing module: $ModuleName (timeout: ${TimeoutSeconds}s)" "AUDIT"
            $ModuleStartTime = Get-Date
            
            # Execute the module function
            try {
                $Results = & $ModuleName
                $ModuleDuration = ((Get-Date) - $ModuleStartTime).TotalSeconds
                
                if ($Results -and $Results.Count -gt 0) {
                    $AllResults += $Results
                    $ModuleResults[$ModuleName] = $Results
                    Write-LogMessage "SUCCESS" "$ModuleName completed in $([math]::Round($ModuleDuration, 2))s - $($Results.Count) results" "AUDIT"
                } else {
                    Write-LogMessage "WARN" "$ModuleName returned no results" "AUDIT"
                }
            }
            catch {
                Write-LogMessage "ERROR" "$ModuleName execution failed: $($_.Exception.Message)" "AUDIT"
            }
        }
    }
    catch {
        Write-LogMessage "ERROR" "Failed to process module $ModuleName : $($_.Exception.Message)" "MODULE"
    }
}

# Generate final results
$AuditDuration = ((Get-Date) - $Script:StartTime).TotalMinutes
Write-LogMessage "INFO" "Server audit completed in $([math]::Round($AuditDuration, 2)) minutes" "MAIN"
Write-LogMessage "INFO" "Total findings: $($AllResults.Count)" "MAIN"

if ($AllResults.Count -gt 0) {
    # Export results
    try {
        Write-LogMessage "INFO" "Exporting audit results..." "EXPORT"
        
        if ($Config.output.formats -contains "markdown") {
            Export-MarkdownReport -Results $AllResults -OutputPath $OutputPath -BaseFileName $Script:BaseFileName -IsServer $true
        }
        
        if ($Config.output.formats -contains "rawjson") {  
            Export-RawDataJSON -Results $AllResults -OutputPath $OutputPath -BaseFileName $Script:BaseFileName -IsServer $true
        }
        
        Write-LogMessage "SUCCESS" "Server audit results exported to: $OutputPath" "EXPORT"
        
        # Display summary
        $RiskCounts = $AllResults | Group-Object RiskLevel | ForEach-Object { "$($_.Name): $($_.Count)" }
        Write-LogMessage "INFO" "Risk summary - $($RiskCounts -join ', ')" "SUMMARY"
        
        Write-Host "`nServer Audit Complete!" -ForegroundColor Green
        Write-Host "Results saved to: $OutputPath" -ForegroundColor Cyan
        Write-Host "Log file: $($Script:LogFile)" -ForegroundColor Cyan
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to export results: $($_.Exception.Message)" "EXPORT"
    }
} else {
    Write-LogMessage "ERROR" "No audit results to export" "MAIN"
    Write-Host "ERROR: No audit results were collected. Check the log file for details." -ForegroundColor Red
}

Write-LogMessage "INFO" "WindowsServerAuditor execution completed" "MAIN"
# WindowsWorkstationAuditor - Logging Initialization Module
# Version 1.3.0

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the logging system for the audit tool
        
    .DESCRIPTION
        Creates log directory structure and sets up the main log file path.
        Can work with parameters or global script variables.
        
    .PARAMETER LogDirectory
        Directory to create log files in (optional, uses $OutputPath/logs if not specified)
        
    .PARAMETER LogFileName
        Name of the log file (optional, uses ${Script:BaseFileName}_audit.log if not specified)
        
    .NOTES
        Requires: $OutputPath, $Script:BaseFileName, $ComputerName global variables (if parameters not provided)
    #>
    param(
        [string]$LogDirectory,
        [string]$LogFileName
    )
    
    try {
        # Use parameters if provided, otherwise fall back to global variables
        if (-not $LogDirectory) {
            $LogDirectory = Join-Path $OutputPath "logs"
        }
        
        if (-not $LogFileName) {
            $LogFileName = "${Script:BaseFileName}_audit.log"
        }
        
        if (-not (Test-Path $LogDirectory)) {
            New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
        }
        
        $Script:LogFile = Join-Path $LogDirectory $LogFileName
        
        # Determine if this is workstation or server based on the filename
        $AuditorType = if ($LogFileName -like "*server*") { "WindowsServerAuditor" } else { "WindowsWorkstationAuditor" }
        
        Write-LogMessage "INFO" "$AuditorType v1.3.0 Started"
        Write-LogMessage "INFO" "Computer: $($Script:ComputerName)"
        Write-LogMessage "INFO" "User: $env:USERNAME"
        Write-LogMessage "INFO" "Base filename: $Script:BaseFileName"
        Write-LogMessage "INFO" "Log file: $Script:LogFile"
        
        return $true
    }
    catch {
        Write-Host "ERROR: Failed to initialize logging: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}
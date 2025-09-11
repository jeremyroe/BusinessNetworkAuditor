# WindowsWorkstationAuditor - Centralized Logging Module
# Version 1.3.0

function Write-LogMessage {
    <#
    .SYNOPSIS
        Centralized logging function with console and file output
        
    .DESCRIPTION
        Writes log messages with timestamp, level, and category formatting.
        Provides colored console output and file logging capabilities.
        
    .PARAMETER Level
        Log level: ERROR, WARN, SUCCESS, INFO
        
    .PARAMETER Message
        The log message content
        
    .PARAMETER Category
        Optional category for message organization (default: GENERAL)
        
    .NOTES
        Requires: $Script:LogFile global variable for file output
    #>
    param(
        [string]$Level,
        [string]$Message,
        [string]$Category = "GENERAL"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] [$Category] $Message"
    
    # Console output with color coding
    switch ($Level) {
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        "WARN"  { Write-Host $LogEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        default { Write-Host $LogEntry }
    }
    
    # File output
    if ($Script:LogFile) {
        Add-Content -Path $Script:LogFile -Value $LogEntry
    }
}
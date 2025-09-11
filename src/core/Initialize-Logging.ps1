# WindowsWorkstationAuditor - Logging Initialization Module
# Version 1.3.0

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the logging system for the Windows Workstation Auditor
        
    .DESCRIPTION
        Creates log directory structure and sets up the main log file path.
        Depends on global script variables for output path and base filename.
        
    .NOTES
        Requires: $OutputPath, $Script:BaseFileName, $ComputerName global variables
    #>
    
    $LogDirectory = Join-Path $OutputPath "logs"
    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    
    $Script:LogFile = Join-Path $LogDirectory "${Script:BaseFileName}_audit.log"
    
    Write-LogMessage "INFO" "Windows Workstation Auditor v1.3.0 Started"
    Write-LogMessage "INFO" "Computer: $ComputerName"
    Write-LogMessage "INFO" "User: $env:USERNAME"
    Write-LogMessage "INFO" "Base filename: $Script:BaseFileName"
}
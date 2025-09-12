# WindowsWorkstationAuditor - Testing Guide
*Version 1.3.0 - Modular Architecture*

## Overview
This guide provides comprehensive testing instructions for the modular WindowsWorkstationAuditor system. Follow these steps to validate functionality before production deployment.

## Prerequisites

### System Requirements
- **PowerShell**: Version 5.0 or higher
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **Permissions**: Local Administrator rights (recommended for full functionality)
- **PowerShell Execution Policy**: RemoteSigned or Unrestricted

### Check Prerequisites
```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Check execution policy
Get-ExecutionPolicy

# Set execution policy if needed (as Administrator)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Testing Phases

### Phase 1: Structure Validation

#### 1.1 Manual Structure Test
```powershell
# Navigate to project root
cd C:\Path\To\WindowsWorkstationAuditor

# Check required files exist
$RequiredFiles = @(
    "src\WindowsWorkstationAuditor.ps1",
    "src\core\Initialize-Logging.ps1", 
    "src\core\Write-LogMessage.ps1",
    "src\modules\Get-SystemInformation.ps1",
    # ... all module files
    "config\audit-config.json"
)

foreach ($File in $RequiredFiles) {
    if (Test-Path $File) {
        Write-Host "[OK] $File" -ForegroundColor Green
    } else {
        Write-Host "[MISSING] $File" -ForegroundColor Red
    }
}
```

**Expected Output:**
- [OK] All required files present
- All PowerShell files have valid syntax  
- Configuration file is valid JSON

#### 1.2 Manual File Verification
```powershell
# Check core files exist
Get-ChildItem src\core\*.ps1
Get-ChildItem src\modules\*.ps1
Test-Path config\audit-config.json

# Verify file sizes (should not be 0 bytes)
Get-ChildItem src\modules\*.ps1 | Select-Object Name, Length
```

### Phase 2: Module Testing

#### 2.1 Individual Module Testing
Test each module independently to isolate any issues:

```powershell
# Load core logging functions first
. .\src\core\Write-LogMessage.ps1
. .\src\core\Initialize-Logging.ps1

# Initialize basic logging for testing
$Script:LogFile = ".\test-audit.log"
$OutputPath = ".\test-output"

# Test individual modules
. .\src\modules\Get-SystemInformation.ps1
$Results = Get-SystemInformation
Write-Host "System module returned $($Results.Count) results" -ForegroundColor Green

. .\src\modules\Get-DiskSpaceAnalysis.ps1  
$Results = Get-DiskSpaceAnalysis
Write-Host "Disk module returned $($Results.Count) results" -ForegroundColor Green

# Continue for other modules...
```

#### 2.2 Module Function Verification
```powershell
# Verify all expected functions are loaded
$ExpectedFunctions = @(
    'Get-SystemInformation', 'Get-UserAccountAnalysis', 'Get-SoftwareInventory',
    'Get-SecuritySettings', 'Get-PatchStatus', 'Get-PolicyAnalysis',
    'Get-DiskSpaceAnalysis', 'Get-MemoryAnalysis', 'Get-PrinterAnalysis', 
    'Get-NetworkAnalysis', 'Get-ProcessAnalysis', 'Get-EventLogAnalysis'
)

foreach ($Function in $ExpectedFunctions) {
    if (Get-Command $Function -ErrorAction SilentlyContinue) {
        Write-Host "✅ $Function" -ForegroundColor Green
    } else {
        Write-Host "❌ $Function" -ForegroundColor Red
    }
}
```

### Phase 3: Configuration Testing

#### 3.1 Configuration Validation
```powershell
# Test configuration loading
$Config = Get-Content .\config\audit-config.json | ConvertFrom-Json

# Verify all modules are configured
$ConfiguredModules = $Config.modules | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
Write-Host "Configured modules: $($ConfiguredModules.Count)" -ForegroundColor Cyan
$ConfiguredModules | ForEach-Object { Write-Host "  - $_" }

# Check output formats
Write-Host "Output formats: $($Config.output.formats -join ', ')" -ForegroundColor Cyan
```

#### 3.2 Module Enable/Disable Testing
```powershell
# Test selective module execution by temporarily modifying config
$OriginalConfig = Get-Content .\config\audit-config.json
$Config = $OriginalConfig | ConvertFrom-Json

# Disable all but system module for quick test
$Config.modules.PSObject.Properties | ForEach-Object { 
    if ($_.Name -ne 'system') { $_.Value.enabled = $false }
}

# Save temporary config
$Config | ConvertTo-Json -Depth 10 | Set-Content .\config\audit-config-test.json

# Test with limited config
.\src\WindowsWorkstationAuditor-Modular.ps1 -ConfigPath .\config -OutputPath .\test-output

# Restore original config
$OriginalConfig | Set-Content .\config\audit-config.json
Remove-Item .\config\audit-config-test.json
```

### Phase 4: Integration Testing

#### 4.1 Full System Test (Safe Mode)
```powershell
# Run complete audit in test mode
New-Item -ItemType Directory -Path .\test-output -Force

# Execute full modular audit
.\src\WindowsWorkstationAuditor.ps1 -OutputPath .\test-output -Verbose

# Verify outputs were created
Get-ChildItem .\test-output

# Check log file for errors
$LogFiles = Get-ChildItem .\test-output\logs\*.log
if ($LogFiles) {
    $LogContent = Get-Content $LogFiles[-1]  # Most recent log
    $Errors = $LogContent | Where-Object { $_ -match '\[ERROR\]' }
    $Warnings = $LogContent | Where-Object { $_ -match '\[WARN\]' }
    
    Write-Host "Log Analysis:" -ForegroundColor Cyan
    Write-Host "  Errors: $($Errors.Count)" -ForegroundColor $(if($Errors.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  Warnings: $($Warnings.Count)" -ForegroundColor Yellow
}
```

#### 4.2 Output Validation
```powershell
# Check CSV output
$CSVFiles = Get-ChildItem .\test-output\*.csv
if ($CSVFiles) {
    $CSV = Import-Csv $CSVFiles[0]
    Write-Host "CSV Results: $($CSV.Count) entries" -ForegroundColor Green
    
    # Verify required columns exist
    $RequiredColumns = @('Category', 'Item', 'Value', 'Details', 'RiskLevel', 'Compliance')
    $CSVColumns = $CSV[0].PSObject.Properties.Name
    
    foreach ($Column in $RequiredColumns) {
        if ($Column -in $CSVColumns) {
            Write-Host "  ✅ $Column column present" -ForegroundColor Green
        } else {
            Write-Host "  ❌ $Column column missing" -ForegroundColor Red
        }
    }
    
    # Check risk levels
    $RiskLevels = $CSV | Group-Object RiskLevel | Select-Object Name, Count
    Write-Host "Risk Level Distribution:" -ForegroundColor Cyan
    $RiskLevels | ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" }
}

# Check JSON output (if configured)
$JSONFiles = Get-ChildItem .\test-output\*.json -ErrorAction SilentlyContinue
if ($JSONFiles) {
    $JSON = Get-Content $JSONFiles[0] | ConvertFrom-Json
    Write-Host "JSON Results: $($JSON.Count) entries" -ForegroundColor Green
}
```

### Phase 5: Performance Testing

#### 5.1 Execution Time Testing
```powershell
# Measure execution time
$StartTime = Get-Date
.\src\WindowsWorkstationAuditor.ps1 -OutputPath .\perf-test
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Host "Execution Time: $($Duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor Cyan

# Check individual module performance from logs
$LogFile = Get-ChildItem .\perf-test\logs\*.log | Sort-Object LastWriteTime | Select-Object -Last 1
$LogContent = Get-Content $LogFile
$ModuleCompletions = $LogContent | Where-Object { $_ -match 'completed in \d+\.\d+ seconds' }

Write-Host "Module Performance:" -ForegroundColor Cyan
$ModuleCompletions | ForEach-Object { Write-Host "  $_" }
```

#### 5.2 Resource Usage Monitoring
```powershell
# Monitor memory usage during execution (run in separate PowerShell session)
$Process = Start-Process powershell -ArgumentList "-File .\src\WindowsWorkstationAuditor.ps1 -OutputPath .\resource-test" -PassThru
$MaxMemory = 0

while (!$Process.HasExited) {
    $CurrentMemory = $Process.WorkingSet64 / 1MB
    if ($CurrentMemory -gt $MaxMemory) { $MaxMemory = $CurrentMemory }
    Start-Sleep -Seconds 1
}

Write-Host "Peak Memory Usage: $($MaxMemory.ToString('F2')) MB" -ForegroundColor Cyan
```

## Common Issues & Troubleshooting

### Issue 1: Module Loading Failures
**Symptoms:** "Module file not found" or "Failed to load module" errors

**Solutions:**
```powershell
# Check file paths and permissions
Get-ChildItem src\modules\*.ps1 | ForEach-Object { 
    Write-Host "$($_.Name): $($_.Length) bytes" 
}

# Verify execution policy
Get-ExecutionPolicy -List

# Check for syntax errors
Get-ChildItem src\modules\*.ps1 | ForEach-Object {
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $_.FullName -Raw), [ref]$null)
        Write-Host "✅ $($_.Name)" -ForegroundColor Green
    } catch {
        Write-Host "❌ $($_.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}
```

### Issue 2: Access Denied Errors
**Symptoms:** WMI access denied, registry access denied, service enumeration failures

**Solutions:**
```powershell
# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as Administrator: $IsAdmin" -ForegroundColor $(if($IsAdmin){'Green'}else{'Yellow'})

# Test WMI access
try {
    $OS = Get-CimInstance Win32_OperatingSystem
    Write-Host "✅ WMI Access: OK" -ForegroundColor Green
} catch {
    Write-Host "❌ WMI Access: $($_.Exception.Message)" -ForegroundColor Red
}

# Test registry access
try {
    $RegTest = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
    Write-Host "✅ Registry Access: OK" -ForegroundColor Green
} catch {
    Write-Host "❌ Registry Access: $($_.Exception.Message)" -ForegroundColor Red
}
```

### Issue 3: Configuration Issues
**Symptoms:** JSON parsing errors, module configuration not loaded

**Solutions:**
```powershell
# Validate JSON syntax
try {
    $Config = Get-Content .\config\audit-config.json | ConvertFrom-Json
    Write-Host "✅ Configuration: Valid JSON" -ForegroundColor Green
} catch {
    Write-Host "❌ Configuration: $($_.Exception.Message)" -ForegroundColor Red
    
    # Show JSON validation using online tool or manual inspection
    Get-Content .\config\audit-config.json
}

# Reset to default configuration if needed
$DefaultConfig = @{
    version = "1.3.0"
    modules = @{
        system = @{ enabled = $true; timeout = 30 }
        users = @{ enabled = $true; timeout = 15 }
        # ... add other modules as needed
    }
    output = @{
        formats = @("csv")
        path = "./output"
        timestamp = $true
    }
}

$DefaultConfig | ConvertTo-Json -Depth 10 | Set-Content .\config\audit-config-backup.json
```

## Test Scenarios by Environment

### Development Environment
```powershell
# Manual validation test
# Check file structure and syntax manually

# Single module test
.\src\WindowsWorkstationAuditor.ps1 -OutputPath .\dev-test -Verbose
```

### Staging Environment  
```powershell
# Full system test with all modules
.\src\WindowsWorkstationAuditor.ps1 -OutputPath .\staging-test

# Performance baseline test
Measure-Command { .\src\WindowsWorkstationAuditor.ps1 -OutputPath .\perf-baseline }
```

### Production Environment
```powershell
# Pre-deployment verification
# Manual file structure check

# Monitored production test
$Results = .\src\WindowsWorkstationAuditor.ps1 -OutputPath C:\AuditResults\$(Get-Date -Format 'yyyyMMdd_HHmmss')

# Verify results and logs
if ($Results.Count -gt 0) {
    Write-Host "[SUCCESS] Production test completed successfully - $($Results.Count) results generated"
} else {
    Write-Host "[WARNING] Production test completed but no results generated - check logs"
}
```

## Success Criteria

### Module Loading
- ✅ All 12 audit modules load without errors
- ✅ Core logging functions initialize properly
- ✅ Configuration file parses correctly

### Execution
- ✅ Audit completes without fatal errors
- ✅ Results generated in expected format(s)
- ✅ Log file created with appropriate entries
- ✅ Execution time under 10 minutes on typical workstation

### Output Quality
- ✅ Risk levels properly assigned (HIGH/MEDIUM/LOW/INFO)
- ✅ NIST compliance recommendations included where appropriate
- ✅ All required columns present in CSV output
- ✅ No duplicate entries in results

### Error Handling
- ✅ Graceful handling of access denied scenarios
- ✅ Proper logging of warnings and errors
- ✅ System continues execution despite individual module failures

---

## Continuous Testing

### Automated Testing Setup
Create a scheduled task or script to run periodic validation:

```powershell
# Weekly validation script
$TestResults = .\test-modular.ps1 *>&1
$TestLog = "test-results-$(Get-Date -Format 'yyyyMMdd').log"
$TestResults | Out-File $TestLog

if ($TestResults -match "All tests passed") {
    Write-EventLog -LogName Application -Source "WindowsWorkstationAuditor" -EventId 1000 -Message "Weekly validation passed"
} else {
    Write-EventLog -LogName Application -Source "WindowsWorkstationAuditor" -EventId 1001 -EntryType Warning -Message "Weekly validation failed - see $TestLog"
}
```

Remember to test in a non-production environment first, and always review logs for any warnings or issues before deploying to production systems.
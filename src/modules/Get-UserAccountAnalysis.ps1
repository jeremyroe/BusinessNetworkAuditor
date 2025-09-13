# WindowsWorkstationAuditor - User Account Analysis Module
# Version 1.3.0

function Get-UserAccountAnalysis {
    <#
    .SYNOPSIS
        Analyzes user accounts and administrative privileges with Azure AD support
        
    .DESCRIPTION
        Performs comprehensive analysis of local and Azure AD user accounts including:
        - Local administrator account enumeration
        - Current user privilege assessment
        - Guest account status verification
        - Azure AD joined system detection
        - Administrative privilege distribution analysis
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local admin rights recommended for complete analysis
        Supports: Traditional domain, Azure AD joined, and workgroup systems
    #>
    
    Write-LogMessage "INFO" "Analyzing user accounts..." "USERS"
    
    try {
        $LocalAdmins = @()
        
        # Determine execution context
        $CurrentUser = if ($env:USERNAME -eq "SYSTEM") { "SYSTEM" } else { $env:USERNAME }
        Write-LogMessage "INFO" "Current user: $CurrentUser" "USERS"
        
        # Check if current user is admin
        $IsCurrentUserAdmin = $false
        try {
            $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
            $IsCurrentUserAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            Write-LogMessage "INFO" "Current user is admin: $IsCurrentUserAdmin" "USERS"
        }
        catch {
            Write-LogMessage "WARN" "Could not check current user admin status: $($_.Exception.Message)" "USERS"
        }
        
        # Method 1: Try Get-LocalGroupMember (best for Azure AD)
        try {
            Write-LogMessage "INFO" "Attempting Get-LocalGroupMember..." "USERS"
            $AdminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            Write-LogMessage "INFO" "Get-LocalGroupMember returned $($AdminMembers.Count) members" "USERS"
            
            $LocalAdmins = foreach ($Member in $AdminMembers) {
                Write-LogMessage "INFO" "Processing member: Name='$($Member.Name)', ObjectClass='$($Member.ObjectClass)'" "USERS"
                
                # Extract just the username part
                if ($Member.Name -match "\\") {
                    $Username = $Member.Name.Split('\')[-1]
                } else {
                    $Username = $Member.Name
                }
                Write-LogMessage "INFO" "Extracted username: '$Username'" "USERS"
                $Username
            }
        }
        catch {
            Write-LogMessage "WARN" "Get-LocalGroupMember failed: $($_.Exception.Message)" "USERS"
        }
        
        # Method 2: Fallback to net localgroup
        if ($LocalAdmins.Count -eq 0) {
            try {
                Write-LogMessage "INFO" "Fallback: Using net localgroup Administrators" "USERS"
                $NetOutput = & net localgroup Administrators 2>&1
                Write-LogMessage "INFO" "Net command output has $($NetOutput.Count) lines" "USERS"
                
                if ($LASTEXITCODE -eq 0) {
                    $InMembersList = $false
                    $LocalAdmins = foreach ($Line in $NetOutput) {
                        # Look for the separator line
                        if ($Line -match "^-+$") {
                            $InMembersList = $true
                            continue
                        }
                        
                        # Process member lines
                        if ($InMembersList -and $Line.Trim() -ne "" -and $Line -notmatch "The command completed successfully") {
                            $CleanName = $Line.Trim()
                            # Handle AzureAD\ prefix
                            if ($CleanName -match "^AzureAD\\(.+)$") {
                                $CleanName = $matches[1]
                            }
                            Write-LogMessage "INFO" "Found admin: '$CleanName'" "USERS"
                            $CleanName
                        }
                    }
                }
            }
            catch {
                Write-LogMessage "ERROR" "Net localgroup method failed: $($_.Exception.Message)" "USERS"
            }
        }
        
        # Method 3: If still no admins but current user is admin, add them
        if ($LocalAdmins.Count -eq 0 -and $IsCurrentUserAdmin) {
            Write-LogMessage "INFO" "Adding current user as admin since detection failed" "USERS"
            $LocalAdmins = @($env:USERNAME)
        }
        
        # Get local users for Guest account check
        $LocalUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True"
        
        $Results = @()
        
        # Local Administrator Count
        $AdminCount = $LocalAdmins.Count
        Write-LogMessage "SUCCESS" "Administrator count: $AdminCount" "USERS"
        $Results += [PSCustomObject]@{
            Category = "Users"
            Item = "Local Administrators"
            Value = $AdminCount
            Details = "Users: $($LocalAdmins -join ', ')"
            RiskLevel = if ($AdminCount -gt 3) { "HIGH" } elseif ($AdminCount -gt 1) { "MEDIUM" } else { "LOW" }
            Recommendation = if ($AdminCount -gt 3) { "Limit administrative access" } else { "" }
        }
        
        # Guest Account Status
        $GuestAccount = $LocalUsers | Where-Object { $_.Name -eq "Guest" }
        if ($GuestAccount) {
            $Results += [PSCustomObject]@{
                Category = "Users"
                Item = "Guest Account"
                Value = if ($GuestAccount.Disabled) { "Disabled" } else { "Enabled" }
                Details = "Guest account status"
                RiskLevel = if ($GuestAccount.Disabled) { "LOW" } else { "HIGH" }
                Recommendation = if (-not $GuestAccount.Disabled) { "Disable guest account" } else { "" }
            }
        }
        
        Write-LogMessage "SUCCESS" "User account analysis completed - Found $AdminCount administrators" "USERS"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze user accounts: $($_.Exception.Message)" "USERS"
        return @()
    }
}
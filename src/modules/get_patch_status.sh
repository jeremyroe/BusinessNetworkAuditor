#!/bin/bash

# macOSWorkstationAuditor - Patch Status Module
# Version 1.0.0

# Global variables for collecting data
declare -a PATCH_FINDINGS=()

get_patch_status_data() {
    log_message "INFO" "Checking patch status and updates..." "PATCHING"
    
    # Initialize findings array
    PATCH_FINDINGS=()
    
    # Check macOS version and updates
    check_macos_version
    
    # Check available updates
    check_available_updates
    
    # Check automatic update settings
    check_auto_update_settings
    
    # Check XProtect updates
    check_xprotect_updates
    
    log_message "SUCCESS" "Patch status analysis completed - ${#PATCH_FINDINGS[@]} findings" "PATCHING"
}

check_macos_version() {
    log_message "INFO" "Checking macOS version..." "PATCHING"
    
    local os_version=$(sw_vers -productVersion)
    local os_build=$(sw_vers -buildVersion)
    local os_name=$(sw_vers -productName)
    
    # Use the actual marketing version instead of internal version numbers
    # Extract major version from the marketing version (e.g., 15.1 -> 15)
    local marketing_major=$(echo "$os_version" | cut -d. -f1)
    local marketing_minor=$(echo "$os_version" | cut -d. -f2)
    
    # Ensure they are valid integers
    if ! [[ "$marketing_major" =~ ^[0-9]+$ ]]; then
        marketing_major=0
    fi
    if ! [[ "$marketing_minor" =~ ^[0-9]+$ ]]; then
        marketing_minor=0
    fi
    
    # Determine version status based on Apple's official support lifecycle
    # Updated with current end-of-support dates as of 2024/2025
    local version_status="Current Version"
    local risk_level="INFO"
    local recommendation=""
    local current_date=$(date +%Y%m%d)
    local monterey_eol="20241130"  # November 30, 2024
    local ventura_eol="20251130"   # November 30, 2025
    
    case "$marketing_major" in
        "15")
            version_status="Latest Version (Sequoia)"
            # Sequoia is the current latest version, fully supported
            ;;
        "14")
            version_status="Current Supported (Sonoma)"
            # Sonoma is currently supported, no EOL date announced yet
            ;;
        "13")
            version_status="Supported (Ventura)"
            if [[ $current_date -gt $ventura_eol ]]; then
                version_status="End of Life (Ventura)"
                risk_level="HIGH"
                recommendation="macOS 13 Ventura support ended November 30, 2025. Upgrade to macOS 14+ immediately"
            else
                risk_level="LOW"
                recommendation="macOS 13 Ventura support ends November 30, 2025. Plan upgrade to macOS 14+"
            fi
            ;;
        "12")
            if [[ $current_date -gt $monterey_eol ]]; then
                version_status="End of Life (Monterey)"
                risk_level="HIGH"
                recommendation="macOS 12 Monterey support ended November 30, 2024. Upgrade to macOS 13+ immediately"
            else
                version_status="End of Life Soon (Monterey)"
                risk_level="MEDIUM"
                recommendation="macOS 12 Monterey support ends November 30, 2024. Upgrade to macOS 13+ urgently"
            fi
            ;;
        "11")
            version_status="End of Life (Big Sur)"
            risk_level="HIGH"
            recommendation="macOS 11 Big Sur is no longer supported. Upgrade to macOS 13+ immediately"
            ;;
        "10")
            if [[ "$marketing_minor" -ge 15 ]]; then
                version_status="End of Life (Catalina/Legacy)"
                risk_level="HIGH"
                recommendation="macOS 10.15+ reached end of life. Upgrade to macOS 13+ immediately"
            else
                version_status="End of Life (Legacy)"
                risk_level="HIGH"
                recommendation="macOS version is no longer supported. Upgrade to macOS 13+ immediately"
            fi
            ;;
        *)
            # For unknown versions (future or very old), be conservative
            if [[ "$marketing_major" -gt 15 ]]; then
                version_status="Newer Version"
                recommendation="Running newer macOS version. Verify enterprise software compatibility"
            else
                version_status="End of Life (Legacy)"
                risk_level="HIGH"
                recommendation="macOS version is no longer supported. Upgrade to a current version immediately"
            fi
            ;;
    esac
    
    add_patch_finding "System" "macOS Version" "$os_version" "$os_name $os_version (Build: $os_build) - $version_status" "$risk_level" "$recommendation"
}

check_available_updates() {
    log_message "INFO" "Checking for available updates..." "PATCHING"
    
    # Check for software updates
    local update_output=""
    local update_count=0
    local critical_updates=0
    
    # Use softwareupdate to check for available updates
    if command -v softwareupdate >/dev/null 2>&1; then
        log_message "INFO" "Scanning for available updates (this may take a moment)..." "PATCHING"
        update_output=$(softwareupdate -l 2>/dev/null)
        
        if echo "$update_output" | grep -q "No new software available"; then
            add_patch_finding "Patching" "Available Updates" "None" "System is up to date" "INFO" ""
        elif echo "$update_output" | grep -q "Software Update found"; then
            # Count available updates and extract details
            update_count=$(echo "$update_output" | grep -c "Title:" || echo 0)
            
            # Extract update titles for details
            local update_titles=$(echo "$update_output" | grep "Title:" | sed 's/.*Title: //' | sed 's/,.*$//' | tr '\n' ', ' | sed 's/, $//')
            
            # Check for security/critical updates
            critical_updates=$(echo "$update_output" | grep -i -c "security\|critical" 2>/dev/null)
            if [[ -z "$critical_updates" ]]; then
                critical_updates=0
            fi
            critical_updates=$(echo "$critical_updates" | tr -d '[:space:]')
            # Ensure it's a valid number
            if ! [[ "$critical_updates" =~ ^[0-9]+$ ]]; then
                critical_updates=0
            fi
            
            local risk_level="MEDIUM"
            local recommendation="Install available updates to maintain security and stability"
            
            if [[ $critical_updates -gt 0 ]]; then
                risk_level="HIGH"
                recommendation="Critical security updates available. Install immediately"
            fi
            
            local update_details="Available: $update_titles"
            if [[ $critical_updates -gt 0 ]]; then
                update_details="$update_details ($critical_updates critical)"
            fi
            
            add_patch_finding "Patching" "Available Updates" "$update_count updates" "$update_details" "$risk_level" "$recommendation"
        else
            add_patch_finding "Patching" "Update Check" "Unable to determine" "Could not check for available updates" "LOW" "Manually check for updates in System Preferences"
        fi
    else
        add_patch_finding "Patching" "Update Tool" "Not Available" "softwareupdate command not found" "LOW" "Check system integrity"
    fi
}

check_auto_update_settings() {
    log_message "INFO" "Checking automatic update settings..." "PATCHING"
    
    # Check various automatic update preferences
    local auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "unknown")
    local auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null || echo "unknown")
    local auto_install_os=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "unknown")
    local auto_install_app=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null || echo "unknown")
    local auto_install_security=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null || echo "unknown")
    local auto_install_system=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "unknown")
    
    # Assess overall auto-update configuration
    local auto_config_score=0
    local config_issues=()
    
    # Check each setting
    if [[ "$auto_check" == "1" ]]; then
        ((auto_config_score++))
    else
        config_issues+=("Automatic check disabled")
    fi
    
    if [[ "$auto_download" == "1" ]]; then
        ((auto_config_score++))
    else
        config_issues+=("Automatic download disabled")
    fi
    
    if [[ "$auto_install_security" == "1" ]]; then
        ((auto_config_score++))
    else
        config_issues+=("Security updates not auto-installed")
    fi
    
    if [[ "$auto_install_system" == "1" ]]; then
        ((auto_config_score++))
    else
        config_issues+=("System updates not auto-installed")
    fi
    
    # Determine overall status
    local auto_status=""
    local risk_level="INFO"
    local recommendation=""
    
    if [[ $auto_config_score -ge 3 ]]; then
        auto_status="Well Configured"
    elif [[ $auto_config_score -ge 2 ]]; then
        auto_status="Partially Configured"
        risk_level="LOW"
        recommendation="Enable additional automatic update options for better security"
    else
        auto_status="Poorly Configured"
        risk_level="MEDIUM"
        recommendation="Enable automatic updates to ensure timely security patches"
    fi
    
    local details="Check: $auto_check, Download: $auto_download, Security: $auto_install_security, System: $auto_install_system"
    add_patch_finding "Patching" "Automatic Updates" "$auto_status" "$details" "$risk_level" "$recommendation"
    
    if [[ ${#config_issues[@]} -gt 0 ]]; then
        local issues_list=$(IFS=", "; echo "${config_issues[*]}")
        add_patch_finding "Patching" "Update Configuration Issues" "${#config_issues[@]} issues" "$issues_list" "$risk_level" "$recommendation"
    fi
}

check_xprotect_updates() {
    log_message "INFO" "Checking XProtect malware definitions..." "PATCHING"
    
    # Check for macOS version to determine XProtect structure
    local macos_major=$(sw_vers -productVersion | cut -d. -f1)
    local macos_minor=$(sw_vers -productVersion | cut -d. -f2)
    
    # Primary location for macOS 15+ (Sequoia)
    local xprotect_new="/var/protected/xprotect/XProtect.bundle/Contents/Resources/XProtect.yara"
    local xprotect_new_plist="/var/protected/xprotect/XProtect.bundle/Contents/Info.plist"
    
    # Legacy location (pre-Sequoia and fallback)
    local xprotect_legacy="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"
    local xprotect_legacy_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    
    # Very old location
    local xprotect_old="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist"
    
    local xprotect_version="Unknown"
    local update_time="Unknown"
    local xprotect_location="Not Found"
    local risk_level="INFO"
    local recommendation=""
    
    # Check new location first (macOS 15+)
    if [[ -f "$xprotect_new" && -f "$xprotect_new_plist" ]]; then
        xprotect_location="New Location (Sequoia+)"
        xprotect_version=$(defaults read "$xprotect_new_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        update_time=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_new" 2>/dev/null || echo "Unknown")
        local file_timestamp=$(stat -f "%m" "$xprotect_new" 2>/dev/null || echo "0")
        
        # Check if legacy version is newer (indicating update issue)
        if [[ -f "$xprotect_legacy_plist" ]]; then
            local legacy_version=$(defaults read "$xprotect_legacy_plist" CFBundleShortVersionString 2>/dev/null || echo "0")
            local legacy_timestamp=$(stat -f "%m" "$xprotect_legacy" 2>/dev/null || echo "0")
            
            if [[ $legacy_timestamp -gt $file_timestamp ]]; then
                recommendation="Legacy XProtect version appears newer. Run 'sudo xprotect update' to synchronize"
                risk_level="MEDIUM"
            fi
        fi
        
    # Check legacy location
    elif [[ -f "$xprotect_legacy" && -f "$xprotect_legacy_plist" ]]; then
        xprotect_location="Legacy Location"
        xprotect_version=$(defaults read "$xprotect_legacy_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        update_time=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_legacy" 2>/dev/null || echo "Unknown")
        local file_timestamp=$(stat -f "%m" "$xprotect_legacy" 2>/dev/null || echo "0")
        
        # If on macOS 15+ but only legacy exists, this is concerning
        if [[ $macos_major -ge 15 ]]; then
            risk_level="MEDIUM"
            recommendation="macOS 15+ detected but XProtect not in new location. Check 'sudo xprotect update'"
        fi
        
    # Check very old location (pre-bundle format)
    elif [[ -f "$xprotect_old" ]]; then
        xprotect_location="Very Old Location"
        xprotect_version=$(defaults read "$xprotect_old" Version 2>/dev/null || echo "Unknown")
        update_time=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_old" 2>/dev/null || echo "Unknown")
        local file_timestamp=$(stat -f "%m" "$xprotect_old" 2>/dev/null || echo "0")
        risk_level="HIGH"
        recommendation="Very old XProtect format detected. System may need updating"
    fi
    
    # Calculate age and assess if we found XProtect
    if [[ "$update_time" != "Unknown" && "$file_timestamp" != "0" ]]; then
        local current_timestamp=$(date +%s)
        local age_days=$(( (current_timestamp - file_timestamp) / 86400 ))
        
        # Adjust risk based on age if we found a working XProtect
        if [[ "$risk_level" != "HIGH" ]]; then
            if [[ $age_days -gt 30 ]]; then
                risk_level="MEDIUM"
                recommendation="XProtect definitions are over 30 days old. Check for update issues"
            elif [[ $age_days -gt 7 ]]; then
                risk_level="LOW"
                recommendation="XProtect definitions are over a week old. Monitor for updates"
            else
                risk_level="INFO"
                recommendation=""
            fi
        fi
        
        add_patch_finding "Security" "XProtect Definitions" "Version $xprotect_version ($xprotect_location)" "Last Update: $update_time ($age_days days ago)" "$risk_level" "$recommendation"
    else
        # XProtect not found - this is a real problem
        if [[ "$xprotect_location" == "Not Found" ]]; then
            risk_level="HIGH"
            recommendation="XProtect malware protection not found. This indicates a serious system issue"
        fi
        add_patch_finding "Security" "XProtect Definitions" "$xprotect_location" "Version: $xprotect_version" "$risk_level" "$recommendation"
    fi
    
    # Check XProtect command tool availability (macOS 15+)
    if command -v xprotect >/dev/null 2>&1; then
        local xprotect_status=$(xprotect status 2>/dev/null || echo "Unable to query")
        add_patch_finding "Security" "XProtect Management Tool" "Available" "Status: $xprotect_status" "INFO" ""
    fi
}

# Helper function to add patch findings to the array
add_patch_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    PATCH_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_patch_findings() {
    printf '%s\n' "${PATCH_FINDINGS[@]}"
}
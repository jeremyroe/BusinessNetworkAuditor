#!/bin/bash

# macOSWorkstationAuditor - Security Settings Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a SECURITY_FINDINGS=()

# Function to add findings to the array (bash 3.2 compatible)
add_security_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"

    # Create JSON finding (bash 3.2 compatible string building)
    local finding="{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}"

    SECURITY_FINDINGS+=("$finding")
}

get_security_settings_data() {
    log_message "INFO" "Analyzing macOS security settings..." "SECURITY"
    
    # Initialize findings array
    SECURITY_FINDINGS=()
    
    # Check XProtect (Apple's built-in malware protection)
    check_xprotect_status
    
    # Check Gatekeeper configuration
    check_gatekeeper_config
    
    # Check System Integrity Protection (SIP)
    check_sip_status
    
    # Check firewall status
    check_firewall_status
    
    # Check FileVault encryption
    check_filevault_status
    
    
    # Check third-party security software
    check_third_party_security

    # Check RMM (Remote Monitoring and Management) tools
    check_rmm_tools

    # Check privacy settings
    check_privacy_settings
    
    # Check screen lock settings
    check_screen_lock
    
    # Check MDM enrollment and management
    check_mdm_enrollment
    
    # Check iCloud status
    check_icloud_status
    
    # Check Find My status
    check_find_my_status
    
    # Check screen sharing settings
    check_screen_sharing_settings
    
    # Check file sharing services
    check_file_sharing_services
    
    # Check AirDrop status
    check_airdrop_status
    
    # Check RMM agents
    check_rmm_agents
    
    # Check backup solutions
    check_backup_solutions
    
    # Check managed login providers
    check_managed_login
    
    # Device information handled by system information module to avoid duplication
    
    log_message "SUCCESS" "Security settings analysis completed - ${#SECURITY_FINDINGS[@]} findings" "SECURITY"
}

check_xprotect_status() {
    log_message "INFO" "Checking XProtect malware protection..." "SECURITY"
    
    local xprotect_status="Unknown"
    local xprotect_version="Unknown"
    local last_update="Unknown"
    local risk_level="INFO"
    local recommendation=""
    local xprotect_location="Not Found"
    
    # Check for macOS version to determine XProtect structure
    local macos_major=$(sw_vers -productVersion | cut -d. -f1)
    
    # Primary location for macOS 15+ (Sequoia)
    local xprotect_new="/var/protected/xprotect/XProtect.bundle/Contents/Resources/XProtect.yara"
    local xprotect_new_plist="/var/protected/xprotect/XProtect.bundle/Contents/Info.plist"
    
    # Legacy location (pre-Sequoia and fallback)
    local xprotect_legacy="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"
    local xprotect_legacy_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    
    # Very old location
    local xprotect_old="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist"
    
    # Check new location first (macOS 15+)
    if [[ -f "$xprotect_new" && -f "$xprotect_new_plist" ]]; then
        xprotect_status="Enabled"
        xprotect_location="Modern (Sequoia+)"
        xprotect_version=$(defaults read "$xprotect_new_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        last_update=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_new" 2>/dev/null || echo "Unknown")
        
    # Check legacy location
    elif [[ -f "$xprotect_legacy" && -f "$xprotect_legacy_plist" ]]; then
        xprotect_status="Enabled"
        xprotect_location="Legacy"
        xprotect_version=$(defaults read "$xprotect_legacy_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        last_update=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_legacy" 2>/dev/null || echo "Unknown")
        
        if [[ $macos_major -ge 15 ]]; then
            risk_level="LOW"
            recommendation="macOS 15+ detected but XProtect using legacy location. Modern location preferred"
        fi
        
    # Check very old location
    elif [[ -f "$xprotect_old" ]]; then
        xprotect_status="Enabled"
        xprotect_location="Very Old"
        xprotect_version=$(defaults read "$xprotect_old" Version 2>/dev/null || echo "Unknown")
        last_update=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_old" 2>/dev/null || echo "Unknown")
        risk_level="MEDIUM"
        recommendation="Very old XProtect format detected. System may need updating"
        
    else
        xprotect_status="Not Found"
        risk_level="HIGH"
        recommendation="XProtect malware protection not found. This is unusual for macOS systems"
    fi
    
    add_security_finding "Security" "XProtect Malware Protection" "$xprotect_status ($xprotect_location)" "Version: $xprotect_version, Last Update: $last_update" "$risk_level" "$recommendation"
}

check_gatekeeper_config() {
    log_message "INFO" "Checking Gatekeeper configuration..." "SECURITY"
    
    local gatekeeper_status="Unknown"
    local risk_level="INFO"
    local recommendation=""
    
    if command -v spctl >/dev/null 2>&1; then
        local gk_output=$(spctl --status 2>/dev/null)
        if echo "$gk_output" | grep -q "assessments enabled"; then
            gatekeeper_status="Enabled"
        elif echo "$gk_output" | grep -q "assessments disabled"; then
            gatekeeper_status="Disabled"
            risk_level="MEDIUM"
            recommendation="Gatekeeper is disabled. Enable it to prevent execution of malicious software"
        else
            gatekeeper_status="Unknown Status"
            risk_level="LOW"
            recommendation="Could not determine Gatekeeper status. Verify security settings"
        fi
    else
        gatekeeper_status="Command Not Available"
        risk_level="LOW"
        recommendation="spctl command not available to check Gatekeeper status"
    fi
    
    # Check for developer mode or reduced security
    local dev_mode_details=""
    if [[ "$gatekeeper_status" == "Enabled" ]]; then
        local gk_assess_output=$(spctl --assess --verbose /Applications/Safari.app 2>&1 || echo "")
        if echo "$gk_assess_output" | grep -q "override"; then
            dev_mode_details="Developer mode or security overrides detected"
            risk_level="LOW"
            recommendation="Review Gatekeeper overrides and developer mode settings for security implications"
        fi
    fi
    
    add_security_finding "Security" "Gatekeeper" "$gatekeeper_status" "Application execution control. $dev_mode_details" "$risk_level" "$recommendation"
}

check_sip_status() {
    log_message "INFO" "Checking System Integrity Protection..." "SECURITY"
    
    local sip_status="Unknown"
    local sip_details=""
    local risk_level="INFO"
    local recommendation=""
    
    if command -v csrutil >/dev/null 2>&1; then
        local sip_output=$(csrutil status 2>/dev/null)
        if echo "$sip_output" | grep -q "enabled"; then
            sip_status="Enabled"
            sip_details="Full kernel-level protection active"
        elif echo "$sip_output" | grep -q "disabled"; then
            sip_status="Disabled"
            sip_details="System protections disabled"
            risk_level="MEDIUM"
            recommendation="SIP is disabled. Enable System Integrity Protection for enhanced security unless specifically required for development"
        else
            sip_status="Partially Disabled"
            sip_details="Some protections may be disabled"
            risk_level="LOW"
            recommendation="Review SIP configuration to ensure appropriate security level"
        fi
    else
        sip_status="Command Not Available"
        risk_level="LOW"
        recommendation="csrutil command not available to check SIP status"
    fi
    
    add_security_finding "Security" "System Integrity Protection" "$sip_status" "$sip_details" "$risk_level" "$recommendation"
}

check_firewall_status() {
    log_message "INFO" "Checking firewall configuration..." "SECURITY"
    
    local firewall_status="Unknown"
    local stealth_mode="Unknown"
    local risk_level="INFO"
    local recommendation=""
    
    # Check application firewall status using multiple methods
    local fw_state=""
    
    # Method 1: Try direct defaults read (most reliable)
    fw_state=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)
    
    # Method 2: If that fails, try user domain (sometimes firewall settings are here)
    if [[ -z "$fw_state" ]]; then
        fw_state=$(defaults read ~/Library/Preferences/com.apple.alf globalstate 2>/dev/null)
    fi
    
    # Method 3: Try socketfilterfw command if available
    if [[ -z "$fw_state" ]] && command -v /usr/libexec/ApplicationFirewall/socketfilterfw >/dev/null 2>&1; then
        local socketfw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
        if echo "$socketfw_status" | grep -q "enabled"; then
            fw_state="1"  # Default to basic enabled state
        elif echo "$socketfw_status" | grep -q "disabled"; then
            fw_state="0"
        fi
    fi
    
    # Ensure we have a clean integer value
    fw_state=$(echo "$fw_state" | tr -d '[:space:]' | grep -o '^[0-9]')
    
    case "$fw_state" in
        0)
            firewall_status="Disabled"
            risk_level="MEDIUM"
            recommendation="Application firewall is disabled. Enable firewall to protect against unauthorized network connections"
            ;;
        1)
            firewall_status="Enabled (Allow signed software)"
            ;;
        2)
            firewall_status="Enabled (Block all incoming)"
            ;;
        *)
            # Default to showing what we actually detected
            if [[ -n "$fw_state" ]]; then
                firewall_status="Unknown State (detected: $fw_state)"
            else
                firewall_status="Cannot Determine"
                risk_level="LOW"
                recommendation="Unable to read firewall status. Check System Settings > Network > Firewall for current state"
            fi
            ;;
    esac
    
    # Check stealth mode with better error handling
    local stealth_state=""
    stealth_state=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)
    
    # Fallback to user domain if system domain fails
    if [[ -z "$stealth_state" ]]; then
        stealth_state=$(defaults read ~/Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)
    fi
    
    # Clean the value
    stealth_state=$(echo "$stealth_state" | tr -d '[:space:]' | grep -o '^[0-9]')
    
    if [[ "$stealth_state" == "1" ]]; then
        stealth_mode="Enabled"
    elif [[ "$stealth_state" == "0" ]]; then
        stealth_mode="Disabled"
    else
        stealth_mode="Unknown"
    fi
    
    local details="Stealth mode: $stealth_mode"
    add_security_finding "Security" "Application Firewall" "$firewall_status" "$details" "$risk_level" "$recommendation"
}

check_filevault_status() {
    log_message "INFO" "Checking FileVault encryption..." "SECURITY"
    
    local fv_status="Unknown"
    local risk_level="INFO"
    local recommendation=""
    local details=""
    
    if command -v fdesetup >/dev/null 2>&1; then
        local fv_output=$(fdesetup status 2>/dev/null)
        if echo "$fv_output" | grep -q "FileVault is On"; then
            fv_status="Enabled"
            details="Full disk encryption active"
        elif echo "$fv_output" | grep -q "FileVault is Off"; then
            fv_status="Disabled"
            risk_level="HIGH"
            recommendation="FileVault disk encryption is disabled. Enable FileVault to protect data if device is lost or stolen"
            details="Disk encryption not active - data at risk"
        else
            fv_status="Unknown State"
            risk_level="LOW"
            recommendation="Could not determine FileVault status. Check encryption settings"
            details="FileVault status unclear"
        fi
    else
        fv_status="Command Not Available"
        risk_level="LOW"
        recommendation="fdesetup command not available to check FileVault status"
    fi
    
    add_security_finding "Security" "FileVault Encryption" "$fv_status" "$details" "$risk_level" "$recommendation"
}


check_third_party_security() {
    log_message "INFO" "Checking for third-party security software..." "SECURITY"
    
    local detected_av=()
    local detected_security=()
    
    # Common antivirus applications
    local av_paths=(
        "/Applications/Bitdefender Virus Scanner.app"
        "/Applications/ClamXav.app"
        "/Applications/Malwarebytes Anti-Malware.app"
        "/Applications/Norton Security.app"
        "/Applications/Sophos Endpoint.app"
        "/Applications/Trend Micro Antivirus.app"
        "/Applications/Intego VirusBarrier.app"
        "/Applications/Avast.app"
        "/Applications/AVG AntiVirus.app"
        "/Applications/ESET Cyber Security.app"
        "/Applications/Kaspersky Internet Security.app"
        "/Applications/McAfee Endpoint Security for Mac.app"
    )
    
    # Common security tools
    local security_paths=(
        "/Applications/1Blocker- Ad Blocker & Privacy.app"
        "/Applications/Little Snitch.app"
        "/Applications/Micro Snitch.app"
        "/Applications/BlockBlock.app"
        "/Applications/LuLu.app"
        "/Applications/Radio Silence.app"
    )
    
    # Check for antivirus software
    for av_path in "${av_paths[@]}"; do
        if [[ -d "$av_path" ]]; then
            local av_name=$(basename "$av_path" .app)
            detected_av+=("$av_name")
        fi
    done
    
    # Check for security tools
    for sec_path in "${security_paths[@]}"; do
        if [[ -d "$sec_path" ]]; then
            local sec_name=$(basename "$sec_path" .app)
            detected_security+=("$sec_name")
        fi
    done
    
    # Report antivirus findings
    if [[ ${#detected_av[@]} -gt 0 ]]; then
        local av_list=$(IFS=", "; echo "${detected_av[*]}")
        add_security_finding "Security" "Third-party Antivirus" "Detected" "Found: $av_list" "INFO" ""
    else
        add_security_finding "Security" "Third-party Antivirus" "None Detected" "Relying on built-in XProtect and system security" "INFO" ""
    fi
    
    # Report security tools
    if [[ ${#detected_security[@]} -gt 0 ]]; then
        local sec_list=$(IFS=", "; echo "${detected_security[*]}")
        add_security_finding "Security" "Security Tools" "Detected" "Found: $sec_list" "INFO" ""
    else
        add_security_finding "Security" "Security Tools" "None Detected" "Basic macOS security features detected" "INFO" "Evaluate enterprise security solutions such as CrowdStrike, SentinelOne, or Jamf Protect for comprehensive threat detection"
    fi
}

check_rmm_tools() {
    log_message "INFO" "Checking for RMM (Remote Monitoring and Management) tools..." "SECURITY"

    local detected_rmm=()
    local risk_level="INFO"
    local recommendation=""

    # Actual RMM applications (not screen sharing)
    local rmm_paths=(
        "/Applications/DattoRMM.app"
        "/Applications/Kaseya.app"
        "/Applications/NinjaRMM.app"
        "/Applications/N-able.app"
        "/Applications/Atera.app"
        "/Applications/Pulseway.app"
        "/Applications/Automate.app"
        "/Applications/Datto.app"
        "/Applications/Syncro.app"
        "/Applications/SimpleHelp.app"
        "/Applications/Level.app"
        "/Applications/Tacticalrmm.app"
        "/Applications/Comodo One.app"
        "/Applications/ManageEngine.app"
        "/Applications/SolarWinds.app"
        "/Applications/Continuum.app"
        "/Applications/LabTech.app"
        "/Applications/ConnectWise Automate.app"
        "/Applications/ConnectWise Manage.app"
    )

    # Check for RMM applications
    for rmm_path in "${rmm_paths[@]}"; do
        if [[ -d "$rmm_path" ]]; then
            local rmm_name=$(basename "$rmm_path" .app)
            detected_rmm+=("$rmm_name")
        fi
    done

    # Check running processes for RMM services (not screen sharing)
    local rmm_processes=$(ps -axo comm | grep -iE "(kaseya|ninj|nable|atera|pulseway|datto|syncro|simplehelp)" | head -3)
    if [[ -n "$rmm_processes" ]]; then
        while IFS= read -r process; do
            if [[ -n "$process" ]]; then
                local process_name=$(basename "$process" | cut -d. -f1)
                # Only add if not already detected
                if [[ ! " ${detected_rmm[*]} " =~ " ${process_name} " ]]; then
                    detected_rmm+=("${process_name} (service)")
                fi
            fi
        done <<< "$rmm_processes"
    fi

    # Report RMM findings
    if [[ ${#detected_rmm[@]} -gt 0 ]]; then
        local rmm_list=$(IFS=", "; echo "${detected_rmm[*]}")
        risk_level="INFO"
        recommendation=""
        add_security_finding "Security" "RMM Tools" "Detected" "Found: $rmm_list" "$risk_level" "$recommendation"
    else
        add_security_finding "Security" "RMM Tools" "None Detected" "No remote monitoring or management platforms found" "INFO" ""
    fi
}

check_privacy_settings() {
    log_message "INFO" "Checking privacy and security settings..." "SECURITY"
    
    # Check location services using accurate method
    local location_enabled="Unknown"
    local location_details="Unable to determine location services status"
    
    # Method 1: Check the actual LocationServicesEnabled setting (most reliable)
    local location_pref=$(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>/dev/null)
    if [[ "$location_pref" == "1" ]]; then
        location_enabled="Enabled"
        location_details="Location services enabled in system preferences"
    elif [[ "$location_pref" == "0" ]]; then
        location_enabled="Disabled"
        location_details="Location services disabled in system preferences"
    # Method 2: Alternative location for newer macOS versions
    elif [[ -f "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist" ]]; then
        # Try to read the plist directly
        local plist_value=$(plutil -extract LocationServicesEnabled raw "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist" 2>/dev/null)
        if [[ "$plist_value" == "true" ]]; then
            location_enabled="Enabled"
            location_details="Location services enabled (plist configuration)"
        elif [[ "$plist_value" == "false" ]]; then
            location_enabled="Disabled"
            location_details="Location services disabled (plist configuration)"
        else
            location_enabled="Available"
            location_details="Location services configuration present but status unclear"
        fi
    # Method 3: Check user preference for current user
    elif [[ -n "$(defaults read com.apple.locationmenu LocationServicesEnabled 2>/dev/null)" ]]; then
        local user_location=$(defaults read com.apple.locationmenu LocationServicesEnabled 2>/dev/null)
        if [[ "$user_location" == "1" ]]; then
            location_enabled="Enabled"
            location_details="Location services enabled (user preferences)"
        else
            location_enabled="Disabled"
            location_details="Location services disabled (user preferences)"
        fi
    # Method 4: Check if daemon is running as a fallback indicator
    elif pgrep -x "locationd" >/dev/null 2>&1; then
        location_enabled="Enabled"
        location_details="Location daemon active (indicates services are enabled)"
    else
        location_enabled="Disabled"
        location_details="No location daemon or configuration detected"
    fi
    
    add_security_finding "Privacy" "Location Services" "$location_enabled" "$location_details" "INFO" ""
    
    # Check analytics/diagnostics with better detection
    local analytics_enabled="Disabled"
    local analytics_details="Diagnostic data sharing is disabled"
    
    # Method 1: Check system-wide analytics setting
    local analytics_pref=$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit 2>/dev/null)
    if [[ -z "$analytics_pref" ]]; then
        # Method 2: Alternative location
        analytics_pref=$(defaults read com.apple.SubmitDiagInfo AutoSubmit 2>/dev/null)
    fi
    if [[ -z "$analytics_pref" ]]; then
        # Method 3: User-specific setting
        analytics_pref=$(defaults read com.apple.CrashReporter DialogType 2>/dev/null)
        if [[ "$analytics_pref" == "none" ]]; then
            analytics_pref="0"
        elif [[ "$analytics_pref" == "crashreport" || "$analytics_pref" == "server" ]]; then
            analytics_pref="1"
        fi
    fi
    
    if [[ "$analytics_pref" == "1" ]]; then
        analytics_enabled="Enabled"
        analytics_details="System diagnostic data is shared with Apple"
    elif [[ "$analytics_pref" == "0" ]]; then
        analytics_enabled="Disabled"
        analytics_details="Diagnostic data sharing is disabled"
    else
        # Check if user chose to not send crash reports (typical default)
        local crash_reporter_type=$(defaults read com.apple.CrashReporter DialogType 2>/dev/null)
        if [[ "$crash_reporter_type" == "none" ]]; then
            analytics_enabled="Disabled"
            analytics_details="Crash reporting disabled (user preference)"
        elif [[ -f "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" ]]; then
            analytics_enabled="Disabled"
            analytics_details="Diagnostic data sharing disabled (system default)"
        else
            analytics_enabled="Not Configured"
            analytics_details="Analytics preferences have not been configured"
        fi
    fi
    
    add_security_finding "Privacy" "Analytics & Diagnostics" "$analytics_enabled" "$analytics_details" "INFO" ""
}

check_screen_lock() {
    log_message "INFO" "Checking screen lock settings..." "SECURITY"
    
    local ask_for_password=""
    local delay_time=""
    local risk_level="INFO"
    local recommendation=""
    local screen_lock_status="Unknown"
    local detection_method=""
    
    # Check multiple possible locations for screen lock settings
    # Method 1: Try global domain first (modern macOS)
    ask_for_password=$(defaults read -g askForPassword 2>/dev/null)
    if [[ -n "$ask_for_password" ]]; then
        detection_method="Global domain"
        delay_time=$(defaults read -g askForPasswordDelay 2>/dev/null)
    fi
    
    # Method 2: Try screensaver domain (legacy and some modern systems)
    if [[ -z "$ask_for_password" ]]; then
        ask_for_password=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
        if [[ -n "$ask_for_password" ]]; then
            detection_method="Screensaver domain"
            delay_time=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
        fi
    fi
    
    # Method 3: Try current user's screensaver preferences
    if [[ -z "$ask_for_password" ]]; then
        ask_for_password=$(defaults read ~/Library/Preferences/com.apple.screensaver askForPassword 2>/dev/null)
        if [[ -n "$ask_for_password" ]]; then
            detection_method="User screensaver preferences"
            delay_time=$(defaults read ~/Library/Preferences/com.apple.screensaver askForPasswordDelay 2>/dev/null)
        fi
    fi
    
    # Method 4: Check if system has screen lock via login window preferences
    if [[ -z "$ask_for_password" ]]; then
        local loginwindow_lock=$(defaults read /Library/Preferences/com.apple.loginwindow DisableScreenLock 2>/dev/null)
        if [[ "$loginwindow_lock" == "0" || -z "$loginwindow_lock" ]]; then
            # Screen lock is not disabled, assume it's enabled
            ask_for_password="1"
            detection_method="System policy"
            delay_time="0"  # Default to immediate
        fi
    fi
    
    # Method 5: Check for Touch ID/biometric unlock as an indicator of screen security
    local biometric_unlock="No"
    local biometric_processes=""
    if pgrep -x "biometrickitd" >/dev/null 2>&1; then
        biometric_unlock="Available"
        biometric_processes="biometrickitd"
    fi
    
    # Check for Apple Watch unlock capability
    if pgrep -x "watchdog" >/dev/null 2>&1 || [[ -f "/System/Library/PrivateFrameworks/WatchConnectivity.framework/WatchConnectivity" ]]; then
        if [[ "$biometric_unlock" == "Available" ]]; then
            biometric_unlock="Touch ID + Apple Watch"
        else
            biometric_unlock="Apple Watch"
        fi
    fi
    
    # Clean up values
    ask_for_password=$(echo "$ask_for_password" | tr -d '[:space:]')
    delay_time=$(echo "$delay_time" | tr -d '[:space:]')
    
    # If delay_time is empty, default to 0 (immediate)
    if [[ -z "$delay_time" ]]; then
        delay_time="0"
    fi
    
    # Determine screen lock status
    if [[ "$ask_for_password" == "1" ]]; then
        if [[ "$delay_time" == "0" ]]; then
            screen_lock_status="Immediate"
            add_security_finding "Security" "Screen Lock" "Immediate" "Password required immediately after sleep/screensaver, Biometric: $biometric_unlock ($detection_method)" "INFO" ""
        else
            local delay_desc="${delay_time} seconds"
            screen_lock_status="Delayed ($delay_desc)"
            if [[ "$delay_time" -gt 300 ]]; then  # More than 5 minutes
                risk_level="MEDIUM"
                recommendation="Screen lock delay is too long. Reduce delay to 5 minutes or less for better security"
            elif [[ "$delay_time" -gt 60 ]]; then  # More than 1 minute
                risk_level="LOW"
                recommendation="Consider reducing screen lock delay for improved security"
            fi
            add_security_finding "Security" "Screen Lock" "Delayed" "Password required after $delay_desc delay, Biometric: $biometric_unlock ($detection_method)" "$risk_level" "$recommendation"
        fi
    elif [[ "$ask_for_password" == "0" ]]; then
        add_security_finding "Security" "Screen Lock" "Disabled" "No password required after sleep/screensaver ($detection_method)" "HIGH" "Enable screen lock password requirement for security"
    else
        # Check if we can determine screen lock from system security features
        if [[ "$biometric_unlock" != "No" ]]; then
            # If biometrics are available, screen lock is likely configured
            screen_lock_status="Likely Enabled"
            add_security_finding "Security" "Screen Lock" "Likely Enabled" "Biometric unlock ($biometric_unlock) is active, indicating screen security is configured" "INFO" ""
        else
            # Unable to determine - could be controlled by MDM or other policy
            add_security_finding "Security" "Screen Lock" "Cannot Determine" "Screen lock configuration cannot be detected - may be controlled by system policy or MDM" "LOW" "Screen lock status unclear due to system restrictions"
        fi
    fi
}

check_mdm_enrollment() {
    log_message "INFO" "Checking MDM enrollment status..." "SECURITY"
    
    # Check MDM enrollment using profiles command
    local enrollment_status="Unknown"
    local enrollment_details=""
    local risk_level="INFO"
    local recommendation=""
    
    if command -v profiles >/dev/null 2>&1; then
        local profiles_output=$(profiles status -type enrollment 2>/dev/null)
        
        if echo "$profiles_output" | grep -q "Enrolled via DEP: Yes"; then
            enrollment_status="DEP Enrolled"
            enrollment_details="Device Enrollment Program (automated enrollment)"
            
            if echo "$profiles_output" | grep -q "User Approved"; then
                enrollment_details="$enrollment_details - User Approved MDM"
                risk_level="INFO"
            else
                enrollment_details="$enrollment_details - Not User Approved"
                risk_level="LOW"
                recommendation="MDM enrollment detected but not user-approved. Some management features may be limited"
            fi
            
        elif echo "$profiles_output" | grep -q "MDM enrollment: Yes (User Approved)"; then
            enrollment_status="User Enrolled"
            enrollment_details="Manual MDM enrollment with user approval"
            risk_level="INFO"
            
        elif echo "$profiles_output" | grep -q "MDM enrollment: Yes"; then
            enrollment_status="Enrolled (Not User Approved)"
            enrollment_details="MDM enrolled but lacking user approval"
            risk_level="MEDIUM"
            recommendation="MDM enrollment detected but not user-approved. Limited management capabilities"
            
        elif echo "$profiles_output" | grep -q "MDM enrollment: No"; then
            enrollment_status="Not Enrolled"
            enrollment_details="Device is not enrolled in Mobile Device Management"
            risk_level="INFO"
            
        else
            enrollment_status="Unknown"
            enrollment_details="Unable to determine MDM enrollment status"
            risk_level="LOW"
            recommendation="Verify MDM enrollment status manually"
        fi
        
        # Check for specific MDM profiles
        local mdm_profiles=$(profiles -P 2>/dev/null | grep -E "MDM|Device Management|Mobile Device Management" | wc -l | tr -d ' ')
        if [[ $mdm_profiles -gt 0 ]]; then
            enrollment_details="$enrollment_details ($mdm_profiles MDM profiles installed)"
        fi
        
    else
        enrollment_status="Unable to Check"
        enrollment_details="profiles command not available"
        risk_level="LOW"
        recommendation="Install macOS command line tools to check MDM status"
    fi
    
    add_security_finding "Management" "MDM Enrollment" "$enrollment_status" "$enrollment_details" "$risk_level" "$recommendation"
    
    # Check device supervision status
    check_device_supervision
    
    # Check for configuration profiles
    check_configuration_profiles
}

check_device_supervision() {
    log_message "INFO" "Checking device supervision status..." "SECURITY"
    
    local supervision_status="Not Supervised"
    local supervision_details=""
    local dep_status="Not Enrolled"
    local risk_level="INFO"
    local recommendation=""
    
    if command -v profiles >/dev/null 2>&1; then
        # Check supervision status (requires elevated privileges)
        local supervision_output=""
        if [[ $EUID -eq 0 ]]; then
            supervision_output=$(profiles -S 2>/dev/null)
            
            if [[ $? -eq 0 && -n "$supervision_output" ]]; then
                if echo "$supervision_output" | grep -q "Device Enrollment Program.*YES"; then
                    dep_status="DEP Enrolled"
                    supervision_status="Supervised (DEP)"
                    supervision_details="Device is supervised via Device Enrollment Program (Apple Business Manager)"
                    risk_level="INFO"
                elif echo "$supervision_output" | grep -q "Supervision.*YES"; then
                    supervision_status="Supervised (Manual)"
                    supervision_details="Device is manually supervised"
                    risk_level="INFO"
                elif echo "$supervision_output" | grep -q "Supervision.*NO"; then
                    supervision_status="Not Supervised"
                    supervision_details="Device is not under supervision"
                    risk_level="INFO"
                fi
                
                # Check DEP enrollment separately
                if echo "$supervision_output" | grep -q "Device Enrollment Program.*NO"; then
                    dep_status="Not DEP Enrolled"
                fi
            else
                supervision_status="Unable to Check"
                supervision_details="Run with sudo for definitive status"
                dep_status="Unable to Check"
            fi
        else
            # Running without administrative privileges - use alternative detection methods
            supervision_details="Run with sudo for definitive status - using indirect detection"
            
            # Check for MDM-related files and processes as indicators
            local mdm_indicators=0
            
            # Check for MDM processes
            if pgrep -f "mdm" >/dev/null 2>&1; then
                ((mdm_indicators++))
            fi
            
            # Check for configuration profiles directory
            if [[ -d "/var/db/ConfigurationProfiles" ]] && [[ $(ls -1 /var/db/ConfigurationProfiles/ 2>/dev/null | wc -l) -gt 2 ]]; then
                ((mdm_indicators++))
            fi
            
            # Check for common MDM apps
            if [[ -d "/Applications/Company Portal.app" ]] || [[ -d "/Applications/Self Service.app" ]] || [[ -d "/Applications/Munki Managed Software Center.app" ]]; then
                ((mdm_indicators++))
            fi
            
            # Check definitive indicators for unmanaged devices
            local profile_count=$(profiles show 2>/dev/null | grep -c "There are no configuration profiles" || echo "0")
            local system_profiler_check=$(system_profiler SPConfigurationProfileDataType 2>/dev/null | wc -l)

            if [[ "$profile_count" -gt 0 || "$system_profiler_check" -eq 0 ]]; then
                # Definitive evidence of no management
                supervision_status="Not Supervised"
                dep_status="Not Enrolled"
                supervision_details="No configuration profiles installed - personal/unmanaged device"
                risk_level="INFO"
                recommendation=""
            elif [[ $mdm_indicators -gt 0 ]]; then
                supervision_status="Possibly Supervised"
                dep_status="Possibly Enrolled"
                supervision_details="Found $mdm_indicators MDM indicators. Run with administrative privileges for definitive status"
                risk_level="LOW"
                recommendation="Run audit with sudo for complete device management analysis"
            else
                supervision_status="Not Supervised"
                dep_status="Not Enrolled"
                supervision_details="No MDM indicators or configuration profiles detected - personal/unmanaged device"
                risk_level="INFO"
                recommendation=""
            fi
        fi
        
        # Add DEP/Apple Business Manager status as separate finding
        local dep_details=""
        if [[ "$dep_status" == "DEP Enrolled" ]]; then
            dep_details="Device enrolled through Apple Business Manager or Apple School Manager"
        elif [[ "$dep_status" == "Not DEP Enrolled" ]]; then
            dep_details="Device not enrolled via Apple Business Manager - manually managed or personal device"
        elif [[ "$dep_status" == "Requires Administrative Privileges" ]]; then
            dep_details="Apple Business Manager enrollment status requires administrative privileges (see startup message)"
        elif [[ "$dep_status" == "Likely Not Enrolled" ]]; then
            dep_details="No MDM indicators detected - appears to be personal/unmanaged device"
        elif [[ "$dep_status" == "Possibly Enrolled" ]]; then
            dep_details="MDM indicators detected - may be enrolled in device management"
        fi
        
        add_security_finding "Management" "Apple Business Manager" "$dep_status" "$dep_details" "INFO" "$recommendation"
        
    else
        supervision_status="Unable to Check"
        supervision_details="profiles command not available"
        risk_level="LOW"
        recommendation="Install macOS command line tools to check supervision status"
    fi
    
    add_security_finding "Management" "Device Supervision" "$supervision_status" "$supervision_details" "$risk_level" "$recommendation"
}

check_configuration_profiles() {
    log_message "INFO" "Checking configuration profiles..." "SECURITY"
    
    if command -v profiles >/dev/null 2>&1; then
        # Count system profiles
        local system_profiles=$(profiles -P 2>/dev/null | grep -c "System" 2>/dev/null)
        if [[ -z "$system_profiles" ]]; then
            system_profiles=0
        fi
        system_profiles=$(echo "$system_profiles" | tr -d '[:space:]')
        if ! [[ "$system_profiles" =~ ^[0-9]+$ ]]; then
            system_profiles=0
        fi
        
        local user_profiles=$(profiles -P 2>/dev/null | grep -c "User" 2>/dev/null)
        if [[ -z "$user_profiles" ]]; then
            user_profiles=0
        fi
        user_profiles=$(echo "$user_profiles" | tr -d '[:space:]')
        if ! [[ "$user_profiles" =~ ^[0-9]+$ ]]; then
            user_profiles=0
        fi
        
        # Check for concerning profile types
        local security_profiles=$(profiles -P 2>/dev/null | grep -iE "certificate|vpn|wifi|security|restriction" | wc -l | tr -d ' ')
        
        local risk_level="INFO"
        local recommendation=""
        
        if [[ $system_profiles -gt 10 ]]; then
            risk_level="LOW"
            recommendation="Large number of system profiles detected. Review for necessity"
        fi
        
        add_security_finding "Management" "Configuration Profiles" "$system_profiles system, $user_profiles user" "Security-related profiles: $security_profiles" "$risk_level" "$recommendation"
        
        # Check for VPN profiles specifically
        local vpn_profiles=$(profiles -P 2>/dev/null | grep -i "vpn" | wc -l | tr -d ' ')
        if ! [[ "$vpn_profiles" =~ ^[0-9]+$ ]]; then
            vpn_profiles=0
        fi
        if [[ $vpn_profiles -gt 0 ]]; then
            add_security_finding "Network" "VPN Profiles" "$vpn_profiles profiles" "VPN configuration profiles installed" "INFO" ""
        fi
    fi
}



check_screen_sharing_settings() {
    log_message "INFO" "Checking remote access settings..." "SECURITY"
    
    # Check if Screen Sharing and SSH are enabled using proper methods from research
    local screen_sharing_enabled="Disabled"
    local vnc_enabled="Disabled" 
    local remote_management_enabled="Disabled"
    local ssh_enabled="Disabled"
    local details=""
    local risk_level="INFO"
    local recommendation=""
    
    # Method 1: Check for VNC listening port using netstat (no sudo required)
    if netstat -atp tcp 2>/dev/null | grep -q rfb; then
        screen_sharing_enabled="Enabled" 
        vnc_enabled="Enabled"
    fi
    
    # Method 2: Check if VNC port 5900 is listening (fallback)
    if netstat -an 2>/dev/null | grep -q ":5900.*LISTEN"; then
        screen_sharing_enabled="Enabled"
        vnc_enabled="Enabled"
    fi
    
    
    # Check Apple Remote Desktop (ARD) - different from screen sharing
    if pgrep -x "ARDAgent" >/dev/null 2>&1; then
        remote_management_enabled="Enabled"
    fi
    
    # Also check for Remote Management via system preferences (if available)
    if [[ -f "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd" ]]; then
        remote_management_enabled="Enabled"
    fi
    
    # Check SSH (Remote Login) status using multiple methods
    # Method 1: Check if SSH port 22 is listening (no admin required)
    if netstat -an 2>/dev/null | grep -q -E "(\*\.22.*LISTEN|:22.*LISTEN|\*\.ssh.*LISTEN)"; then
        ssh_enabled="Enabled"
    fi
    
    # Method 2: Check if SSH process is running
    if pgrep -x "sshd" >/dev/null 2>&1; then
        ssh_enabled="Enabled"
    fi
    
    # Method 3: Try systemsetup (may require admin)
    local ssh_status=$(systemsetup -getremotelogin 2>/dev/null)
    if [[ "$ssh_status" == *"Remote Login: On"* ]]; then
        ssh_enabled="Enabled"
    elif [[ "$ssh_status" == *"Remote Login: Off"* ]]; then
        ssh_enabled="Disabled"
    fi
    
    
    # Determine overall status and risk level for all remote access services
    local enabled_services=()
    local remote_access_enabled="Disabled"
    
    if [[ "$vnc_enabled" == "Enabled" ]]; then
        enabled_services+=("VNC/Screen Sharing")
        remote_access_enabled="Enabled"
    fi
    
    if [[ "$remote_management_enabled" == "Enabled" ]]; then
        enabled_services+=("Remote Management/ARD")
        remote_access_enabled="Enabled"
    fi
    
    if [[ "$ssh_enabled" == "Enabled" ]]; then
        enabled_services+=("SSH/Remote Login")
        remote_access_enabled="Enabled"
    fi
    
    # Set details and risk assessment based on all remote access services
    if [[ "$remote_access_enabled" == "Enabled" ]]; then
        details="Enabled services: $(IFS=", "; echo "${enabled_services[*]}")"
        
        if [[ ${#enabled_services[@]} -gt 2 ]]; then
            risk_level="HIGH"
            recommendation="Multiple remote access methods enabled (${#enabled_services[@]} services). Review necessity and ensure strong authentication"
        elif [[ ${#enabled_services[@]} -gt 1 ]]; then
            risk_level="MEDIUM"
            recommendation="Multiple remote access methods enabled. Ensure proper authentication and network restrictions"
        else
            risk_level="LOW"  
            recommendation="Remote access enabled. Ensure strong passwords and network access controls"
        fi
    else
        details="No remote access services detected (SSH, VNC, ARD all disabled)"
        risk_level="INFO"
        recommendation=""
    fi
    
    add_security_finding "Security" "Remote Access Services" "$remote_access_enabled" "$details" "$risk_level" "$recommendation"
}

check_file_sharing_services() {
    log_message "INFO" "Checking file sharing services..." "SECURITY"
    
    local file_sharing_enabled="Disabled"
    local enabled_services=()
    local details=""
    local risk_level="INFO"
    local recommendation=""
    
    # Check SMB (Samba) file sharing
    if launchctl list | grep -q smbd 2>/dev/null; then
        enabled_services+=("SMB")
        file_sharing_enabled="Enabled"
    fi
    
    # Check AFP (Apple Filing Protocol) - deprecated but still possible
    if launchctl list | grep -q afpd 2>/dev/null; then
        enabled_services+=("AFP")
        file_sharing_enabled="Enabled"
    fi
    
    # Check FTP service
    if launchctl list | grep -q ftpd 2>/dev/null; then
        enabled_services+=("FTP")
        file_sharing_enabled="Enabled"
    fi
    
    # Check NFS (Network File System) - must be actively listening
    if netstat -an 2>/dev/null | grep -q ":2049.*LISTEN"; then
        enabled_services+=("NFS")
        file_sharing_enabled="Enabled"
    fi
    
    # Alternative method: Check using systemsetup (may require admin)
    local sharing_status=$(systemsetup -getremoteappleevents 2>/dev/null)
    if [[ "$sharing_status" == *"Remote Apple Events: On"* ]]; then
        enabled_services+=("Remote Apple Events")
        file_sharing_enabled="Enabled"
    fi
    
    # Check for listening ports commonly used by file sharing
    if netstat -an 2>/dev/null | grep -E ":445.*LISTEN|:139.*LISTEN|:548.*LISTEN|:21.*LISTEN|:2049.*LISTEN" >/dev/null; then
        if [[ "$file_sharing_enabled" == "Disabled" ]]; then
            enabled_services+=("Unknown File Sharing")
            file_sharing_enabled="Enabled"
        fi
    fi
    
    # Set risk level and details
    if [[ "$file_sharing_enabled" == "Enabled" ]]; then
        details="Active services: $(IFS=", "; echo "${enabled_services[*]}")"
        
        if [[ ${#enabled_services[@]} -gt 2 ]]; then
            risk_level="HIGH"
            recommendation="Multiple file sharing services enabled. Review necessity and ensure proper access controls"
        elif [[ " ${enabled_services[*]} " =~ " FTP " ]]; then
            risk_level="HIGH"
            recommendation="FTP file sharing is insecure. Use SFTP or other secure alternatives"
        else
            risk_level="MEDIUM"
            recommendation="File sharing enabled. Ensure proper authentication and network restrictions"
        fi
    else
        details="No active file sharing services detected (SMB, AFP, FTP, NFS all disabled)"
        risk_level="INFO"
        recommendation=""
    fi
    
    add_security_finding "Security" "File Sharing Services" "$file_sharing_enabled" "$details" "$risk_level" "$recommendation"
}

check_airdrop_status() {
    log_message "INFO" "Checking AirDrop status..." "SECURITY"
    
    local airdrop_status="Disabled"
    local details=""
    local risk_level="INFO"
    local recommendation=""
    
    # Check definitive AirDrop status via system preferences
    local discoverable_mode=$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null)
    
    if [[ "$discoverable_mode" == "Off" || -z "$discoverable_mode" ]]; then
        airdrop_status="Disabled"
        details="AirDrop is disabled (DiscoverableMode: Off)"
        risk_level="INFO"
        recommendation=""
    elif [[ "$discoverable_mode" == "Contacts Only" ]]; then
        airdrop_status="Enabled (Contacts Only)"
        details="AirDrop is enabled with contacts-only restriction (DiscoverableMode: $discoverable_mode)"
        risk_level="LOW"
        recommendation="AirDrop is configured securely for contacts only. Consider disabling completely if not needed for business"
    elif [[ "$discoverable_mode" == "Everyone" ]]; then
        airdrop_status="Enabled (Everyone)"
        details="AirDrop is enabled for everyone (DiscoverableMode: $discoverable_mode)"
        risk_level="HIGH"
        recommendation="AirDrop is configured to accept from everyone. Change to 'Contacts Only' or disable in System Settings > General > AirDrop"
    else
        airdrop_status="Enabled"
        details="AirDrop is enabled (DiscoverableMode: $discoverable_mode)"
        risk_level="MEDIUM"
        recommendation="Review AirDrop configuration in System Settings > General > AirDrop"
    fi
    
    add_security_finding "Security" "AirDrop Status" "$airdrop_status" "$details" "$risk_level" "$recommendation"
}

check_rmm_agents() {
    log_message "INFO" "Checking for RMM agents..." "SECURITY"
    
    local rmm_found=()
    local rmm_processes=""
    local rmm_apps=""
    
    # Common RMM agent process names and signatures (matching Windows detection)
    local rmm_patterns=(
        "kaseya"
        "agentmon"
        "n-able"
        "ninja.*rmm"
        "ninja.*one"
        "ninja.*agent"
        "datto.*rmm"
        "centrastage"
        "autotask"
        "atera.*agent"
        "continuum.*agent"
        "labtech"
        "ltservice"
        "connectwise.*automate"
        "solar.*winds.*rmm"
        "n-central"
        "syncro.*agent"
        "repairshopr"
        "pulseway"
        "manageengine"
        "desktop.*central"
        "auvik"
        "prtg"
        "whatsup.*gold"
        "crowdstrike"
        "falcon.*sensor"
        "sentinelone"
        "sentinel.*agent"
        "huntress"
        "bitdefender.*gravity"
        "gravityzone"
        "logmein.*central"
        "gotoassist.*corporate"
        "bomgar"
        "beyondtrust.*remote"
    )
    
    # Check running processes for RMM signatures
    for pattern in "${rmm_patterns[@]}"; do
        if ps -eo comm | grep -qi "$pattern"; then
            local found_processes=$(ps -eo comm | grep -i "$pattern" | sort -u | tr '\n' ',' | sed 's/,$//')
            if [[ -n "$found_processes" ]]; then
                rmm_found+=("$found_processes")
            fi
        fi
    done
    
    # Check installed applications for RMM agent platforms (matching Windows detection)
    local app_paths=(
        "/Applications/Kaseya Agent.app"
        "/Applications/N-able Agent.app"
        "/Applications/Datto RMM.app"
        "/Applications/NinjaRMM.app"
        "/Applications/NinjaOne.app"
        "/Applications/Atera Agent.app"
        "/Applications/ConnectWise Automate.app"
        "/Applications/Syncro.app"
        "/Applications/Pulseway.app"
        "/Applications/ManageEngine Desktop Central.app"
        "/Applications/Auvik.app"
        "/Applications/PRTG.app"
        "/Applications/CrowdStrike Falcon.app"
        "/Applications/SentinelOne.app"
        "/Applications/Huntress.app"
        "/Applications/Bitdefender GravityZone.app"
        "/Applications/LogMeIn Central.app"
        "/Applications/BeyondTrust.app"
        "/Library/Application Support/Kaseya"
        "/Library/Application Support/N-able"
        "/Library/Application Support/Datto"
        "/Library/Application Support/NinjaRMM"
        "/Library/Application Support/NinjaOne"
        "/Library/Application Support/Atera"
        "/Library/Application Support/ConnectWise"
        "/Library/Application Support/Syncro"
        "/Library/Application Support/Pulseway"
        "/Library/Application Support/ManageEngine"
        "/Library/Application Support/CrowdStrike"
        "/Library/Application Support/SentinelOne"
        "/Library/Application Support/Huntress"
        "/Library/Application Support/Bitdefender"
        "/usr/local/bin/kaseya"
        "/usr/local/bin/ninja"
        "/usr/local/bin/crowdstrike"
        "/opt/kaseya"
        "/opt/n-able"
        "/opt/datto"
        "/opt/ninja"
        "/opt/crowdstrike"
        "/opt/sentinelone"
    )
    
    for app_path in "${app_paths[@]}"; do
        if [[ -e "$app_path" ]]; then
            local app_name=$(basename "$app_path" .app)
            rmm_found+=("$app_name")
        fi
    done
    
    # Report findings
    if [[ ${#rmm_found[@]} -gt 0 ]]; then
        local rmm_list=$(printf '%s,' "${rmm_found[@]}" | sed 's/,$//')
        local rmm_count=${#rmm_found[@]}
        
        if [[ $rmm_count -gt 2 ]]; then
            local risk_level="HIGH"
            local recommendation="Multiple RMM agents detected. Review all remote access tools for security and business justification. Remove unauthorized tools immediately."
        else
            local risk_level="MEDIUM"
            local recommendation="RMM agents detected. Verify these tools are authorized and properly secured with strong authentication."
        fi
        
        add_security_finding "Security" "RMM Agents" "$rmm_count agents" "Found: $rmm_list" "$risk_level" "$recommendation"
    else
        add_security_finding "Security" "RMM Agents" "None Detected" "No remote monitoring/management agents found" "INFO" ""
    fi
}

check_backup_solutions() {
    log_message "INFO" "Checking backup solutions..." "SECURITY"
    
    local backup_found=()
    local backup_services=""
    
    # Common backup solution patterns for macOS
    local backup_apps=(
        "/Applications/Time Machine.app"
        "/Applications/Backblaze.app"
        "/Applications/Carbonite.app"
        "/Applications/CrashPlan.app"
        "/Applications/Arq.app"
        "/Applications/ChronoSync.app"
        "/Applications/SuperDuper!.app"
        "/Applications/Carbon Copy Cloner.app"
        "/Applications/Get Backup Pro.app"
        "/Applications/Acronis True Image.app"
        "/Applications/iCloud.app"
        "/System/Library/CoreServices/Applications/Backup and Restore.app"
    )
    
    # Check installed backup applications
    for app_path in "${backup_apps[@]}"; do
        if [[ -e "$app_path" ]]; then
            local app_name=$(basename "$app_path" .app)
            backup_found+=("$app_name")
        fi
    done
    
    # Check for running backup processes
    local backup_processes=(
        "backupd"
        "tmutil"
        "bzagent"
        "carbonite"
        "crashplan"
        "arq"
        "chronosync"
        "ccc"
        "acronis"
    )
    
    for process in "${backup_processes[@]}"; do
        if pgrep -x "$process" >/dev/null 2>&1; then
            backup_found+=("$process (running)")
        fi
    done
    
    # Check Time Machine status specifically
    if command -v tmutil >/dev/null 2>&1; then
        # Check if Time Machine is configured by looking for destination
        local tm_destination=$(tmutil destinationinfo 2>/dev/null)
        
        if [[ -n "$tm_destination" ]]; then
            # Check if Time Machine is currently running a backup
            local tm_running=$(tmutil status 2>/dev/null | grep -E "Running.*[^0]" 2>/dev/null)
            if [[ -n "$tm_running" ]]; then
                backup_found+=("Time Machine (backup in progress)")
            fi
            
            # Get detailed Time Machine backup information
            local latest_backup=$(tmutil latestbackup 2>/dev/null)
            local backup_count=0
            local listbackups_output=$(tmutil listbackups 2>&1)
            
            # Check if we have actual backups (not just an error message)
            if [[ "$listbackups_output" != *"No machine directory found"* ]] && [[ -n "$listbackups_output" ]]; then
                backup_count=$(echo "$listbackups_output" | wc -l | tr -d ' ')
            fi
            
            if [[ $backup_count -gt 0 && -n "$latest_backup" && "$latest_backup" != "No backup found" ]]; then
                # We have completed backups
                backup_found+=("Time Machine (active)")
                
                # Extract date from backup path (format: /Volumes/BackupDisk/Backups.backupdb/MacName/YYYY-MM-DD-HHMMSS)
                local backup_date=$(basename "$latest_backup" | sed 's/-.*//')
                if [[ "$backup_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
                    # Convert date format for better readability
                    local formatted_date=$(date -j -f "%Y-%m-%d" "$backup_date" "+%B %d, %Y" 2>/dev/null || echo "$backup_date")
                    add_security_finding "System" "Time Machine Backups" "$backup_count backups" "Latest: $formatted_date" "INFO" "Regular backups detected - verify backup integrity periodically"
                else
                    add_security_finding "System" "Time Machine Backups" "$backup_count backups" "Latest backup path: $latest_backup" "INFO" "Regular backups detected - verify backup integrity periodically"
                fi
            else
                # Time Machine is configured but no backups completed yet
                add_security_finding "System" "Time Machine Backups" "Configured" "No backups completed yet" "LOW" "Time Machine is configured but no backups have completed. Verify backup destination is accessible"
            fi
        fi
    fi
    
    # Report findings
    if [[ ${#backup_found[@]} -gt 0 ]]; then
        local backup_list=$(printf '%s,' "${backup_found[@]}" | sed 's/,$//')
        local backup_count=${#backup_found[@]}
        
        add_security_finding "System" "Backup Solutions" "$backup_count solutions" "Found: $backup_list" "INFO" "Backup solutions detected - verify they are configured and running properly"
    else
        add_security_finding "System" "Backup Solutions" "None Detected" "No backup solutions found" "MEDIUM" "Consider implementing a backup solution to protect against data loss"
    fi
}

check_managed_login() {
    log_message "INFO" "Checking managed login providers..." "SECURITY"
    
    local managed_login_found=()
    local login_type="Standard"
    
    # Check for Jamf Connect
    if [[ -e "/Applications/Jamf Connect.app" ]] || [[ -e "/usr/local/bin/jamf" ]]; then
        managed_login_found+=("Jamf Connect")
    fi
    
    # Check for NoMAD/Kandji login
    if [[ -e "/Applications/NoMAD.app" ]] || [[ -e "/Library/Application Support/Kandji" ]]; then
        managed_login_found+=("NoMAD/Kandji")
    fi
    
    # Check for Platform SSO (Entra ID integration)
    if defaults read com.apple.extensiond 2>/dev/null | grep -q "com.microsoft.CompanyPortal.ssoextension"; then
        managed_login_found+=("Microsoft Platform SSO")
    fi

    # Report managed login findings
    if [[ ${#managed_login_found[@]} -gt 0 ]]; then
        local managed_list=$(printf '%s,' "${managed_login_found[@]}" | sed 's/,$//')
        login_type="Managed"

        add_security_finding "Authentication" "Login Management" "$login_type" "Managed providers: $managed_list" "INFO" ""
    else
        add_security_finding "Authentication" "Login Management" "$login_type" "No managed login providers detected - using standard macOS authentication" "INFO" ""
    fi
}

check_icloud_status() {
    log_message "INFO" "Checking iCloud status..." "SECURITY"

    # Check if user is signed into iCloud using accurate AccountID detection
    # Handle sudo case - need to read from actual user's preferences, not root's
    local actual_user="${SUDO_USER:-$(whoami)}"
    local user_home=$(eval echo "~$actual_user")
    local icloud_data

    if [[ "$EUID" -eq 0 && -n "$SUDO_USER" ]]; then
        # Running as sudo - read from the actual user's preferences
        icloud_data=$(sudo -u "$SUDO_USER" defaults read MobileMeAccounts Accounts 2>/dev/null)
    else
        # Normal user execution
        icloud_data=$(defaults read MobileMeAccounts Accounts 2>/dev/null)
    fi
    local icloud_account_id=$(echo "$icloud_data" | grep "AccountID" | cut -d'"' -f2)

    # DEBUG OUTPUT

    if [[ -n "$icloud_account_id" ]]; then
        # User is signed into iCloud - extract actual email
        add_security_finding "Security" "iCloud Status" "Signed In" "Account: $icloud_account_id" "INFO" ""

        # Check iCloud backup status - look for actual service data
        local backup_enabled=$(echo "$icloud_data" | grep -A 5 "MOBILE_DOCUMENTS" | grep "Enabled = 1")
        if [[ -n "$backup_enabled" ]]; then
            add_security_finding "Security" "iCloud Backup" "Enabled" "iCloud Drive and backup services active" "INFO" ""
        else
            add_security_finding "Security" "iCloud Backup" "Disabled" "iCloud backup services not active" "INFO" ""
        fi
    else
        # User not signed into iCloud
        add_security_finding "Security" "iCloud Status" "Not Signed In" "No iCloud account configured" "LOW" "Consider signing into iCloud for backup and device synchronization"
        add_security_finding "Security" "iCloud Backup" "Not Available" "Cannot backup without iCloud account" "LOW" "Sign into iCloud and enable backup for data protection"
    fi
}

check_find_my_status() {
    log_message "INFO" "Checking Find My status..." "SECURITY"

    # Check Find My Mac status using accurate service detection
    local actual_user="${SUDO_USER:-$(whoami)}"
    local icloud_data

    if [[ "$EUID" -eq 0 && -n "$SUDO_USER" ]]; then
        icloud_data=$(sudo -u "$SUDO_USER" defaults read MobileMeAccounts Accounts 2>/dev/null)
    else
        icloud_data=$(defaults read MobileMeAccounts Accounts 2>/dev/null)
    fi

    local find_my_service=$(echo "$icloud_data" | grep -A 8 "FIND_MY_MAC")


    if [[ -n "$find_my_service" ]]; then
        # Check if Find My service is properly configured (has authentication and hostnames)
        local find_my_hostname=$(echo "$find_my_service" | grep "hostname")
        local find_my_auth=$(echo "$find_my_service" | grep "authMechanism")


        if [[ -n "$find_my_hostname" && -n "$find_my_auth" ]]; then
            add_security_finding "Security" "Find My" "Enabled" "Find My Mac service is active and configured in iCloud account" "INFO" ""
        else
            add_security_finding "Security" "Find My" "Partially Configured" "Find My Mac service present but incomplete configuration" "LOW" "Complete Find My setup in System Preferences > Apple ID > iCloud"
        fi
    else
        # No iCloud account or Find My service not configured
        local icloud_account_id=$(echo "$icloud_data" | grep "AccountID")
        if [[ -n "$icloud_account_id" ]]; then
            add_security_finding "Security" "Find My" "Not Configured" "iCloud account present but Find My not set up" "LOW" "Enable Find My for device security and theft protection"
        else
            add_security_finding "Security" "Find My" "Not Available" "Requires iCloud account" "LOW" "Sign into iCloud to enable Find My"
        fi
    fi
}

check_screen_sharing_settings() {
    log_message "INFO" "Checking screen sharing settings..." "SECURITY"

    # Check if Screen Sharing is enabled
    local screen_sharing_enabled=false

    # Check system preferences
    local ssh_enabled=$(systemsetup -getremotelogin 2>/dev/null | grep -c "On")
    local vnc_enabled=$(ps aux | grep -c "[S]creenSharingAgent")

    if [[ "$vnc_enabled" -gt 0 ]]; then
        screen_sharing_enabled=true
        add_security_finding "Security" "Screen Sharing" "Enabled" "VNC/Screen Sharing is active" "MEDIUM" "Screen sharing enabled - ensure strong passwords and network access controls"
    else
        add_security_finding "Security" "Screen Sharing" "Disabled" "Screen sharing services not active" "INFO" ""
    fi
}

# Function to get findings for report generation
get_security_findings() {
    printf '%s\n' "${SECURITY_FINDINGS[@]}"
}

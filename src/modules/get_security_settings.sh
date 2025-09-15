#!/bin/bash

# macOSWorkstationAuditor - Security Settings Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a SECURITY_FINDINGS=()

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
    
    # Check device information
    check_device_information
    
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
        add_security_finding "Security" "Security Tools" "None Detected" "Consider additional security tools for enhanced protection" "LOW" "Consider network monitoring tools like Little Snitch for enhanced security"
    fi
}

check_privacy_settings() {
    log_message "INFO" "Checking privacy and security settings..." "SECURITY"
    
    # Check location services using multiple methods
    local location_enabled="Disabled"
    local location_details="Location services are not active"
    
    # Method 1: Check locationd daemon process
    if pgrep -x "locationd" >/dev/null 2>&1; then
        location_enabled="Enabled"
        location_details="Location services daemon is running"
    # Method 2: Check for location database
    elif [[ -f "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist" ]]; then
        location_enabled="Available"
        location_details="Location services configured but daemon status unclear"
    # Method 3: Check system preferences
    elif defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>/dev/null | grep -q "1"; then
        location_enabled="Enabled"
        location_details="Location services enabled in system preferences"
    fi
    
    add_security_finding "Privacy" "Location Services" "$location_enabled" "$location_details" "INFO" ""
    
    # Check analytics/diagnostics with better detection
    local analytics_enabled="Disabled"
    local analytics_details="Diagnostic data sharing is disabled"
    
    # Check multiple possible locations for analytics settings
    local analytics_pref=$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit 2>/dev/null)
    if [[ -z "$analytics_pref" ]]; then
        analytics_pref=$(defaults read com.apple.SubmitDiagInfo AutoSubmit 2>/dev/null)
    fi
    
    if [[ "$analytics_pref" == "1" ]]; then
        analytics_enabled="Enabled"
        analytics_details="System diagnostic data is shared with Apple"
    elif [[ "$analytics_pref" == "0" ]]; then
        analytics_enabled="Disabled"
        analytics_details="Diagnostic data sharing is disabled"
    else
        # Check if the system has never been configured (fresh install)
        if [[ ! -f "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" ]]; then
            analytics_enabled="Not Configured"
            analytics_details="Analytics preferences have not been set"
        else
            analytics_enabled="Disabled"
            analytics_details="Diagnostic data sharing appears to be disabled (default state)"
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
    
    # Check for configuration profiles
    check_configuration_profiles
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

check_icloud_status() {
    log_message "INFO" "Checking iCloud status..." "SECURITY"
    
    local icloud_account="Not Signed In"
    local icloud_services=""
    local risk_level="INFO"
    local recommendation=""
    
    # Check if signed into iCloud
    local icloud_user=$(defaults read MobileMeAccounts Accounts 2>/dev/null | grep -A1 "AccountID" | grep -o '"[^"]*"' | head -1 | tr -d '"' 2>/dev/null || echo "")
    
    if [[ -n "$icloud_user" && "$icloud_user" != "" ]]; then
        icloud_account="$icloud_user"
        
        # Check enabled iCloud services
        local enabled_services=()
        
        # Check common iCloud services
        local icloud_drive=$(defaults read com.apple.bird ubiquity-account-available 2>/dev/null || echo "unknown")
        local icloud_photos=$(defaults read com.apple.Photos.Settings iCloudPhotosEnabled 2>/dev/null || echo "unknown")
        local icloud_keychain=$(security list-keychains | grep -q "iCloud" && echo "enabled" || echo "disabled")
        
        if [[ "$icloud_drive" == "1" ]]; then
            enabled_services+=("iCloud Drive")
        fi
        if [[ "$icloud_photos" == "1" ]]; then
            enabled_services+=("Photos")
        fi
        if [[ "$icloud_keychain" == "enabled" ]]; then
            enabled_services+=("Keychain")
        fi
        
        if [[ ${#enabled_services[@]} -gt 0 ]]; then
            icloud_services=$(IFS=", "; echo "${enabled_services[*]}")
        else
            icloud_services="Basic services only"
        fi
        
        # Check for corporate vs personal account
        if echo "$icloud_user" | grep -qE "@(company|corp|work|business)\."; then
            risk_level="LOW"
            recommendation="Corporate iCloud account detected. Ensure compliance with data policies"
        fi
        
    else
        icloud_account="Not Signed In"
        icloud_services="No iCloud services active"
        recommendation="Consider enabling iCloud for backup and device synchronization"
    fi
    
    add_security_finding "Cloud Services" "iCloud Status" "$icloud_account" "$icloud_services" "$risk_level" "$recommendation"
}

check_find_my_status() {
    log_message "INFO" "Checking Find My status..." "SECURITY"
    
    local find_my_status="Unknown"
    local find_my_details=""
    local risk_level="INFO"
    local recommendation=""
    local detection_method=""
    
    # Method 1: Check modern Find My status (macOS 10.15+)
    local find_my_enabled=$(defaults read com.apple.icloud.fmfd FMFAllowed 2>/dev/null)
    if [[ -n "$find_my_enabled" ]]; then
        detection_method="Modern Find My service"
    else
        # Method 2: Try legacy Find My Mac preference
        find_my_enabled=$(defaults read com.apple.findmymac FMMEnabled 2>/dev/null)
        if [[ -n "$find_my_enabled" ]]; then
            detection_method="Legacy Find My Mac"
        fi
    fi
    
    # Method 3: Try user-level Find My settings
    if [[ -z "$find_my_enabled" ]]; then
        find_my_enabled=$(defaults read ~/Library/Preferences/com.apple.icloud.fmfd FMFAllowed 2>/dev/null)
        if [[ -n "$find_my_enabled" ]]; then
            detection_method="User Find My preferences"
        fi
    fi
    
    # Method 4: Check for Find My processes/services
    if [[ -z "$find_my_enabled" ]]; then
        if pgrep -x "FindMyDevice" >/dev/null 2>&1 || pgrep -x "fmfd" >/dev/null 2>&1; then
            find_my_enabled="1"
            detection_method="Find My process detection"
        fi
    fi
    
    # Method 5: Check for iCloud Sign-in and Find My capability
    if [[ -z "$find_my_enabled" ]]; then
        # Check if iCloud is signed in (prerequisite for Find My)
        local icloud_account=$(defaults read MobileMeAccounts Accounts 2>/dev/null | grep -A1 "AccountID" | grep -o '"[^"]*"' | head -1 | tr -d '"' 2>/dev/null)
        if [[ -n "$icloud_account" && "$icloud_account" != "" ]]; then
            # If iCloud is signed in, check for Find My capability
            if [[ -d "/System/Library/PrivateFrameworks/FindMyDevice.framework" ]] || [[ -f "/usr/libexec/fmfd" ]]; then
                find_my_enabled="inferred"
                detection_method="iCloud signed in with Find My capability"
            fi
        fi
    fi
    
    # Clean the value
    find_my_enabled=$(echo "$find_my_enabled" | tr -d '[:space:]')
    
    # Determine status based on findings
    if [[ "$find_my_enabled" == "1" ]]; then
        find_my_status="Enabled"
        find_my_details="Find My is active for device location and remote management ($detection_method)"
        
        # Check if activation lock is enabled (T2/Apple Silicon indicator)
        local activation_lock_status="Unknown"
        if nvram -p 2>/dev/null | grep -qi "fmm-mobileme-token-hash\|fmm-computer-name"; then
            activation_lock_status="Enabled"
            find_my_details="$find_my_details with Activation Lock"
        else
            # Check for Apple Silicon/T2 security chip presence
            if sysctl -n machdep.cpu.brand_string 2>/dev/null | grep -qi "Apple\|M1\|M2\|M3"; then
                activation_lock_status="Likely Enabled (Apple Silicon)"
            elif system_profiler SPiBridgeDataType 2>/dev/null | grep -q "T2"; then
                activation_lock_status="Likely Enabled (T2 Chip)"  
            else
                activation_lock_status="Not Available (Intel without T2)"
            fi
            find_my_details="$find_my_details, Activation Lock: $activation_lock_status"
        fi
        
    elif [[ "$find_my_enabled" == "0" ]]; then
        find_my_status="Disabled"
        find_my_details="Find My is not enabled ($detection_method)"
        risk_level="MEDIUM"
        recommendation="Enable Find My for device tracking and theft protection"
        
    elif [[ "$find_my_enabled" == "inferred" ]]; then
        find_my_status="Available (iCloud Active)"
        find_my_details="iCloud signed in with Find My capability present - Find My functionality is available ($detection_method)"
        risk_level="INFO"
        recommendation=""
        
    else
        # Check if not signed into iCloud at all
        local icloud_account=$(defaults read MobileMeAccounts Accounts 2>/dev/null | grep -A1 "AccountID" | grep -o '"[^"]*"' | head -1 | tr -d '"' 2>/dev/null)
        if [[ -z "$icloud_account" || "$icloud_account" == "" ]]; then
            find_my_status="Not Available"
            find_my_details="Not signed into iCloud - Find My requires iCloud account"
            risk_level="LOW"
            recommendation="Sign into iCloud and enable Find My for device security"
        else
            find_my_status="Cannot Determine"
            find_my_details="Unable to determine Find My status despite iCloud sign-in"
            risk_level="LOW"
            recommendation="Find My status unclear - may be controlled by system policy or MDM"
        fi
    fi
    
    add_security_finding "Device Security" "Find My" "$find_my_status" "$find_my_details" "$risk_level" "$recommendation"
}

check_device_information() {
    log_message "INFO" "Checking device information..." "SECURITY"
    
    # Get serial number
    local serial_number=$(system_profiler SPHardwareDataType | grep "Serial Number" | awk '{print $4}' 2>/dev/null || echo "Unknown")
    if [[ -z "$serial_number" || "$serial_number" == "" ]]; then
        serial_number=$(ioreg -c IOPlatformExpertDevice -d 2 | awk -F\" '/IOPlatformSerialNumber/{print $(NF-1)}' 2>/dev/null || echo "Unknown")
    fi
    
    # Get hardware UUID
    local hardware_uuid=$(system_profiler SPHardwareDataType | grep "Hardware UUID" | awk '{print $3}' 2>/dev/null || echo "Unknown")
    
    # Get model information
    local model_name=$(sysctl -n hw.model 2>/dev/null || echo "Unknown")
    local model_identifier=$(system_profiler SPHardwareDataType | grep "Model Identifier" | awk '{print $3}' 2>/dev/null || echo "Unknown")
    
    add_security_finding "Device Info" "Serial Number" "$serial_number" "Hardware serial number for device identification" "INFO" ""
    add_security_finding "Device Info" "Hardware UUID" "$hardware_uuid" "Unique hardware identifier" "INFO" ""
    add_security_finding "Device Info" "Model Information" "$model_identifier" "Model: $model_name" "INFO" ""
}

# Helper function to add security findings to the array
add_security_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    SECURITY_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_security_findings() {
    printf '%s\n' "${SECURITY_FINDINGS[@]}"
}
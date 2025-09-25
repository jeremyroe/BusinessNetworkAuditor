#!/bin/bash

# macOSWorkstationAuditor - User Account Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a USER_FINDINGS=()

get_user_account_analysis_data() {
    log_message "INFO" "Analyzing user accounts..." "USERS"
    
    # Initialize findings array
    USER_FINDINGS=()
    
    # Analyze local user accounts
    analyze_local_users
    
    # Check administrator accounts
    check_administrator_accounts
    
    # Check for disabled accounts
    check_disabled_accounts
    
    # Check password policies
    check_password_policies
    
    # Check login items
    check_login_items
    
    # Check user groups
    check_user_groups
    
    log_message "SUCCESS" "User account analysis completed - ${#USER_FINDINGS[@]} findings" "USERS"
}

analyze_local_users() {
    log_message "INFO" "Analyzing local user accounts..." "USERS"
    
    # Get list of all local users (UID >= 500, excluding system accounts)
    local all_users=$(dscl . list /Users UniqueID | awk '$2 >= 500 {print $1}' | grep -v "^_")
    local user_count=$(echo "$all_users" | wc -l | tr -d ' ')
    
    if [[ -z "$all_users" ]]; then
        user_count=0
    fi
    
    # Analyze user accounts and categorize
    local active_users=0
    local admin_users=0
    local standard_users=0
    local admin_user_list=()
    local risky_users=()
    
    while IFS= read -r username; do
        if [[ -n "$username" ]]; then
            # Check if user is active (has a home directory)
            if [[ -d "/Users/$username" ]]; then
                ((active_users++))
            fi
            
            # Check if user is admin and categorize
            if dseditgroup -o checkmember -m "$username" admin 2>/dev/null | grep -q "yes"; then
                ((admin_users++))
                admin_user_list+=("$username")
            else
                ((standard_users++))
            fi
            
            # Only report individual users if there are issues/risks
            local user_issues=$(check_user_for_issues "$username")
            if [[ -n "$user_issues" ]]; then
                analyze_single_user "$username"
                risky_users+=("$username")
            fi
        fi
    done <<< "$all_users"
    
    # Create concise user summary
    local user_summary=""
    local admin_list=$(IFS=", "; echo "${admin_user_list[*]}")
    
    if [[ $user_count -eq 1 && $admin_users -eq 1 ]]; then
        user_summary="Single administrator account ($admin_list)"
    elif [[ $admin_users -gt 0 && $standard_users -gt 0 ]]; then
        user_summary="$admin_users administrator(s), $standard_users standard user(s)"
    elif [[ $admin_users -gt 0 ]]; then
        user_summary="$admin_users administrator account(s) only"
    else
        user_summary="$standard_users standard user(s) only"
    fi
    
    add_user_finding "Users" "User Accounts" "$user_count total" "$user_summary" "INFO" ""
}

# Function to check if a user has issues worth individual reporting
check_user_for_issues() {
    local username="$1"
    local issues=""
    
    # Check for disabled account
    local account_policy=$(pwpolicy -u "$username" -getpolicy 2>/dev/null)
    if echo "$account_policy" | grep -q "isDisabled=1"; then
        issues="disabled"
    fi
    
    # Check for passwordless account
    local password_hash=$(dscl . read "/Users/$username" AuthenticationAuthority 2>/dev/null)
    if [[ -z "$password_hash" ]] || echo "$password_hash" | grep -q "No such key"; then
        issues="${issues:+$issues,}passwordless"
    fi
    
    # Check for unusual shell
    local shell=$(dscl . read "/Users/$username" UserShell 2>/dev/null | awk '{print $2}')
    case "$shell" in
        "/bin/bash"|"/bin/zsh"|"/bin/sh"|"/usr/bin/false"|"/sbin/nologin")
            # Normal shells - no issue
            ;;
        *)
            issues="${issues:+$issues,}unusual_shell"
            ;;
    esac
    
    echo "$issues"
}

analyze_single_user() {
    local username="$1"
    
    # Get user information
    local real_name=$(dscl . read "/Users/$username" RealName 2>/dev/null | grep -v "RealName:" | sed 's/^ *//' | head -1)
    local uid=$(dscl . read "/Users/$username" UniqueID 2>/dev/null | awk '{print $2}')
    local shell=$(dscl . read "/Users/$username" UserShell 2>/dev/null | awk '{print $2}')
    local home_dir=$(dscl . read "/Users/$username" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    
    # Check last login (simplified)
    local last_login="Unknown"
    if [[ -f "/var/log/wtmp" ]]; then
        last_login=$(last -1 "$username" 2>/dev/null | head -1 | awk '{print $3, $4, $5, $6}' || echo "Unknown")
    fi
    
    # Check if account is locked/disabled
    local account_status="Active"
    local account_policy=$(pwpolicy -u "$username" -getpolicy 2>/dev/null)
    if echo "$account_policy" | grep -q "isDisabled=1"; then
        account_status="Disabled"
    fi
    
    # Determine risk level based on various factors
    local risk_level="INFO"
    local recommendation=""
    
    # Check for risky shells
    case "$shell" in
        "/bin/bash"|"/bin/zsh"|"/bin/sh")
            # Normal shells
            ;;
        "/usr/bin/false"|"/sbin/nologin")
            account_status="No Shell Login"
            ;;
        *)
            risk_level="LOW"
            recommendation="Unusual shell detected: $shell"
            ;;
    esac
    
    local details="UID: $uid, Shell: $shell, Last Login: $last_login"
    if [[ -n "$real_name" ]]; then
        details="Real Name: $real_name, $details"
    fi
    
    add_user_finding "Users" "User: $username" "$account_status" "$details" "$risk_level" "$recommendation"
}

check_administrator_accounts() {
    log_message "INFO" "Checking administrator accounts..." "USERS"
    
    # Get list of admin users - try multiple methods for compatibility
    local admin_users=""
    local admin_count=0
    local risky_admins=()
    
    # Method 1: Try dscl (most reliable and consistent)
    if command -v dscl >/dev/null 2>&1; then
        admin_users=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //' | tr ' ' '\n' | grep -v "^$" | grep -v "^root$" | grep -v "^_mbsetupuser$" | grep -v "^_" | sort -u)
    fi
    
    # Method 2: If that fails, try dseditgroup (alternative approach)
    if [[ -z "$admin_users" ]] && command -v dseditgroup >/dev/null 2>&1; then
        admin_users=$(dseditgroup -o read admin 2>/dev/null | grep -A 20 "GroupMembership -" | grep "^[[:space:]]*[a-zA-Z][a-zA-Z0-9_]*$" | sed 's/^[[:space:]]*//' | sort -u)
    fi
    
    # Method 3: If still nothing, try checking who's in wheel group
    if [[ -z "$admin_users" ]]; then
        admin_users=$(dscl . -read /Groups/wheel GroupMembership 2>/dev/null | grep -v "GroupMembership:" | tr ' ' '\n' | grep -v "^$" | sort -u)
    fi
    
    # Count admin users and check for issues
    if [[ -n "$admin_users" ]]; then
        while IFS= read -r admin_user; do
            if [[ -n "$admin_user" ]]; then
                ((admin_count++))
                
                # Check for default/generic admin accounts
                case "$admin_user" in
                    "admin"|"administrator"|"root"|"test"|"guest")
                        risky_admins+=("$admin_user")
                        ;;
                esac
            fi
        done <<< "$admin_users"
    fi
    
    # Only report admin accounts if there are issues or concerns
    local should_report=false
    local risk_level="INFO"
    local recommendation=""
    local admin_details=""
    
    if [[ $admin_count -eq 0 ]]; then
        should_report=true
        risk_level="HIGH"
        recommendation="No administrator accounts found. This may indicate a configuration issue"
        admin_details="No administrator accounts found"
    elif [[ $admin_count -gt 5 ]]; then
        should_report=true
        risk_level="MEDIUM"
        recommendation="Large number of administrator accounts. Review and remove unnecessary admin privileges"
        local admin_list=$(echo "$admin_users" | tr '\n' ', ' | sed 's/, $//')
        admin_details="$admin_count admin accounts: $admin_list"
    elif [[ ${#risky_admins[@]} -gt 0 ]]; then
        should_report=true
        risk_level="HIGH"
        local risky_list=$(IFS=", "; echo "${risky_admins[*]}")
        recommendation="Generic/default admin accounts detected: $risky_list. Rename or disable these accounts"
        admin_details="Risky admin accounts found: $risky_list"
    fi
    
    # Report only if there are issues
    if [[ "$should_report" == true ]]; then
        add_user_finding "Security" "Administrator Account Issues" "$admin_count accounts" "$admin_details" "$risk_level" "$recommendation"
    fi
    
    # Check root account status - it should be disabled by default
    local root_auth=$(dscl . read /Users/root AuthenticationAuthority 2>/dev/null)
    if [[ -n "$root_auth" && ! "$root_auth" =~ ";DisabledUser;" ]]; then
        add_user_finding "Security" "Root Account" "Enabled" "System root account is active" "MEDIUM" "Consider disabling root account if not needed"
    fi
}

check_disabled_accounts() {
    log_message "INFO" "Checking for disabled accounts..." "USERS"
    
    local disabled_count=0
    local disabled_users=()
    local all_users=$(dscl . list /Users UniqueID | awk '$2 >= 500 {print $1}' | grep -v "^_")
    
    while IFS= read -r username; do
        if [[ -n "$username" ]]; then
            local account_policy=$(pwpolicy -u "$username" -getpolicy 2>/dev/null)
            if echo "$account_policy" | grep -q "isDisabled=1"; then
                ((disabled_count++))
                disabled_users+=("$username")
            fi
        fi
    done <<< "$all_users"
    
    # Only report if there are disabled accounts
    if [[ $disabled_count -gt 0 ]]; then
        local disabled_list=$(IFS=", "; echo "${disabled_users[*]}")
        add_user_finding "Security" "Disabled Accounts" "$disabled_count accounts" "Disabled users: $disabled_list" "LOW" "Review disabled accounts and remove if no longer needed"
    fi
}

check_password_policies() {
    log_message "INFO" "Checking password policies..." "USERS"
    
    # Check global password policy
    local global_policy=$(pwpolicy -getglobalpolicy 2>/dev/null)
    
    # Extract key policy settings
    local min_length="Unknown"
    local complexity="Unknown"
    local max_age="Unknown"
    local history="Unknown"
    
    if [[ -n "$global_policy" ]]; then
        min_length=$(echo "$global_policy" | grep "minChars=" | sed 's/.*minChars=//' | sed 's/[^0-9].*//' | head -1 | tr -d '\n\r ' || echo "Unknown")
        [[ -z "$min_length" ]] && min_length="Unknown"
        complexity=$(echo "$global_policy" | grep "requiresAlpha=" | sed 's/.*requiresAlpha=//' | sed 's/[^0-9].*//' | head -1 | tr -d '\n\r ' || echo "Unknown")
        [[ -z "$complexity" ]] && complexity="Unknown"
        max_age=$(echo "$global_policy" | grep "maxMinutesUntilChangePassword=" | sed 's/.*maxMinutesUntilChangePassword=//' | sed 's/[^0-9].*//' | head -1 | tr -d '\n\r ' || echo "Unknown")
        [[ -z "$max_age" ]] && max_age="Unknown"
        history=$(echo "$global_policy" | grep "usingHistory=" | sed 's/.*usingHistory=//' | sed 's/[^0-9].*//' | head -1 | tr -d '\n\r ' || echo "Unknown")
        [[ -z "$history" ]] && history="Unknown"
    fi
    
    # Assess password policy strength
    local policy_strength="Unknown"
    local risk_level="INFO"
    local recommendation=""
    
    # Ensure min_length is clean and numeric
    min_length=$(echo "$min_length" | tr -d '\n\r ' | sed 's/[^0-9]//g')
    if [[ -z "$min_length" ]]; then
        min_length="0"
    fi
    
    if [[ "$min_length" =~ ^[0-9]+$ && "$min_length" -ge 8 ]]; then
        policy_strength="Adequate"
    elif [[ "$min_length" =~ ^[0-9]+$ && "$min_length" -lt 8 && "$min_length" -gt 0 ]]; then
        policy_strength="Weak"
        risk_level="MEDIUM"
        recommendation="Password minimum length is less than 8 characters. Increase to at least 8-12 characters"
    else
        policy_strength="Not Configured"
        risk_level="LOW"
        recommendation="Password policy not configured. Consider implementing password complexity requirements"
    fi
    
    local policy_details="Min Length: $min_length, Complexity: $complexity, Max Age: $max_age days, History: $history"
    add_user_finding "Security" "Password Policy" "$policy_strength" "$policy_details" "$risk_level" "$recommendation"
    
    # Check for accounts without passwords (security risk)
    check_passwordless_accounts
}

check_passwordless_accounts() {
    log_message "INFO" "Checking for passwordless accounts..." "USERS"
    
    local passwordless_count=0
    local passwordless_users=()
    local all_users=$(dscl . list /Users UniqueID | awk '$2 >= 500 {print $1}' | grep -v "^_")
    
    while IFS= read -r username; do
        if [[ -n "$username" ]]; then
            # Check if user has a password hash
            local password_hash=$(dscl . read "/Users/$username" AuthenticationAuthority 2>/dev/null)
            if [[ -z "$password_hash" ]] || echo "$password_hash" | grep -q "No such key"; then
                ((passwordless_count++))
                passwordless_users+=("$username")
            fi
        fi
    done <<< "$all_users"
    
    # Ensure passwordless_count is a valid integer
    if ! [[ "$passwordless_count" =~ ^[0-9]+$ ]]; then
        passwordless_count=0
    fi
    
    # Only report if there are passwordless accounts (HIGH risk)
    if [[ $passwordless_count -gt 0 ]]; then
        local user_list=$(IFS=", "; echo "${passwordless_users[*]}")
        add_user_finding "Security" "Passwordless Accounts" "$passwordless_count accounts" "Passwordless users: $user_list" "HIGH" "Set passwords for all user accounts to prevent unauthorized access"
    fi
}

check_login_items() {
    log_message "INFO" "Checking login items..." "USERS"
    
    # Check system-wide login items
    local system_login_items=0
    if [[ -f "/Library/Preferences/loginwindow.plist" ]]; then
        system_login_items=$(defaults read /Library/Preferences/loginwindow AutoLaunchedApplicationDictionary 2>/dev/null | grep -c "Path =" || echo 0)
    fi
    
    if [[ $system_login_items -gt 0 ]]; then
        add_user_finding "System" "System Login Items" "$system_login_items items" "Applications launched at system startup" "LOW" "Review system login items for security and performance"
    fi
    
    # Check current user's login items
    local user_login_items=0
    if [[ -f "$HOME/Library/Preferences/loginwindow.plist" ]]; then
        user_login_items=$(defaults read "$HOME/Library/Preferences/loginwindow" AutoLaunchedApplicationDictionary 2>/dev/null | grep -c "Path =" 2>/dev/null)
        if [[ -z "$user_login_items" ]]; then
            user_login_items=0
        fi
        user_login_items=$(echo "$user_login_items" | tr -d '[:space:]')
        # Ensure it's a valid number
        if ! [[ "$user_login_items" =~ ^[0-9]+$ ]]; then
            user_login_items=0
        fi
    fi
    
    if [[ $user_login_items -gt 0 ]]; then
        add_user_finding "Users" "User Login Items" "$user_login_items items" "Applications launched at user login" "INFO" ""
    fi
    
    # Check LaunchAgents and LaunchDaemons with better categorization
    local system_launch_agents=$(find /System/Library/LaunchAgents -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
    local user_launch_agents=$(find /Library/LaunchAgents ~/Library/LaunchAgents -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
    local total_launch_agents=$((system_launch_agents + user_launch_agents))
    
    local system_launch_daemons=$(find /System/Library/LaunchDaemons -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
    local user_launch_daemons=$(find /Library/LaunchDaemons -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
    local total_launch_daemons=$((system_launch_daemons + user_launch_daemons))
    
    # Get count of actually loaded launch items
    local loaded_items=$(launchctl list 2>/dev/null | wc -l | tr -d ' ')
    # Subtract header line
    if [[ $loaded_items -gt 0 ]]; then
        loaded_items=$((loaded_items - 1))
    fi
    
    # Report with better context
    local agents_details="Total: $total_launch_agents (System: $system_launch_agents, User: $user_launch_agents)"
    local daemons_details="Total: $total_launch_daemons (System: $system_launch_daemons, User: $user_launch_daemons)"
    local loaded_details="Active background processes currently loaded"
    
    # Risk assessment for user-installed items
    local agents_risk="INFO"
    local agents_recommendation=""
    if [[ $user_launch_agents -gt 10 ]]; then
        agents_risk="LOW"
        agents_recommendation="Review user-installed launch agents for unnecessary or suspicious items"
    fi
    
    local daemons_risk="INFO"
    local daemons_recommendation=""
    if [[ $user_launch_daemons -gt 5 ]]; then
        daemons_risk="LOW"
        daemons_recommendation="Review user-installed launch daemons for unnecessary or suspicious items"
    fi
    
    add_user_finding "System" "Launch Agents" "$total_launch_agents items" "$agents_details" "$agents_risk" "$agents_recommendation"
    add_user_finding "System" "Launch Daemons" "$total_launch_daemons items" "$daemons_details" "$daemons_risk" "$daemons_recommendation"
    add_user_finding "System" "Active Launch Items" "$loaded_items loaded" "$loaded_details" "INFO" ""
}

check_user_groups() {
    log_message "INFO" "Checking user group memberships..." "USERS"
    
    # Check for users in sensitive groups
    local sensitive_groups=("admin" "wheel" "_developer" "com.apple.access_ssh")
    
    for group in "${sensitive_groups[@]}"; do
        local group_member_list=$(dseditgroup -o read "$group" 2>/dev/null | grep -E "users:|GroupMembership:" | sed 's/.*: //' | tr ' ' '\n' | grep -v "^$")
        local group_members=$(echo "$group_member_list" | wc -l | tr -d ' ')
        
        # Handle empty group case
        if [[ -z "$group_member_list" ]]; then
            group_members=0
        fi
        
        if [[ $group_members -gt 0 ]]; then
            local risk_level="INFO"
            local recommendation=""
            
            case "$group" in
                "admin"|"wheel")
                    if [[ $group_members -gt 3 ]]; then
                        risk_level="LOW"
                        recommendation="Large number of users in $group group. Review membership"
                    fi
                    ;;
                "_developer")
                    risk_level="LOW"
                    recommendation="Developer group membership detected. Ensure users require development access"
                    ;;
                "com.apple.access_ssh")
                    risk_level="MEDIUM"
                    recommendation="SSH access group detected. Review SSH access requirements"
                    ;;
            esac
            
            # Create member list for details
            local member_names=$(echo "$group_member_list" | tr '\n' ', ' | sed 's/, $//')
            local group_details="Members: $member_names"
            
            add_user_finding "Security" "Group: $group" "$group_members members" "$group_details" "$risk_level" "$recommendation"
        fi
    done
}

# Helper function to add user findings to the array
add_user_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    USER_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_user_findings() {
    printf '%s\n' "${USER_FINDINGS[@]}"
}
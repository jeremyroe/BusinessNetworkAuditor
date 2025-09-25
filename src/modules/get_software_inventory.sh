#!/bin/bash

# macOSWorkstationAuditor - Software Inventory Module
# Version 1.0.0

# Global variables for collecting data
declare -a SOFTWARE_FINDINGS=()

get_software_inventory_data() {
    log_message "INFO" "Collecting macOS software inventory..." "SOFTWARE"
    
    # Initialize findings array
    SOFTWARE_FINDINGS=()
    
    # Collect applications from /Applications
    collect_applications_inventory
    
    # Check for critical software versions
    check_critical_software
    
    # Check for development tools
    check_development_tools
    
    # Check for remote access software
    check_remote_access_software
    
    # Check for browser plugins and extensions
    check_browser_security
    
    # Check for package managers
    check_package_managers
    
    log_message "SUCCESS" "Software inventory completed - ${#SOFTWARE_FINDINGS[@]} findings" "SOFTWARE"
}

collect_applications_inventory() {
    log_message "INFO" "Scanning /Applications directory..." "SOFTWARE"
    
    local app_count=0
    local system_app_count=0
    local user_app_count=0
    
    # Count applications in /Applications
    if [[ -d "/Applications" ]]; then
        app_count=$(find /Applications -maxdepth 1 -name "*.app" -type d | wc -l | tr -d ' ')
    fi
    
    # Count system applications in /System/Applications (macOS Catalina+)
    if [[ -d "/System/Applications" ]]; then
        system_app_count=$(find /System/Applications -maxdepth 1 -name "*.app" -type d | wc -l | tr -d ' ')
    fi
    
    # Count user applications in ~/Applications
    if [[ -d "$HOME/Applications" ]]; then
        user_app_count=$(find "$HOME/Applications" -maxdepth 1 -name "*.app" -type d | wc -l | tr -d ' ')
    fi
    
    local total_apps=$((app_count + system_app_count + user_app_count))
    
    add_software_finding "Software" "Total Installed Applications" "$total_apps" "Applications: $app_count, System: $system_app_count, User: $user_app_count" "INFO" ""
    
    # Check for suspicious application counts
    if [[ $app_count -gt 200 ]]; then
        add_software_finding "Software" "Application Count" "High" "Large number of applications may indicate software sprawl" "LOW" "Review installed applications and remove unused software"
    fi
}

check_critical_software() {
    log_message "INFO" "Checking critical software versions..." "SOFTWARE"
    
    # Check critical applications (bash 3.2 compatible) - prioritize by security importance
    
    # Browsers (security critical)
    check_single_application "Google Chrome" "/Applications/Google Chrome.app"
    check_single_application "Mozilla Firefox" "/Applications/Firefox.app" 
    check_single_application "Microsoft Edge" "/Applications/Microsoft Edge.app"
    # Safari is reported separately as default macOS browser
    
    # Communication & Remote Access (business critical)
    check_single_application "Zoom" "/Applications/zoom.us.app"
    check_single_application "Slack" "/Applications/Slack.app"
    check_single_application "Microsoft Teams" "/Applications/Microsoft Teams.app"
    check_single_application "Discord" "/Applications/Discord.app"
    check_single_application "TeamViewer" "/Applications/TeamViewer.app"
    
    # Cloud Storage & Sync (data security)
    check_single_application "Dropbox" "/Applications/Dropbox.app"
    check_single_application "Google Drive" "/Applications/Google Drive.app"
    check_single_application "OneDrive" "/Applications/OneDrive.app"
    check_single_application "iCloud Drive" "/System/Applications/iCloud Drive.app"
    
    # Development Tools (if present)
    check_single_application "Docker Desktop" "/Applications/Docker.app"
    check_single_application "Visual Studio Code" "/Applications/Visual Studio Code.app"
    check_single_application "JetBrains Toolbox" "/Applications/JetBrains Toolbox.app"
    
    # Security & VPN
    check_single_application "1Password" "/Applications/1Password 7 - Password Manager.app"
    check_single_application "Malwarebytes" "/Applications/Malwarebytes for Mac.app"
    check_single_application "Little Snitch" "/Applications/Little Snitch.app"
    
    # Special handling for Office suite and Adobe (high priority due to update frequency)
    check_microsoft_office
    check_adobe_acrobat
}

check_single_application() {
    local app_name="$1"
    local app_path="$2"
    
    if [[ -d "$app_path" ]]; then
        local version="Unknown"
        local install_date="Unknown"
        local risk_level="INFO"
        local recommendation=""
        
        # Try to get version from Info.plist
        local info_plist="$app_path/Contents/Info.plist"
        if [[ -f "$info_plist" ]]; then
            version=$(defaults read "$info_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
            
            # Get installation/modification date
            local mod_time=$(stat -f "%Sm" -t "%Y-%m-%d" "$app_path" 2>/dev/null || echo "Unknown")
            install_date="$mod_time"
            
            # Check age of application (based on modification time)
            if [[ "$mod_time" != "Unknown" ]]; then
                local mod_timestamp=$(date -j -f "%Y-%m-%d" "$mod_time" "+%s" 2>/dev/null || echo "0")
                local current_timestamp=$(date +%s)
                local age_days=$(( (current_timestamp - mod_timestamp) / 86400 ))
                
                if [[ $age_days -gt 365 ]]; then
                    risk_level="MEDIUM"
                    recommendation="Application is over 1 year old. Check for updates"
                elif [[ $age_days -gt 180 ]]; then
                    risk_level="LOW"
                    recommendation="Consider checking for application updates"
                fi
            fi
        fi
        
        add_software_finding "Software" "$app_name" "$version" "Install Date: $install_date" "$risk_level" "$recommendation"
    fi
}

check_microsoft_office() {
    # Check for various Office applications
    local office_apps=(
        "Microsoft Word.app"
        "Microsoft Excel.app"
        "Microsoft PowerPoint.app"
        "Microsoft Outlook.app"
        "Microsoft OneNote.app"
    )
    
    local found_office=false
    local office_version="Unknown"
    
    for office_app in "${office_apps[@]}"; do
        local app_path="/Applications/$office_app"
        if [[ -d "$app_path" ]]; then
            found_office=true
            office_version=$(defaults read "$app_path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
            break
        fi
    done
    
    if [[ "$found_office" == true ]]; then
        add_software_finding "Software" "Microsoft Office" "$office_version" "Office suite detected" "INFO" ""
    fi
}

check_adobe_acrobat() {
    # Check for various Adobe Acrobat versions
    local adobe_paths=(
        "/Applications/Adobe Acrobat DC/Adobe Acrobat.app"
        "/Applications/Adobe Acrobat Reader DC.app"
        "/Applications/Adobe Reader.app"
    )
    
    for adobe_path in "${adobe_paths[@]}"; do
        if [[ -d "$adobe_path" ]]; then
            local version=$(defaults read "$adobe_path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
            local app_name=$(basename "$adobe_path" .app)
            add_software_finding "Software" "Adobe Acrobat/Reader" "$version" "Found: $app_name" "INFO" ""
            return
        fi
    done
}

check_development_tools() {
    log_message "INFO" "Checking for development tools..." "SOFTWARE"
    
    # Check for Xcode
    if [[ -d "/Applications/Xcode.app" ]]; then
        local xcode_version=$(defaults read "/Applications/Xcode.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        add_software_finding "Software" "Xcode" "$xcode_version" "Apple development environment" "INFO" ""
    fi
    
    # Check for command line tools
    if xcode-select -p >/dev/null 2>&1; then
        local cli_path=$(xcode-select -p 2>/dev/null || echo "Unknown")
        add_software_finding "Software" "Command Line Tools" "Installed" "Path: $cli_path" "INFO" ""
    fi
    
    # Check for common development tools
    local dev_apps=(
        "Visual Studio Code.app"
        "Sublime Text.app"
        "Atom.app"
        "IntelliJ IDEA.app"
        "PyCharm.app"
        "Docker.app"
        "Terminal.app"
        "iTerm.app"
    )
    
    local dev_count=0
    local found_dev_apps=()
    
    for dev_app in "${dev_apps[@]}"; do
        if [[ -d "/Applications/$dev_app" ]]; then
            ((dev_count++))
            local app_name=$(basename "$dev_app" .app)
            found_dev_apps+=("$app_name")
        fi
    done
    
    if [[ $dev_count -gt 0 ]]; then
        local dev_list=$(IFS=", "; echo "${found_dev_apps[*]}")
        add_software_finding "Software" "Development Tools" "$dev_count applications" "Found: $dev_list" "INFO" ""
    fi
}

check_remote_access_software() {
    log_message "INFO" "Checking for remote access software..." "SOFTWARE"
    
    # Common remote access applications
    local remote_apps=(
        "TeamViewer.app"
        "AnyDesk.app"
        "Chrome Remote Desktop Host.app"
        "LogMeIn.app"
        "GoToMyPC.app"
        "Remote Desktop Connection.app"
        "VNC Viewer.app"
        "Screens.app"
        "Jump Desktop.app"
        "ScreenConnect Client.app"
        "ConnectWise Control.app"
        "Splashtop Business.app"
        "Splashtop Streamer.app"
        "Apple Remote Desktop.app"
        "RealVNC.app"
        "TightVNC.app"
        "UltraVNC.app"
        "Parallels Access.app"
        "Remotix.app"
        "Microsoft Remote Desktop.app"
    )
    
    local found_remote=()
    
    # Check standard Applications folder
    for remote_app in "${remote_apps[@]}"; do
        if [[ -d "/Applications/$remote_app" ]]; then
            local app_name=$(basename "$remote_app" .app)
            found_remote+=("$app_name")
        fi
    done
    
    # Check for remote access software by bundle identifier (more reliable)
    local bundle_id_patterns=(
        "com.screenconnect.client:ScreenConnect"
        "com.connectwise.control:ConnectWise Control"  
        "com.teamviewer.TeamViewer:TeamViewer"
        "com.anydesk.AnyDesk:AnyDesk"
        "com.google.chromeremotedesktop:Chrome Remote Desktop"
        "com.logmein.LogMeIn:LogMeIn"
        "com.gotomypc.GoToMyPC:GoToMyPC"
        "com.realvnc.VNCViewer:RealVNC"
        "com.osxvnc.VNCViewer:VNC Viewer"
        "com.parallels.ParallelsAccess:Parallels Access"
        "com.apple.RemoteDesktop:Apple Remote Desktop"
        "com.edovia.SplashDesktop:Splashtop Desktop"
        "com.splashtop.business:Splashtop Business"
        "com.splashtop.streamer:Splashtop Streamer"
    )
    
    # Check all apps for remote access bundle identifiers
    for app_path in /Applications/*.app /Applications/*/*.app; do
        if [[ -d "$app_path" && -f "$app_path/Contents/Info.plist" ]]; then
            local bundle_id=$(defaults read "$app_path/Contents/Info.plist" CFBundleIdentifier 2>/dev/null)
            if [[ -n "$bundle_id" ]]; then
                for pattern in "${bundle_id_patterns[@]}"; do
                    local id_pattern="${pattern%:*}"
                    local display_name="${pattern#*:}"
                    if [[ "$bundle_id" == "$id_pattern" ]]; then
                        found_remote+=("$display_name")
                        break
                    fi
                done
            fi
        fi
    done
    
    # Also check for ScreenConnect/ConnectWise in alternate locations and patterns  
    local screenconnect_patterns=(
        "/Applications/ScreenConnect Client*.app"
        "/Applications/*ScreenConnect*.app"
        "/Applications/ConnectWise*.app"
        "/Applications/*ConnectWise*.app"
        "/opt/screenconnect"
        "/usr/local/bin/screenconnect"
    )
    
    for pattern in "${screenconnect_patterns[@]}"; do
        if ls $pattern >/dev/null 2>&1; then
            # Extract a clean name for ScreenConnect variations
            if [[ "$pattern" == *"ScreenConnect"* ]]; then
                found_remote+=("ScreenConnect")
            elif [[ "$pattern" == *"ConnectWise"* ]]; then
                found_remote+=("ConnectWise Control")
            fi
            break  # Only add once even if multiple matches
        fi
    done
    
    # Remove duplicates
    local unique_remote=()
    for app in "${found_remote[@]}"; do
        if [[ ! " ${unique_remote[*]} " =~ " ${app} " ]]; then
            unique_remote+=("$app")
        fi
    done
    found_remote=("${unique_remote[@]}")
    
    if [[ ${#found_remote[@]} -gt 0 ]]; then
        local remote_list=$(IFS=", "; echo "${found_remote[*]}")
        local risk_level="MEDIUM"
        local recommendation="Review remote access software for security and business justification"
        
        add_software_finding "Security" "Remote Access Software" "${#found_remote[@]} applications" "Found: $remote_list" "$risk_level" "$recommendation"
    else
        add_software_finding "Security" "Remote Access Software" "None Detected" "No remote access applications found" "INFO" ""
    fi
}

check_browser_security() {
    log_message "INFO" "Checking browser security..." "SOFTWARE"
    
    # Check Safari version
    if [[ -d "/Applications/Safari.app" ]]; then
        local safari_version=$(defaults read "/Applications/Safari.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        add_software_finding "Software" "Safari Browser" "$safari_version" "Default macOS browser" "INFO" ""
    fi
    
    # Check for browser security extensions/plugins (simplified check)
    local safari_extensions_dir="$HOME/Library/Safari/Extensions"
    if [[ -d "$safari_extensions_dir" ]]; then
        local ext_count=$(find "$safari_extensions_dir" -name "*.safariextz" 2>/dev/null | wc -l | tr -d ' ')
        if [[ $ext_count -gt 0 ]]; then
            add_software_finding "Software" "Safari Extensions" "$ext_count extensions" "Browser extensions installed" "LOW" "Review browser extensions for security and necessity"
        fi
    fi
    
    # Check for Flash Player (security risk if present)
    local flash_paths=(
        "/Library/Internet Plug-Ins/Flash Player.plugin"
        "/System/Library/Frameworks/Adobe AIR.framework"
    )
    
    local flash_found=false
    for flash_path in "${flash_paths[@]}"; do
        if [[ -e "$flash_path" ]]; then
            flash_found=true
            break
        fi
    done
    
    if [[ "$flash_found" == true ]]; then
        add_software_finding "Security" "Adobe Flash Player" "Detected" "Legacy Flash Player installation found" "HIGH" "Remove Adobe Flash Player as it's no longer supported and poses security risks"
    fi
}

check_package_managers() {
    log_message "INFO" "Checking for package managers..." "SOFTWARE"
    
    # Check for Homebrew
    if command -v brew >/dev/null 2>&1; then
        local brew_version=$(brew --version 2>/dev/null | head -1 | awk '{print $2}' || echo "Unknown")
        local brew_packages=$(brew list 2>/dev/null | wc -l | tr -d ' ')
        add_software_finding "Software" "Homebrew" "$brew_version" "$brew_packages packages installed" "INFO" ""
    fi
    
    # Check for MacPorts
    if command -v port >/dev/null 2>&1; then
        local port_version=$(port version 2>/dev/null | awk '{print $2}' || echo "Unknown")
        add_software_finding "Software" "MacPorts" "$port_version" "Package manager detected" "INFO" ""
    fi
    
    # Check for pip (Python package manager)
    if command -v pip >/dev/null 2>&1; then
        local pip_version=$(pip --version 2>/dev/null | awk '{print $2}' || echo "Unknown")
        add_software_finding "Software" "Python pip" "$pip_version" "Python package manager" "INFO" ""
    fi
    
    # Check for npm (Node.js package manager)
    if command -v npm >/dev/null 2>&1; then
        local npm_version=$(npm --version 2>/dev/null || echo "Unknown")
        add_software_finding "Software" "Node.js npm" "$npm_version" "Node.js package manager" "INFO" ""
    fi
}

# Helper function to add software findings to the array
add_software_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    SOFTWARE_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_software_findings() {
    printf '%s\n' "${SOFTWARE_FINDINGS[@]}"
}
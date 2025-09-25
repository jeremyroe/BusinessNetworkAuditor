#!/bin/bash

# macOSWorkstationAuditor - System Information Module
# Version 1.0.0

# Global variables for collecting data
declare -a SYSTEM_FINDINGS=()

get_system_information_data() {
    log_message "INFO" "Collecting macOS system information..." "SYSTEM"
    
    # Initialize findings array
    SYSTEM_FINDINGS=()
    
    # Get basic system information
    local os_version=$(sw_vers -productVersion)
    local os_build=$(sw_vers -buildVersion)
    local os_name=$(sw_vers -productName)
    local hardware_model=$(sysctl -n hw.model)
    local cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown CPU")
    local memory_gb=$(echo "scale=2; $(sysctl -n hw.memsize) / 1073741824" | bc)
    local cpu_cores=$(sysctl -n hw.ncpu)
    
    # Get serial number
    local serial_number=$(system_profiler SPHardwareDataType | grep "Serial Number" | awk '{print $4}' 2>/dev/null || echo "Unknown")
    if [[ -z "$serial_number" || "$serial_number" == "" ]]; then
        serial_number=$(ioreg -c IOPlatformExpertDevice -d 2 | awk -F\" '/IOPlatformSerialNumber/{print $(NF-1)}' 2>/dev/null || echo "Unknown")
    fi
    
    # Get computer name and hostname
    local computer_name=$(scutil --get ComputerName 2>/dev/null || hostname -s)
    local hostname=$(hostname)
    
    # Get system uptime
    local uptime_seconds=$(sysctl -n kern.boottime | awk '{print $4}' | tr -d ',')
    local current_time=$(date +%s)
    local uptime_days=$(( (current_time - uptime_seconds) / 86400 ))
    
    # Get system architecture
    local arch=$(uname -m)
    
    
    
    # Operating System Information (basic info only - patch module handles version analysis)
    local os_details="Build: $os_build, Architecture: $arch"
    add_finding "System" "Operating System" "$os_name $os_version" "$os_details" "INFO" ""
    
    # Hardware Information
    add_finding "System" "Hardware" "$hardware_model" "CPU: $cpu_brand, Cores: $cpu_cores, RAM: ${memory_gb}GB, Serial: $serial_number" "INFO" ""
    
    # Computer Identity
    add_finding "System" "Computer Name" "$computer_name" "Hostname: $hostname" "INFO" ""
    
    # System Uptime
    local uptime_risk="INFO"
    local uptime_recommendation=""
    if [[ $uptime_days -gt 30 ]]; then
        uptime_risk="LOW"
        uptime_recommendation="Consider restarting to apply pending updates and clear system resources"
    fi
    add_finding "System" "System Uptime" "$uptime_days days" "Last reboot: $(date -r $uptime_seconds)" "$uptime_risk" "$uptime_recommendation"
    
    # Check printer configuration
    check_printer_inventory
    
    # Check for open risky ports
    check_open_ports
    
    log_message "SUCCESS" "System information collection completed - ${#SYSTEM_FINDINGS[@]} findings" "SYSTEM"
}

check_printer_inventory() {
    log_message "INFO" "Checking printer configuration..." "SYSTEM"
    
    # Get installed printers using lpstat
    local printer_count=0
    local printer_names=""
    local risk_level="INFO"
    local recommendation=""
    
    if command -v lpstat >/dev/null 2>&1; then
        # Get list of configured printers
        local printers=$(lpstat -p 2>/dev/null | grep "printer" | awk '{print $2}')
        if [[ -n "$printers" ]]; then
            printer_count=$(echo "$printers" | wc -l | tr -d ' ')
            printer_names=$(echo "$printers" | tr '\n' ', ' | sed 's/, $//')
        fi
        
        # Check for network printers (potential security concern)
        local network_printers=0
        if [[ -n "$printers" ]]; then
            while IFS= read -r printer; do
                if [[ -n "$printer" ]]; then
                    local printer_uri=$(lpstat -v "$printer" 2>/dev/null | awk '{print $4}')
                    if echo "$printer_uri" | grep -qE "^(ipp|ipps|http|https|socket|lpd)://"; then
                        ((network_printers++))
                    fi
                fi
            done <<< "$printers"
        fi
        
        # Assess security risk
        if [[ $network_printers -gt 0 ]]; then
            risk_level="LOW"
            recommendation="$network_printers network printers detected. Ensure they are on trusted networks and use secure protocols"
        fi
        
        # Check for default printer
        local default_printer=$(lpstat -d 2>/dev/null | awk '{print $4}')
        local printer_details="$printer_count total"
        if [[ -n "$default_printer" ]]; then
            printer_details="$printer_details, default: $default_printer"
        fi
        if [[ $network_printers -gt 0 ]]; then
            printer_details="$printer_details, $network_printers network"
        fi
        
        add_finding "Hardware" "Printers" "$printer_count printers" "$printer_details" "$risk_level" "$recommendation"
        
        # List individual printers if any exist
        if [[ $printer_count -gt 0 && $printer_count -le 5 ]]; then
            add_finding "Hardware" "Printer List" "$printer_names" "Configured printer names" "INFO" ""
        fi
        
    else
        add_finding "Hardware" "Printers" "Unable to check" "lpstat command not available" "LOW" ""
    fi
}

check_open_ports() {
    log_message "INFO" "Checking for open risky ports..." "SYSTEM"
    
    # Define risky ports to check for
    local risky_ports=(
        "21:FTP"
        "22:SSH" 
        "23:Telnet"
        "53:DNS"
        "80:HTTP"
        "135:RPC"
        "139:NetBIOS"
        "443:HTTPS"
        "445:SMB"
        "993:IMAPS"
        "995:POP3S"
        "1433:SQL Server"
        "1521:Oracle"
        "3306:MySQL"
        "3389:RDP"
        "5432:PostgreSQL"
        "5900:VNC"
        "6379:Redis"
        "8080:HTTP Alt"
        "27017:MongoDB"
    )
    
    local open_ports=()
    local high_risk_ports=()
    local medium_risk_ports=()
    
    # Check if netstat is available
    if command -v netstat >/dev/null 2>&1; then
        # Get listening ports
        local listening_ports=$(netstat -an | grep LISTEN)
        
        # Check each risky port
        for port_info in "${risky_ports[@]}"; do
            local port=$(echo "$port_info" | cut -d: -f1)
            local service=$(echo "$port_info" | cut -d: -f2)
            
            if echo "$listening_ports" | grep -q ":$port "; then
                open_ports+=("$port ($service)")
                
                # Categorize by risk level
                case "$port" in
                    "21"|"23"|"135"|"139"|"445"|"1433"|"3389"|"5900")
                        high_risk_ports+=("$port ($service)")
                        ;;
                    "22"|"53"|"80"|"443"|"993"|"995"|"3306"|"5432"|"6379"|"8080"|"27017")
                        medium_risk_ports+=("$port ($service)")
                        ;;
                esac
            fi
        done
        
        # Assess overall risk
        local risk_level="INFO"
        local recommendation=""
        local port_summary="${#open_ports[@]} risky ports open"
        
        if [[ ${#high_risk_ports[@]} -gt 0 ]]; then
            risk_level="HIGH"
            local high_risk_list=$(IFS=", "; echo "${high_risk_ports[*]}")
            recommendation="High-risk ports open: $high_risk_list. Close unnecessary services and use firewalls"
            port_summary="$port_summary (${#high_risk_ports[@]} high-risk)"
            
        elif [[ ${#medium_risk_ports[@]} -gt 0 ]]; then
            risk_level="MEDIUM"
            local medium_risk_list=$(IFS=", "; echo "${medium_risk_ports[*]}")
            recommendation="Medium-risk ports open: $medium_risk_list. Ensure proper security configuration"
            port_summary="$port_summary (${#medium_risk_ports[@]} medium-risk)"
            
        elif [[ ${#open_ports[@]} -gt 0 ]]; then
            risk_level="LOW"
            recommendation="Monitor open ports and ensure they are necessary for system operation"
        fi
        
        local port_details=""
        if [[ ${#open_ports[@]} -gt 0 ]]; then
            port_details="Open: $(IFS=", "; echo "${open_ports[*]}")"
        else
            port_details="No risky ports detected listening"
        fi
        
        # Network analysis module handles detailed port analysis
        
    else
        add_finding "Network" "Open Ports" "Unable to check" "netstat command not available" "LOW" "Install network utilities to check open ports"
    fi
}

# Helper function to add findings to the array
add_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    SYSTEM_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_system_findings() {
    printf '%s\n' "${SYSTEM_FINDINGS[@]}"
}
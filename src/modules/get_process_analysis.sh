#!/bin/bash

# macOSWorkstationAuditor - Process Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a PROCESS_FINDINGS=()

get_process_analysis_data() {
    log_message "INFO" "Analyzing running processes..." "PROCESSES"
    
    # Initialize findings array
    PROCESS_FINDINGS=()
    
    # Analyze running processes
    analyze_running_processes
    
    # Check for suspicious processes
    check_suspicious_processes
    
    log_message "SUCCESS" "Process analysis completed - ${#PROCESS_FINDINGS[@]} findings" "PROCESSES"
}

analyze_running_processes() {
    log_message "INFO" "Collecting running process information..." "PROCESSES"
    
    # Get process count
    local total_processes=$(ps -ax | wc -l | tr -d ' ')
    ((total_processes--))  # Remove header line
    
    add_process_finding "System" "Total Running Processes" "$total_processes processes" "All active processes on system" "INFO" ""
    
    # Get user processes vs system processes
    local user_processes=$(ps -axo user,pid,command | grep -v "^root\|^_\|^daemon" | wc -l | tr -d ' ')
    local system_processes=$((total_processes - user_processes))
    
    add_process_finding "System" "User Processes" "$user_processes processes" "Processes running under user accounts" "INFO" ""
    add_process_finding "System" "System Processes" "$system_processes processes" "Processes running under system accounts" "INFO" ""
}

check_suspicious_processes() {
    log_message "INFO" "Checking for suspicious or high-risk processes..." "PROCESSES"
    
    # Get all running processes with full command lines
    local all_processes=$(ps -axo pid,ppid,user,%cpu,%mem,command)
    
    # Check for processes that might indicate security issues
    local suspicious_patterns=(
        "bitcoin"
        "miner"
        "cryptonight"
        "xmrig"
        "cgminer"
        "bfgminer"
        "ethminer"
        "backdoor"
        "rootkit"
        "keylogger"
        "trojan"
    )
    
    local suspicious_found=()
    
    for pattern in "${suspicious_patterns[@]}"; do
        local matches=$(echo "$all_processes" | grep -i "$pattern" | grep -v grep)
        if [[ -n "$matches" ]]; then
            suspicious_found+=("$pattern")
        fi
    done
    
    if [[ ${#suspicious_found[@]} -gt 0 ]]; then
        local suspicious_list=$(IFS=", "; echo "${suspicious_found[*]}")
        add_process_finding "Security" "Suspicious Processes" "${#suspicious_found[@]} detected" "Patterns: $suspicious_list" "HIGH" "Investigate suspicious processes immediately. They may indicate malware or unauthorized software"
    else
        add_process_finding "Security" "Suspicious Processes" "None detected" "No obviously suspicious process names found" "INFO" ""
    fi
    
    # Check for high CPU usage processes
    check_high_cpu_processes
    
    # Check for network-related processes
    check_network_processes
}

check_high_cpu_processes() {
    log_message "INFO" "Checking for high CPU usage processes..." "PROCESSES"
    
    # Get top CPU consuming processes
    local high_cpu_processes=$(ps -axo pid,ppid,%cpu,command -r | awk '$3 > 50.0' | grep -v "%CPU")
    local high_cpu_count=0
    
    if [[ -n "$high_cpu_processes" ]]; then
        high_cpu_count=$(echo "$high_cpu_processes" | wc -l | tr -d ' ')
    fi
    
    if [[ $high_cpu_count -gt 0 ]]; then
        local risk_level="MEDIUM"
        local recommendation="High CPU usage processes detected. Monitor system performance and investigate if necessary"
        
        if [[ $high_cpu_count -gt 3 ]]; then
            risk_level="HIGH"
            recommendation="Multiple high CPU processes detected. This may indicate system issues or malware"
        fi
        
        # Extract process names and CPU percentages for details
        local process_details=$(echo "$high_cpu_processes" | awk '{print $4 ": " $3 "%"}' | head -5 | tr '\n' ', ' | sed 's/, $//')
        
        add_process_finding "Performance" "High CPU Processes" "$high_cpu_count processes >50%" "High CPU usage: $process_details" "$risk_level" "$recommendation"
    else
        add_process_finding "Performance" "High CPU Processes" "None detected" "No processes using excessive CPU" "INFO" ""
    fi
}

check_network_processes() {
    log_message "INFO" "Checking for network-related processes..." "PROCESSES"
    
    # Check for common network/remote access processes with detailed pattern matching
    local network_patterns=(
        "sshd.*ssh"
        "ssh "
        "vnc"
        "teamviewer"
        "anydesk"
        "screensharing"
        "ARDAgent"
        "Remote Desktop"
        "AppleVNC"
        "tightvnc"
        "realvnc"
        "logmein"
        "gotomypc"
    )
    
    local found_network_details=()
    local risk_level="INFO"
    local high_risk_count=0
    local medium_risk_count=0
    
    # Get detailed process information
    local all_processes=$(ps -axo pid,ppid,user,command)
    
    for pattern in "${network_patterns[@]}"; do
        local matches=$(echo "$all_processes" | grep -i "$pattern" | grep -v "grep")
        
        if [[ -n "$matches" ]]; then
            # Extract specific details for each match
            while IFS= read -r process_line; do
                if [[ -n "$process_line" ]]; then
                    local pid=$(echo "$process_line" | awk '{print $1}')
                    local user=$(echo "$process_line" | awk '{print $3}')
                    local command=$(echo "$process_line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                    
                    # Extract just the executable name for cleaner display
                    local exe_name=$(basename "$(echo "$command" | awk '{print $1}')")
                    
                    # Check for listening ports related to this process
                    local listening_ports=""
                    if command -v lsof >/dev/null 2>&1; then
                        listening_ports=$(lsof -Pan -p "$pid" -i 2>/dev/null | grep LISTEN | awk '{print $9}' | cut -d: -f2 | tr '\n' ',' | sed 's/,$//')
                    fi
                    
                    # Build detailed description
                    local detail_desc="PID:$pid User:$user"
                    if [[ -n "$listening_ports" ]]; then
                        detail_desc="$detail_desc Ports:$listening_ports"
                    fi
                    
                    # Determine risk level for this specific process
                    case "$exe_name" in
                        "sshd")
                            detail_desc="SSH Server - $detail_desc"
                            ((medium_risk_count++))
                            ;;
                        "ssh")
                            detail_desc="SSH Client - $detail_desc"
                            ;;
                        "teamviewer"|"TeamViewer")
                            detail_desc="TeamViewer - $detail_desc"
                            ((high_risk_count++))
                            ;;
                        "anydesk"|"AnyDesk")
                            detail_desc="AnyDesk - $detail_desc"
                            ((high_risk_count++))
                            ;;
                        "vnc"*|"VNC"*|"AppleVNC"|"tightvnc"|"realvnc")
                            detail_desc="VNC Server - $detail_desc"
                            ((high_risk_count++))
                            ;;
                        "screensharing"|"ARDAgent")
                            detail_desc="Apple Remote Desktop - $detail_desc"
                            ((medium_risk_count++))
                            ;;
                        *)
                            detail_desc="$exe_name - $detail_desc"
                            ;;
                    esac
                    
                    found_network_details+=("$detail_desc")
                fi
            done <<< "$matches"
        fi
    done
    
    # Also check for processes with active network connections
    if command -v lsof >/dev/null 2>&1; then
        local network_connections=$(lsof -i -n | grep -E "ESTABLISHED|LISTEN" | awk '{print $2 ":" $1}' | sort -u | head -10)
        if [[ -n "$network_connections" ]]; then
            local connection_count=$(echo "$network_connections" | wc -l | tr -d ' ')
            add_process_finding "Network" "Active Network Connections" "$connection_count connections" "PIDs with network activity: $(echo "$network_connections" | tr '\n' ', ' | sed 's/, $//')" "INFO" ""
        fi
    fi
    
    # Determine overall risk level and recommendation
    local recommendation=""
    if [[ $high_risk_count -gt 0 ]]; then
        risk_level="HIGH"
        recommendation="High-risk remote access software detected ($high_risk_count). Verify authorization and disable if not needed"
    elif [[ $medium_risk_count -gt 0 ]]; then
        risk_level="MEDIUM"
        recommendation="Network services detected ($medium_risk_count). Ensure proper security configuration and authorization"
    elif [[ ${#found_network_details[@]} -gt 0 ]]; then
        risk_level="LOW"
        recommendation="Network/remote processes active. Monitor for unauthorized access"
    fi
    
    # Report findings
    if [[ ${#found_network_details[@]} -gt 0 ]]; then
        local details_summary=""
        if [[ ${#found_network_details[@]} -le 3 ]]; then
            # Show all details if few processes
            details_summary=$(IFS="; "; echo "${found_network_details[*]}")
        else
            # Show first 3 and count for many processes
            local first_three=("${found_network_details[@]:0:3}")
            details_summary="$(IFS="; "; echo "${first_three[*]}") and $((${#found_network_details[@]} - 3)) more"
        fi
        
        add_process_finding "Security" "Network/Remote Processes" "${#found_network_details[@]} active" "$details_summary" "$risk_level" "$recommendation"
    else
        add_process_finding "Security" "Network/Remote Processes" "None detected" "No remote access processes found" "INFO" ""
    fi
}

# Helper function to add process findings to the array
add_process_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    PROCESS_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_process_findings() {
    printf '%s\n' "${PROCESS_FINDINGS[@]}"
}
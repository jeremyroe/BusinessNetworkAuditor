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

    # Analyze resource usage
    analyze_cpu_usage
    analyze_process_memory_usage

    # Suspicious process detection removed - not appropriate for IT audit tool
    
    log_message "SUCCESS" "Process analysis completed - ${#PROCESS_FINDINGS[@]} findings" "PROCESSES"
}

analyze_running_processes() {
    log_message "INFO" "Collecting running process information..." "PROCESSES"
    
    # Get process count
    local total_processes=$(ps -ax | wc -l | tr -d ' ')
    ((total_processes--))  # Remove header line
    
    # Get user processes vs system processes for consolidated report
    local user_processes=$(ps -axo user,pid,command | grep -v "^root\|^_\|^daemon" | wc -l | tr -d ' ')
    local system_processes=$((total_processes - user_processes))
    
    add_process_finding "System" "Process Activity" "$total_processes total" "User: $user_processes, System: $system_processes" "INFO" ""
}

analyze_cpu_usage() {
    log_message "INFO" "Analyzing CPU usage by processes..." "PROCESSES"

    # Get top 5 CPU processes with actual data format
    local top_cpu_data=$(ps -axo pid,%cpu,command | sort -nr -k2 | head -6 | tail -5)

    if [[ -n "$top_cpu_data" ]]; then
        local cpu_total="0.0"
        local cpu_details=""

        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local cpu_percent=$(echo "$line" | awk '{print $2}')
                local process_name=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/.*\///g' | cut -d' ' -f1 | head -c 20)

                if [[ -n "$cpu_details" ]]; then
                    cpu_details="$cpu_details,$process_name: ${cpu_percent}%"
                else
                    cpu_details="$process_name: ${cpu_percent}%"
                fi

                cpu_total=$(echo "$cpu_total + $cpu_percent" | bc 2>/dev/null || echo "$cpu_total")
            fi
        done <<< "$top_cpu_data"

        add_process_finding "System" "Top 5 Process CPU Usage" "${cpu_total}% total" "Details: $cpu_details" "INFO" ""
    fi
}

analyze_process_memory_usage() {
    log_message "INFO" "Analyzing memory usage by processes..." "PROCESSES"

    # Get top 5 memory processes using RSS (Resident Set Size)
    local top_mem_data=$(ps -axo pid,rss,command | sort -nr -k2 | head -6 | tail -5)

    if [[ -n "$top_mem_data" ]]; then
        local mem_total_kb=0
        local mem_details=""

        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local mem_kb=$(echo "$line" | awk '{print $2}')
                local process_name=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/.*\///g' | cut -d' ' -f1 | head -c 20)

                # Convert KB to MB
                local mem_mb=$((mem_kb / 1024))

                # Calculate percentage of 16GB (total system memory)
                local mem_percent=$(echo "scale=1; $mem_kb / 16384 / 1024 * 100" | bc 2>/dev/null || echo "0.0")

                if [[ -n "$mem_details" ]]; then
                    mem_details="$mem_details,$process_name: ${mem_percent}% (${mem_mb}MB)"
                else
                    mem_details="$process_name: ${mem_percent}% (${mem_mb}MB)"
                fi

                mem_total_kb=$((mem_total_kb + mem_kb))
            fi
        done <<< "$top_mem_data"

        local mem_total_gb=$(echo "scale=2; $mem_total_kb / 1024 / 1024" | bc 2>/dev/null || echo "0.00")

    fi
}

# Suspicious process detection function removed - not appropriate for enterprise IT audit tool
# This is not an antimalware solution and should not pretend to detect threats

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
            
            # Format the connections in a more readable way - just process names
            local formatted_connections=""
            local seen_processes=()
            while IFS= read -r connection; do
                if [[ -n "$connection" ]]; then
                    local process=$(echo "$connection" | cut -d: -f2)
                    # Clean up process name - remove path, truncate, and fix encoding
                    process=$(basename "$process" | cut -c1-15)
                    # Remove hex encoding and clean up names
                    process=$(echo "$process" | sed 's/\\x20/ /g' | sed 's/\\x[0-9A-Fa-f][0-9A-Fa-f]//g' | tr -d '\\')
                    # Remove extra whitespace and truncate
                    process=$(echo "$process" | sed 's/[[:space:]]*$//' | sed 's/^[[:space:]]*//' | cut -c1-12)
                    
                    # Skip empty or very short process names
                    if [[ -n "$process" && ${#process} -gt 2 ]]; then
                        # Only add if not already seen
                        if [[ ! " ${seen_processes[*]} " =~ " ${process} " ]]; then
                            seen_processes+=("$process")
                            if [[ -n "$formatted_connections" ]]; then
                                formatted_connections="$formatted_connections, $process"
                            else
                                formatted_connections="$process"
                            fi
                        fi
                    fi
                fi
            done <<< "$network_connections"
            
            add_process_finding "Network" "Active Network Connections" "${#seen_processes[@]} unique processes" "Processes with network activity: $formatted_connections" "INFO" ""
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
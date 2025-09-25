#!/bin/bash

# macOSWorkstationAuditor - Disk Space Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a DISK_FINDINGS=()

get_disk_space_analysis_data() {
    log_message "INFO" "Analyzing disk space..." "STORAGE"
    
    # Initialize findings array
    DISK_FINDINGS=()
    
    # Analyze disk usage for all mounted volumes (basic disk space check only)
    analyze_disk_usage
    
    log_message "SUCCESS" "Disk space analysis completed - ${#DISK_FINDINGS[@]} findings" "STORAGE"
}

analyze_disk_usage() {
    log_message "INFO" "Checking disk usage for mounted volumes..." "STORAGE"
    
    # Get disk usage for all mounted volumes
    while IFS= read -r line; do
        local device=$(echo "$line" | awk '{print $1}')
        local size=$(echo "$line" | awk '{print $2}')
        local used=$(echo "$line" | awk '{print $3}')
        local available=$(echo "$line" | awk '{print $4}')
        local percent=$(echo "$line" | awk '{print $5}' | tr -d '%')
        local mount_point=$(echo "$line" | awk '{for(i=9;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
        
        # Skip if not a real device or mount point
        if [[ "$device" == "Filesystem" ]] || [[ -z "$mount_point" ]] || [[ "$device" == "map"* ]]; then
            continue
        fi
        
        # Skip system volumes that users don't need to see
        case "$mount_point" in
            "/System/Volumes/VM"|"/System/Volumes/Preboot"|"/System/Volumes/Update"|"/System/Volumes/xarts"|"/System/Volumes/iSCPreboot"|"/System/Volumes/Hardware"|"/System/Volumes/Update/"*|"/private/var/vm")
                continue
                ;;
        esac
        
        # Determine risk level based on usage percentage
        local risk_level="INFO"
        local recommendation=""
        
        if [[ $percent -ge 95 ]]; then
            risk_level="HIGH"
            recommendation="Critical: Disk space is critically low. Free up space immediately to prevent system issues"
        elif [[ $percent -ge 90 ]]; then
            risk_level="HIGH"
            recommendation="Disk space is very low. Clean up unnecessary files to prevent performance degradation"
        elif [[ $percent -ge 80 ]]; then
            risk_level="MEDIUM"
            recommendation="Disk space is getting low. Monitor usage and consider cleanup"
        elif [[ $percent -ge 70 ]]; then
            risk_level="LOW"
            recommendation="Disk usage is moderate. Consider regular cleanup maintenance"
        fi
        
        local details="Used: $used ($percent%), Available: $available, Total: $size"
        add_disk_finding "Storage" "Disk Usage: $mount_point" "$percent% used" "$details" "$risk_level" "$recommendation"
        
        
    done < <(df -h | grep -E '^/dev/')
}


check_storage_optimization() {
    log_message "INFO" "Checking storage optimization features..." "STORAGE"
    
    # Check if storage optimization is enabled (macOS Sierra+)
    local optimization_enabled="Unknown"
    
    # Check for optimized storage settings
    local optimize_storage=$(defaults read com.apple.finder "OptimizeStorage" 2>/dev/null || echo "unknown")
    
    if [[ "$optimize_storage" == "1" ]]; then
        optimization_enabled="Enabled"
    elif [[ "$optimize_storage" == "0" ]]; then
        optimization_enabled="Disabled"
        add_disk_finding "Storage" "Storage Optimization" "$optimization_enabled" "Automatic storage optimization is disabled" "LOW" "Consider enabling storage optimization to automatically manage disk space"
    else
        optimization_enabled="Unknown"
    fi
    
    if [[ "$optimization_enabled" != "Unknown" ]]; then
        add_disk_finding "Storage" "Storage Optimization" "$optimization_enabled" "Automatic storage management status" "INFO" ""
    fi
    
    # Check for Time Machine local snapshots
    check_time_machine_snapshots
    
    # Check Trash/Bin usage
    check_trash_usage
}

check_time_machine_snapshots() {
    log_message "INFO" "Checking Time Machine local snapshots..." "STORAGE"
    
    # Check for local Time Machine snapshots
    if command -v tmutil >/dev/null 2>&1; then
        local snapshots=$(tmutil listlocalsnapshotdates 2>/dev/null | grep -v "Listing" | wc -l | tr -d ' ')
        
        if [[ $snapshots -gt 0 ]]; then
            local risk_level="INFO"
            local recommendation=""
            
            if [[ $snapshots -gt 10 ]]; then
                risk_level="LOW"
                recommendation="Many Time Machine snapshots detected. These consume disk space but are automatically managed"
            fi
            
            add_disk_finding "Storage" "Time Machine Snapshots" "$snapshots snapshots" "Local Time Machine snapshots on disk" "$risk_level" "$recommendation"
        else
            add_disk_finding "Storage" "Time Machine Snapshots" "None" "No local Time Machine snapshots found" "INFO" ""
        fi
    fi
}


# Helper function to add disk findings to the array
add_disk_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    DISK_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_disk_findings() {
    printf '%s\n' "${DISK_FINDINGS[@]}"
}
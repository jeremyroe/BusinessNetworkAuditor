#!/bin/bash

# macOSWorkstationAuditor - Disk Space Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a DISK_FINDINGS=()

get_disk_space_analysis_data() {
    log_message "INFO" "Analyzing disk space..." "STORAGE"
    
    # Initialize findings array
    DISK_FINDINGS=()
    
    # Analyze disk usage for all mounted volumes
    analyze_disk_usage
    
    # Check for large files/directories
    check_large_files
    
    # Check system storage optimization
    check_storage_optimization
    
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
        
        # Special handling for root volume
        if [[ "$mount_point" == "/" ]]; then
            analyze_root_volume_breakdown "$available"
        fi
        
    done < <(df -h | grep -E '^/dev/')
}

analyze_root_volume_breakdown() {
    local available="$1"
    
    log_message "INFO" "Analyzing root volume space breakdown..." "STORAGE"
    
    # Check major directories for space usage
    local major_dirs=("/Applications" "/Users" "/System" "/Library" "/private/var" "/usr")
    
    for dir in "${major_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local dir_size=$(du -sh "$dir" 2>/dev/null | awk '{print $1}' || echo "Unknown")
            if [[ "$dir_size" != "Unknown" ]]; then
                add_disk_finding "Storage" "Directory: $dir" "$dir_size" "Space usage for $dir" "INFO" ""
            fi
        fi
    done
    
    # Check for large log files
    check_log_file_sizes
}

check_large_files() {
    log_message "INFO" "Checking for large files..." "STORAGE"
    
    # Look for files larger than 1GB in common locations
    local large_files_found=false
    local search_paths=("/Applications" "/Users/$USER" "/Library" "/private/tmp")
    
    for search_path in "${search_paths[@]}"; do
        if [[ -d "$search_path" ]]; then
            # Find files larger than 1GB (using a reasonable timeout)
            local large_files=$(timeout 30 find "$search_path" -type f -size +1G 2>/dev/null | head -10)
            
            if [[ -n "$large_files" ]]; then
                large_files_found=true
                local file_count=$(echo "$large_files" | wc -l | tr -d ' ')
                
                # Get size of largest file
                local largest_file=$(echo "$large_files" | head -1)
                local largest_size="Unknown"
                if [[ -n "$largest_file" ]]; then
                    largest_size=$(du -sh "$largest_file" 2>/dev/null | awk '{print $1}' || echo "Unknown")
                fi
                
                local risk_level="LOW"
                local recommendation="Review large files for cleanup opportunities"
                
                if [[ $file_count -gt 5 ]]; then
                    risk_level="MEDIUM"
                    recommendation="Multiple large files found. Review and clean up unnecessary files to free space"
                fi
                
                add_disk_finding "Storage" "Large Files in $search_path" "$file_count files >1GB" "Largest: $largest_size" "$risk_level" "$recommendation"
            fi
        fi
    done
    
    if [[ "$large_files_found" == false ]]; then
        add_disk_finding "Storage" "Large Files" "None found" "No files >1GB detected in common locations" "INFO" ""
    fi
}

check_log_file_sizes() {
    log_message "INFO" "Checking system log file sizes..." "STORAGE"
    
    local log_dirs=("/private/var/log" "/Library/Logs" "$HOME/Library/Logs")
    local total_log_size=0
    local large_logs_found=false
    
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            # Get total size of log directory
            local dir_size_bytes=$(du -sk "$log_dir" 2>/dev/null | awk '{print $1}' || echo "0")
            total_log_size=$((total_log_size + dir_size_bytes))
            
            # Check for individual large log files
            local large_logs=$(find "$log_dir" -type f -size +100M 2>/dev/null | head -5)
            if [[ -n "$large_logs" ]]; then
                large_logs_found=true
                local log_count=$(echo "$large_logs" | wc -l | tr -d ' ')
                
                local risk_level="LOW"
                local recommendation="Large log files detected. Consider log rotation or cleanup"
                
                if [[ $log_count -gt 3 ]]; then
                    risk_level="MEDIUM"
                    recommendation="Multiple large log files found. Implement log rotation and cleanup"
                fi
                
                add_disk_finding "Storage" "Large Log Files in $log_dir" "$log_count files >100MB" "Review log file management" "$risk_level" "$recommendation"
            fi
        fi
    done
    
    # Report total log space usage
    if [[ $total_log_size -gt 0 ]]; then
        local total_log_size_mb=$((total_log_size / 1024))
        local risk_level="INFO"
        local recommendation=""
        
        if [[ $total_log_size_mb -gt 5000 ]]; then  # More than 5GB
            risk_level="MEDIUM"
            recommendation="Log files consuming significant disk space. Review log retention policies"
        elif [[ $total_log_size_mb -gt 2000 ]]; then  # More than 2GB
            risk_level="LOW"
            recommendation="Consider reviewing log file sizes and retention"
        fi
        
        add_disk_finding "Storage" "Total Log File Usage" "${total_log_size_mb}MB" "Combined size of all log directories" "$risk_level" "$recommendation"
    fi
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

check_trash_usage() {
    log_message "INFO" "Checking Trash usage..." "STORAGE"
    
    local trash_dir="$HOME/.Trash"
    if [[ -d "$trash_dir" ]]; then
        local trash_size=$(du -sh "$trash_dir" 2>/dev/null | awk '{print $1}' || echo "0K")
        local trash_items=$(find "$trash_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
        
        local risk_level="INFO"
        local recommendation=""
        
        # Convert size to MB for comparison (rough estimate)
        local size_mb=0
        if echo "$trash_size" | grep -q "G"; then
            size_mb=$(echo "$trash_size" | sed 's/G.*//' | awk '{print $1 * 1024}')
        elif echo "$trash_size" | grep -q "M"; then
            size_mb=$(echo "$trash_size" | sed 's/M.*//')
        fi
        
        if [[ $size_mb -gt 1000 ]]; then  # More than 1GB
            risk_level="MEDIUM"
            recommendation="Trash contains significant data ($trash_size). Empty trash to free disk space"
        elif [[ $size_mb -gt 500 ]]; then  # More than 500MB
            risk_level="LOW"
            recommendation="Consider emptying trash to free up disk space"
        fi
        
        add_disk_finding "Storage" "Trash Usage" "$trash_size" "$trash_items items in trash" "$risk_level" "$recommendation"
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
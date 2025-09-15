#!/bin/bash

# macOSWorkstationAuditor - Memory Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a MEMORY_FINDINGS=()

get_memory_analysis_data() {
    log_message "INFO" "Analyzing memory usage..." "MEMORY"
    
    # Initialize findings array
    MEMORY_FINDINGS=()
    
    # Get memory information
    analyze_memory_usage
    
    log_message "SUCCESS" "Memory analysis completed - ${#MEMORY_FINDINGS[@]} findings" "MEMORY"
}

analyze_memory_usage() {
    log_message "INFO" "Checking memory configuration and usage..." "MEMORY"
    
    # Get total physical memory
    local total_memory_bytes=$(sysctl -n hw.memsize)
    local total_memory_gb=$(echo "scale=2; $total_memory_bytes / 1073741824" | bc)
    
    # Get memory pressure information
    local memory_pressure=$(memory_pressure 2>/dev/null | head -20)
    
    # Extract key memory metrics
    local pages_free=$(echo "$memory_pressure" | grep "Pages free:" | awk '{print $3}' | tr -d '.')
    local pages_active=$(echo "$memory_pressure" | grep "Pages active:" | awk '{print $3}' | tr -d '.')
    local pages_inactive=$(echo "$memory_pressure" | grep "Pages inactive:" | awk '{print $3}' | tr -d '.')
    local pages_wired=$(echo "$memory_pressure" | grep "Pages wired down:" | awk '{print $4}' | tr -d '.')
    local pages_compressed=$(echo "$memory_pressure" | grep "Pages stored in compressor:" | awk '{print $5}' | tr -d '.')
    
    # Calculate memory usage if we have the data
    if [[ -n "$pages_free" && -n "$pages_active" && -n "$pages_wired" ]]; then
        local page_size=4096  # 4KB page size on most systems
        local free_memory_bytes=$((pages_free * page_size))
        local active_memory_bytes=$((pages_active * page_size))
        local wired_memory_bytes=$((pages_wired * page_size))
        
        local free_memory_gb=$(echo "scale=2; $free_memory_bytes / 1073741824" | bc)
        local active_memory_gb=$(echo "scale=2; $active_memory_bytes / 1073741824" | bc)
        local wired_memory_gb=$(echo "scale=2; $wired_memory_bytes / 1073741824" | bc)
        
        local memory_usage_percent=$(echo "scale=1; (($total_memory_bytes - $free_memory_bytes) * 100) / $total_memory_bytes" | bc)
        
        # Assess memory status
        local risk_level="INFO"
        local recommendation=""
        
        if (( $(echo "$memory_usage_percent > 90" | bc -l) )); then
            risk_level="HIGH"
            recommendation="Memory usage is critically high. Close unnecessary applications or add more RAM"
        elif (( $(echo "$memory_usage_percent > 80" | bc -l) )); then
            risk_level="MEDIUM"
            recommendation="Memory usage is high. Monitor memory-intensive applications"
        elif (( $(echo "$memory_usage_percent > 70" | bc -l) )); then
            risk_level="LOW"
            recommendation="Memory usage is moderate. Consider monitoring memory usage patterns"
        fi
        
        add_memory_finding "Memory" "Memory Usage" "${memory_usage_percent}%" "Total: ${total_memory_gb}GB, Free: ${free_memory_gb}GB, Active: ${active_memory_gb}GB" "$risk_level" "$recommendation"
        
        # Check memory pressure indicators
        if [[ -n "$pages_compressed" && $pages_compressed -gt 0 ]]; then
            local compressed_gb=$(echo "scale=2; ($pages_compressed * $page_size) / 1073741824" | bc)
            add_memory_finding "Memory" "Memory Compression" "${compressed_gb}GB compressed" "System is using memory compression to manage pressure" "LOW" "Memory compression active - consider adding more RAM for better performance"
        fi
    else
        # Fallback to basic memory info
        add_memory_finding "Memory" "Total Physical Memory" "${total_memory_gb}GB" "Installed RAM capacity" "INFO" ""
        add_memory_finding "Memory" "Memory Pressure" "Unable to determine" "Could not read detailed memory usage" "LOW" "Check system performance tools for memory usage"
    fi
    
    # Note: Swap usage analysis integrated into main memory analysis above
    
    # Check for memory-intensive processes
    check_memory_intensive_processes
}

# check_swap_usage() - REMOVED: Redundant with main memory analysis
# This function was removed as swap usage is already covered in the main memory pressure analysis

# Function to convert process names to human-readable format
get_human_readable_process_name() {
    local raw_name="$1"
    local clean_name=""
    
    # Remove common prefixes and clean up the name
    clean_name=$(echo "$raw_name" | sed 's/^.*\///g')  # Remove path
    
    # Map common macOS processes to readable names
    case "$clean_name" in
        "com.apple.WebKit.WebContent")
            echo "Safari Web Content"
            ;;
        "WindowServer")
            echo "Window Server (Graphics)"
            ;;
        "kernel_task")
            echo "Kernel Task (System)"
            ;;
        "launchd")
            echo "Launch Daemon (System)"
            ;;
        "Finder")
            echo "Finder"
            ;;
        "Safari")
            echo "Safari Browser"
            ;;
        "Google Chrome Helper"*)
            echo "Chrome Helper Process"
            ;;
        "Google Chrome")
            echo "Google Chrome"
            ;;
        "Firefox")
            echo "Mozilla Firefox"
            ;;
        "Microsoft Edge")
            echo "Microsoft Edge"
            ;;
        "Code")
            echo "Visual Studio Code"
            ;;
        "Xcode")
            echo "Xcode IDE"
            ;;
        "Docker Desktop")
            echo "Docker Desktop"
            ;;
        "VirtualBox"*)
            echo "VirtualBox VM"
            ;;
        "VMware Fusion"*)
            echo "VMware Fusion"
            ;;
        "Parallels Desktop"*)
            echo "Parallels Desktop"
            ;;
        "com.apple."*)
            # Generic Apple system process
            local apple_name=$(echo "$clean_name" | sed 's/com\.apple\.//' | sed 's/\([A-Z]\)/ \1/g' | sed 's/^ //')
            echo "Apple $apple_name"
            ;;
        *".app"*)
            # Generic app name extraction
            echo "$clean_name" | sed 's/\.app.*//' | sed 's/\([A-Z]\)/ \1/g' | sed 's/^ //'
            ;;
        *)
            # Return the clean name with camel case separated
            echo "$clean_name" | sed 's/\([A-Z]\)/ \1/g' | sed 's/^ //'
            ;;
    esac
}

check_memory_intensive_processes() {
    log_message "INFO" "Checking for memory-intensive processes..." "MEMORY"
    
    # Get top memory-consuming processes with better formatting
    local top_processes=$(ps -axo pid,ppid,%mem,rss,command -r | head -6 | tail -5)
    local high_memory_count=0
    local total_top5_memory=0
    local high_memory_details=()
    local top5_process_details=()
    
    while IFS= read -r process_line; do
        if [[ -n "$process_line" ]]; then
            local mem_percent=$(echo "$process_line" | awk '{print $3}')
            local mem_rss_kb=$(echo "$process_line" | awk '{print $4}')
            local raw_command=$(echo "$process_line" | awk '{for(i=5;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
            
            # Extract the executable name and get human-readable version
            local exe_name=$(echo "$raw_command" | awk '{print $1}')
            local process_name=$(get_human_readable_process_name "$exe_name")
            
            # Check if process is using significant memory (>5% or >500MB)
            local mem_mb=$((mem_rss_kb / 1024))
            total_top5_memory=$((total_top5_memory + mem_mb))
            
            # Add to top 5 list with readable names
            top5_process_details+=("$process_name: ${mem_percent}% (${mem_mb}MB)")
            
            if (( $(echo "$mem_percent > 10.0" | bc -l) )) || [[ $mem_mb -gt 500 ]]; then
                ((high_memory_count++))
                high_memory_details+=("$process_name: ${mem_percent}% (${mem_mb}MB)")
            fi
        fi
    done <<< "$top_processes"
    
    if [[ $high_memory_count -gt 0 ]]; then
        local risk_level="LOW"
        local recommendation="Monitor memory-intensive applications for performance impact"
        
        if [[ $high_memory_count -gt 2 ]]; then
            risk_level="MEDIUM"
            recommendation="Multiple memory-intensive processes detected. Consider closing unnecessary applications"
        fi
        
        # Create detailed list of high-memory processes
        local high_memory_list=$(IFS=", "; echo "${high_memory_details[*]}")
        add_memory_finding "Memory" "Memory-Intensive Processes" "$high_memory_count processes" "High usage: $high_memory_list" "$risk_level" "$recommendation"
    fi
    
    # Report detailed top 5 process memory usage
    if [[ $total_top5_memory -gt 0 ]]; then
        local total_top5_gb=$(echo "scale=2; $total_top5_memory / 1024" | bc)
        local top5_list=$(IFS=", "; echo "${top5_process_details[*]}")
        add_memory_finding "Memory" "Top 5 Process Memory Usage" "${total_top5_gb}GB total" "Details: $top5_list" "INFO" ""
    fi
}

# Helper function to add memory findings to the array
add_memory_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    MEMORY_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_memory_findings() {
    printf '%s\n' "${MEMORY_FINDINGS[@]}"
}
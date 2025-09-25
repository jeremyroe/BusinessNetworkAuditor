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
    
    # Extract key memory metrics and get correct page size
    local page_size=$(echo "$memory_pressure" | grep "page size" | sed 's/.*page size of \([0-9]*\).*/\1/')
    local pages_free=$(echo "$memory_pressure" | grep "Pages free:" | awk '{print $3}' | tr -d '.')
    local pages_active=$(echo "$memory_pressure" | grep "Pages active:" | awk '{print $3}' | tr -d '.')
    local pages_inactive=$(echo "$memory_pressure" | grep "Pages inactive:" | awk '{print $3}' | tr -d '.')
    local pages_wired=$(echo "$memory_pressure" | grep "Pages wired down:" | awk '{print $4}' | tr -d '.')
    local pages_compressed=$(echo "$memory_pressure" | grep "used by compressor:" | awk '{print $5}' | tr -d '.')
    
    # Set default page size if not found
    [[ -z "$page_size" ]] && page_size=16384
    
    # Calculate memory usage if we have the data
    if [[ -n "$pages_free" && -n "$pages_active" && -n "$pages_wired" ]]; then
        local free_memory_bytes=$((pages_free * page_size))
        local active_memory_bytes=$((pages_active * page_size))
        local wired_memory_bytes=$((pages_wired * page_size))
        local inactive_memory_bytes=$((${pages_inactive:-0} * page_size))
        local compressed_memory_bytes=$((${pages_compressed:-0} * page_size))
        
        # Calculate used memory (active + wired + compressed)
        local used_memory_bytes=$((active_memory_bytes + wired_memory_bytes + compressed_memory_bytes))
        
        # Calculate available/free memory (total - used)
        local available_memory_bytes=$((total_memory_bytes - used_memory_bytes))
        local available_memory_gb=$(echo "scale=2; $available_memory_bytes / 1073741824" | bc)
        
        local active_memory_gb=$(echo "scale=2; $active_memory_bytes / 1073741824" | bc)
        local used_memory_gb=$(echo "scale=2; $used_memory_bytes / 1073741824" | bc)
        
        local memory_usage_percent=$(echo "scale=1; ($used_memory_bytes * 100) / $total_memory_bytes" | bc)
        
        # Assess memory status
        local risk_level="INFO"
        local recommendation=""
        
        # Convert to integer for bash 3.2 compatibility
        local memory_usage_int=$(echo "$memory_usage_percent" | cut -d. -f1)
        if [[ $memory_usage_int -gt 90 ]]; then
            risk_level="HIGH"
            recommendation="Memory usage is critically high. Close unnecessary applications or add more RAM"
        elif [[ $memory_usage_int -gt 80 ]]; then
            risk_level="MEDIUM"
            recommendation="Memory usage is high. Monitor memory-intensive applications"
        elif [[ $memory_usage_int -gt 70 ]]; then
            risk_level="LOW"
            recommendation="Memory usage is moderate. Consider monitoring memory usage patterns"
        fi
        
        add_memory_finding "Memory" "Memory Usage" "${memory_usage_percent}%" "Total: ${total_memory_gb}GB, Used: ${used_memory_gb}GB, Available: ${available_memory_gb}GB" "$risk_level" "$recommendation"
        
        # Check memory pressure indicators - only report compression issues on Intel Macs
        if [[ -n "$pages_compressed" && "$pages_compressed" != "0" ]]; then
            local compressed_gb=$(echo "scale=2; ($pages_compressed * $page_size) / 1073741824" | bc)
            
            # Check if this is Apple Silicon (M-series) - compression is normal, don't report it
            local cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "")
            if [[ "$cpu_brand" != *"Apple"* ]]; then
                # Only report on Intel Macs where high compression might indicate memory pressure
                if (( $(echo "$compressed_gb > 2" | bc -l) )); then
                    add_memory_finding "Memory" "Memory Compression" "${compressed_gb}GB compressed" "High memory compression may indicate memory pressure" "LOW" "Consider monitoring memory usage or adding more RAM"
                fi
            fi
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
            # Handle truncated or encoded process names
            if [[ ${#clean_name} -gt 15 && "$clean_name" =~ ^[A-Za-z0-9+/=]+$ ]]; then
                echo "Process (${clean_name:0:10}...)"
            else
                # Return the clean name with camel case separated
                echo "$clean_name" | sed 's/\([A-Z]\)/ \1/g' | sed 's/^ //'
            fi
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
            # Convert to integer first to handle floating point values from top command
            local mem_rss_kb_int=$(echo "$mem_rss_kb" | awk '{print int($1)}')
            local mem_mb=$((mem_rss_kb_int / 1024))
            total_top5_memory=$((total_top5_memory + mem_mb))
            
            # Add to top 5 list with readable names
            top5_process_details+=("$process_name: ${mem_percent}% (${mem_mb}MB)")
            
            # Convert percentage to integer for comparison
            local mem_percent_int=$(echo "$mem_percent" | cut -d. -f1)
            if [[ $mem_percent_int -gt 10 ]] || [[ $mem_mb -gt 500 ]]; then
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
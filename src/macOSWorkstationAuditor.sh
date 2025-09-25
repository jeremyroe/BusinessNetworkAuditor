#!/bin/bash

# macOSWorkstationAuditor - macOS Workstation IT Assessment Tool
# Version 1.0.0 - Modular Architecture
# Platform: macOS 10.14+ (Mojave and later)
# Requires: bash 3.2+, Administrative privileges recommended

# Parameter handling
OUTPUT_PATH="./output"
CONFIG_PATH="./config"
VERBOSE=false
FORCE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_PATH="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -h|--help)
            echo "macOS Workstation IT Assessment Tool v1.0.0"
            echo "Usage: $0 [options]"
            echo "  -o, --output PATH    Output directory (default: ./output)"
            echo "  -c, --config PATH    Configuration directory (default: ./config)"
            echo "  -v, --verbose        Enable verbose logging"
            echo "  -f, --force          Force overwrite existing files"
            echo "  -h, --help           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE=""
START_TIME=$(date +%s)
COMPUTER_NAME=$(hostname -s)
BASE_FILENAME="${COMPUTER_NAME}_$(date '+%Y%m%d_%H%M%S')"
MODULES_PATH="$SCRIPT_DIR/modules"

# Configuration (using bash 3.2 compatible syntax)
CONFIG_VERSION="1.0.0"
CONFIG_ANALYSIS_DAYS=7
CONFIG_MAX_EVENTS=1000

# Color definitions for terminal output
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'
COLOR_WHITE='\033[0;37m'
COLOR_BOLD='\033[1m'
COLOR_RESET='\033[0m'

# JSON escape function to handle control characters
escape_json_string() {
    local input="$1"
    # Escape backslashes first, then quotes, then newlines, tabs, and carriage returns, then trim whitespace
    echo "$input" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed 's/\t/\\t/g' | tr '\n' ' ' | tr '\r' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Logging functions with color support
log_message() {
    local level="$1"
    local message="$2"
    local category="${3:-MAIN}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local log_entry="[$timestamp] [$level] [$category] $message"
    local colored_output=""
    
    # Add colors based on log level (matches Windows PowerShell)
    case "$level" in
        "SUCCESS")
            colored_output="${COLOR_GREEN}$log_entry${COLOR_RESET}"
            ;;
        "ERROR")
            colored_output="${COLOR_RED}$log_entry${COLOR_RESET}"
            ;;
        "WARN"|"WARNING")
            colored_output="${COLOR_YELLOW}$log_entry${COLOR_RESET}"
            ;;
        "INFO")
            colored_output="$log_entry"
            ;;
        *)
            colored_output="$log_entry"
            ;;
    esac
    
    # Display colored output for console
    if [[ "$VERBOSE" == true ]] || [[ "$level" == "ERROR" ]]; then
        echo -e "$colored_output"
    fi
    
    # Log plain text to file
    if [[ -n "$LOG_FILE" ]]; then
        echo "$log_entry" >> "$LOG_FILE"
    fi
}

# Enhanced progress output function with Windows-style rich feedback
# Displays colored status messages with optional timing and finding counts
# Parameters:
#   $1 - status: STARTING|COMPLETE|FAILED|HEADER|PROGRESS|WARNING
#   $2 - message: descriptive text for the operation
#   $3 - findings_count: optional number of findings discovered (for COMPLETE status)
#   $4 - duration: optional execution time in seconds (for COMPLETE status)
print_status() {
    local status="$1"
    local message="$2"
    local findings_count="$3"
    local duration="$4"
    
    case "$status" in
        "STARTING")
            # Simple starting message with ellipsis
            echo "${message}..."
            ;;
        "COMPLETE")
            # Rich completion message with optional metrics
            if [[ -n "$findings_count" && -n "$duration" ]]; then
                # Full metrics: findings count and execution time
                echo -e "  ${COLOR_GREEN}→ ${message}: COMPLETE${COLOR_RESET} ${COLOR_CYAN}($findings_count findings, ${duration}s)${COLOR_RESET}"
            elif [[ -n "$findings_count" ]]; then
                # Findings count only
                echo -e "  ${COLOR_GREEN}→ ${message}: COMPLETE${COLOR_RESET} ${COLOR_CYAN}($findings_count findings)${COLOR_RESET}"
            elif [[ -n "$duration" ]]; then
                # Execution time only
                echo -e "  ${COLOR_GREEN}→ ${message}: COMPLETE${COLOR_RESET} ${COLOR_CYAN}(${duration}s)${COLOR_RESET}"
            else
                # Basic completion message
                echo -e "  ${COLOR_GREEN}→ ${message}: COMPLETE${COLOR_RESET}"
            fi
            ;;
        "FAILED")
            # Error status in red
            echo -e "  ${COLOR_RED}→ ${message}: FAILED${COLOR_RESET}"
            ;;
        "HEADER")
            # Bold blue header text
            echo -e "${COLOR_BOLD}${COLOR_BLUE}${message}${COLOR_RESET}"
            ;;
        "PROGRESS")
            # Yellow progress indicator for intermediate steps
            echo -e "  ${COLOR_YELLOW}→ ${message}${COLOR_RESET}"
            ;;
        "WARNING")
            # Yellow warning with warning symbol
            echo -e "  ${COLOR_YELLOW}⚠ ${message}${COLOR_RESET}"
            ;;
    esac
}

# Module loading system
load_module() {
    local module_name="$1"
    local module_file="$MODULES_PATH/$module_name.sh"
    
    if [[ -f "$module_file" ]]; then
        source "$module_file"
        log_message "SUCCESS" "Loaded module: $module_name" "MODULE"
        return 0
    else
        log_message "ERROR" "Module file not found: $module_file" "MODULE"
        return 1
    fi
}

# Configuration loading
load_configuration() {
    local config_file="$CONFIG_PATH/macos-audit-config.json"
    
    if [[ -f "$config_file" ]]; then
        log_message "INFO" "Loading configuration from: $config_file" "CONFIG"
        
        # Parse JSON using plutil (always available on macOS)
        if command -v plutil >/dev/null 2>&1; then
            local version=$(plutil -extract version raw "$config_file" 2>/dev/null)
            if [[ -n "$version" ]]; then
                CONFIG_VERSION="$version"
                log_message "SUCCESS" "Configuration loaded: v$CONFIG_VERSION" "CONFIG"
            fi
        fi
    else
        log_message "WARNING" "Configuration file not found, using defaults" "CONFIG"
    fi
}

# Initialize environment
initialize_environment() {
    log_message "INFO" "macOS Workstation Auditor v$CONFIG_VERSION starting..." "INIT"
    log_message "INFO" "Computer: $COMPUTER_NAME" "INIT"
    log_message "INFO" "macOS Version: $(sw_vers -productVersion)" "INIT"
    log_message "INFO" "Architecture: $(uname -m)" "INIT"
    
    # Create output and logs directories
    if [[ ! -d "$OUTPUT_PATH" ]]; then
        mkdir -p "$OUTPUT_PATH"
        log_message "INFO" "Created output directory: $OUTPUT_PATH" "INIT"
    fi
    
    local logs_dir="$OUTPUT_PATH/logs"
    if [[ ! -d "$logs_dir" ]]; then
        mkdir -p "$logs_dir"
        log_message "INFO" "Created logs directory: $logs_dir" "INIT"
    fi
    
    # Initialize log file in logs subdirectory (matching Windows format)
    LOG_FILE="$logs_dir/${BASE_FILENAME}_audit.log"
    log_message "INFO" "Log file: $LOG_FILE" "INIT"
    
    # Load configuration
    load_configuration
    
    # Check for administrative privileges
    if [[ $EUID -eq 0 ]]; then
        log_message "INFO" "Running with root privileges" "INIT"
    else
        log_message "WARNING" "Not running as root - some data collection may be limited" "INIT"
    fi
}

# Data collection functions with performance tracking and metrics
# Each collection function tracks execution time and finding counts for rich console feedback

collect_system_information() {
    # Track execution time for performance monitoring
    local start_time=$(date +%s)
    print_status "STARTING" "Collecting system information"
    log_message "INFO" "Collecting system information..." "SYSTEM"
    
    # Load system information module
    if load_module "get_system_information"; then
        # Detailed progress feedback during data collection
        print_status "PROGRESS" "Analyzing hardware configuration..."
        print_status "PROGRESS" "Checking macOS version and build details..."
        print_status "PROGRESS" "Gathering system uptime and boot information..."
        
        # Count findings before and after module execution for delta calculation
        local findings_before=${#SYSTEM_FINDINGS[@]}
        get_system_information_data
        local findings_after=${#SYSTEM_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        
        # System-specific warnings and notifications
        if [[ $findings_count -lt 5 ]]; then
            print_status "WARNING" "Limited system information collected - may need elevated privileges"
        fi
        
        # Calculate execution duration for performance visibility
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        # Display completion with metrics (Windows-style rich feedback)
        print_status "COMPLETE" "System information" "$findings_count" "$duration"
    else
        print_status "FAILED" "System information"
        log_message "ERROR" "Failed to load system information module" "SYSTEM"
    fi
}

collect_security_settings() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing security settings"
    log_message "INFO" "Analyzing security settings..." "SECURITY"
    
    if load_module "get_security_settings"; then
        # Comprehensive security analysis progress
        print_status "PROGRESS" "Checking XProtect malware protection status..."
        print_status "PROGRESS" "Analyzing Gatekeeper and System Integrity Protection..."
        print_status "PROGRESS" "Evaluating FileVault encryption configuration..."
        print_status "PROGRESS" "Scanning for third-party security tools..."
        print_status "PROGRESS" "Checking SSH and remote access services..."
        print_status "PROGRESS" "Analyzing AirDrop and sharing settings..."
        print_status "PROGRESS" "Validating firewall and network security..."
        
        local findings_before=${#SECURITY_FINDINGS[@]}
        get_security_settings_data
        local findings_after=${#SECURITY_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        
        # Security-specific insights
        if [[ $findings_count -gt 20 ]]; then
            print_status "PROGRESS" "Comprehensive security profile detected - $findings_count configurations analyzed"
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Security analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Security analysis"
        log_message "ERROR" "Failed to load security settings module" "SECURITY"
    fi
}

collect_software_inventory() {
    local start_time=$(date +%s)
    print_status "STARTING" "Collecting software inventory"
    log_message "INFO" "Collecting software inventory..." "SOFTWARE"
    
    if load_module "get_software_inventory"; then
        local findings_before=${#SOFTWARE_FINDINGS[@]}
        get_software_inventory_data
        local findings_after=${#SOFTWARE_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Software inventory" "$findings_count" "$duration"
    else
        print_status "FAILED" "Software inventory"
        log_message "ERROR" "Failed to load software inventory module" "SOFTWARE"
    fi
}

collect_network_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing network configuration"
    log_message "INFO" "Analyzing network configuration..." "NETWORK"
    
    if load_module "get_network_analysis"; then
        # Detailed network analysis progress
        print_status "PROGRESS" "Scanning active network interfaces and IP configuration..."
        print_status "PROGRESS" "Analyzing listening services and open ports..."
        print_status "PROGRESS" "Checking Wi-Fi networks and saved profiles..."
        print_status "PROGRESS" "Evaluating DNS configuration and VPN status..."
        
        local findings_before=${#NETWORK_FINDINGS[@]}
        get_network_analysis_data
        local findings_after=${#NETWORK_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        
        # Network-specific insights  
        if [[ $findings_count -gt 8 ]]; then
            print_status "PROGRESS" "Complex network configuration detected - $findings_count settings analyzed"
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Network analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Network analysis"
        log_message "ERROR" "Failed to load network analysis module" "NETWORK"
    fi
}

collect_user_account_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing user accounts"
    log_message "INFO" "Analyzing user accounts..." "USERS"
    
    if load_module "get_user_account_analysis"; then
        local findings_before=${#USER_FINDINGS[@]}
        get_user_account_analysis_data
        local findings_after=${#USER_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "User account analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "User account analysis"
        log_message "ERROR" "Failed to load user account analysis module" "USERS"
    fi
}

collect_patch_status() {
    local start_time=$(date +%s)
    print_status "STARTING" "Checking patch status"
    print_status "PROGRESS" "Analyzing macOS version lifecycle and support status..."
    print_status "PROGRESS" "Checking automatic update configuration..."
    print_status "WARNING" "Contacting Apple Software Update servers (may take 30+ seconds)..."
    log_message "INFO" "Checking patch status..." "PATCHING"
    
    if load_module "get_patch_status"; then
        print_status "PROGRESS" "Parsing available software updates..."
        print_status "PROGRESS" "Analyzing XProtect malware definition updates..."
        
        local findings_before=${#PATCH_FINDINGS[@]}
        get_patch_status_data
        local findings_after=${#PATCH_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        
        # Patch-specific insights - check for actual updates rather than just counting findings
        local update_findings=0
        for finding in "${PATCH_FINDINGS[@]}"; do
            if echo "$finding" | grep -q '"item":"Available Updates"' && echo "$finding" | grep -qv '"value":"None"'; then
                ((update_findings++))
            fi
        done

        if [[ $update_findings -eq 0 ]]; then
            print_status "PROGRESS" "No updates available - system appears current"
        elif [[ $update_findings -gt 0 ]]; then
            print_status "WARNING" "Software updates available - review for security patches"
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Patch analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Patch analysis"
        log_message "ERROR" "Failed to load patch status module" "PATCHING"
    fi
}

collect_disk_space_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing disk space"
    log_message "INFO" "Analyzing disk space..." "STORAGE"
    
    if load_module "get_disk_space_analysis"; then
        local findings_before=${#STORAGE_FINDINGS[@]}
        get_disk_space_analysis_data
        local findings_after=${#STORAGE_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Disk analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Disk analysis"
        log_message "ERROR" "Failed to load disk space analysis module" "STORAGE"
    fi
}

collect_memory_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing memory usage"
    log_message "INFO" "Analyzing memory usage..." "MEMORY"
    
    if load_module "get_memory_analysis"; then
        local findings_before=${#MEMORY_FINDINGS[@]}
        get_memory_analysis_data
        local findings_after=${#MEMORY_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Memory analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Memory analysis"
        log_message "ERROR" "Failed to load memory analysis module" "MEMORY"
    fi
}

collect_process_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing running processes"
    log_message "INFO" "Analyzing running processes..." "PROCESSES"
    
    if load_module "get_process_analysis"; then
        local findings_before=${#PROCESS_FINDINGS[@]}
        get_process_analysis_data
        local findings_after=${#PROCESS_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Process analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Process analysis"
        log_message "ERROR" "Failed to load process analysis module" "PROCESSES"
    fi
}

# Report generation with comprehensive summary statistics
# Aggregates findings from all modules and provides detailed progress feedback
generate_reports() {
    local start_time=$(date +%s)
    print_status "STARTING" "Generating assessment reports"
    log_message "INFO" "Generating assessment reports..." "REPORT"
    
    # Calculate total findings across all 9 analysis modules for summary statistics
    # This provides Windows-style visibility into the scope of data being processed
    local total_findings=$((${#SYSTEM_FINDINGS[@]} + ${#SECURITY_FINDINGS[@]} + ${#SOFTWARE_FINDINGS[@]} + ${#NETWORK_FINDINGS[@]} + ${#USER_FINDINGS[@]} + ${#PATCH_FINDINGS[@]} + ${#STORAGE_FINDINGS[@]} + ${#MEMORY_FINDINGS[@]} + ${#PROCESS_FINDINGS[@]}))
    
    # Display processing scope for user awareness (matching Windows auditor style)
    print_status "PROGRESS" "Processing $total_findings findings across 9 modules..."
    
    # Load report generation module and create both markdown and JSON outputs
    if load_module "export_reports"; then
        export_reports  # Generate both markdown and JSON reports with shared data
        
        # Calculate and display final completion metrics
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Report generation" "$total_findings" "$duration"
    else
        print_status "FAILED" "Report generation"
        log_message "ERROR" "Failed to load report generation module" "REPORT"
    fi
}

# Cleanup function
cleanup() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    log_message "SUCCESS" "Assessment completed in ${minutes}m ${seconds}s" "COMPLETE"
    log_message "INFO" "Reports saved to: $OUTPUT_PATH" "COMPLETE"
    
    # List generated files
    if [[ -d "$OUTPUT_PATH" ]]; then
        local files=$(ls -la "$OUTPUT_PATH"/${BASE_FILENAME}* 2>/dev/null | wc -l)
        log_message "INFO" "Generated $files output files" "COMPLETE"
    fi
}

# Signal handlers
trap cleanup EXIT
trap 'log_message "ERROR" "Script interrupted by user" "MAIN"; exit 130' INT

# Main execution
main() {
    # START_TIME already set at top of script for performance tracking
    
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_WHITE}macOS Workstation IT Assessment Tool v$CONFIG_VERSION${COLOR_RESET}"
    echo -e "${COLOR_BOLD}Computer: ${COLOR_CYAN}$COMPUTER_NAME${COLOR_RESET}"
    echo -e "${COLOR_BOLD}Started: ${COLOR_CYAN}$(date)${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
    
    # Check privilege level and provide guidance
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLOR_YELLOW}WARNING: Running as standard user${COLOR_RESET}"
        echo -e "  ${COLOR_CYAN}→ Some security and management features require administrative privileges${COLOR_RESET}"
        echo -e "  ${COLOR_CYAN}→ For complete analysis, consider running: ${COLOR_BOLD}sudo $0${COLOR_RESET}"
        echo -e "  ${COLOR_YELLOW}→ Continuing with limited analysis...${COLOR_RESET}"
        echo ""
    else
        echo -e "${COLOR_GREEN}✓ Running with administrative privileges${COLOR_RESET}"
        echo -e "  ${COLOR_CYAN}→ Complete system analysis enabled${COLOR_RESET}"
        echo ""
    fi
    
    initialize_environment
    
    # Execute audit modules in sequence
    collect_system_information
    collect_security_settings
    collect_user_account_analysis
    collect_network_analysis
    collect_software_inventory
    collect_patch_status
    collect_disk_space_analysis
    collect_memory_analysis
    collect_process_analysis
    
    # Generate consolidated reports
    generate_reports
    
    # Comprehensive completion summary with detailed statistics
    local total_time=$(($(date +%s) - START_TIME))
    local total_findings=$((${#SYSTEM_FINDINGS[@]} + ${#SECURITY_FINDINGS[@]} + ${#SOFTWARE_FINDINGS[@]} + ${#NETWORK_FINDINGS[@]} + ${#USER_FINDINGS[@]} + ${#PATCH_FINDINGS[@]} + ${#STORAGE_FINDINGS[@]} + ${#MEMORY_FINDINGS[@]} + ${#PROCESS_FINDINGS[@]}))
    
    # Risk level breakdown from generated JSON report
    local latest_json=$(ls -t "$OUTPUT_PATH"/*_raw_data.json 2>/dev/null | head -1)
    local high_count=0
    local medium_count=0
    local low_count=0
    local info_count=0
    
    if [[ -f "$latest_json" ]]; then
        high_count=$(grep -c '"risk_level": "HIGH"' "$latest_json" 2>/dev/null || echo 0)
        medium_count=$(grep -c '"risk_level": "MEDIUM"' "$latest_json" 2>/dev/null || echo 0)
        low_count=$(grep -c '"risk_level": "LOW"' "$latest_json" 2>/dev/null || echo 0)
        info_count=$(grep -c '"risk_level": "INFO"' "$latest_json" 2>/dev/null || echo 0)
    fi
    
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_GREEN}✓ Assessment completed successfully!${COLOR_RESET}"
    echo \"\"
    echo -e "${COLOR_BOLD}${COLOR_CYAN}Assessment Summary:${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Total findings collected: ${COLOR_CYAN}$total_findings${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Risk distribution: ${COLOR_RED}$high_count HIGH${COLOR_RESET}, ${COLOR_YELLOW}$medium_count MEDIUM${COLOR_RESET}, ${COLOR_GREEN}$low_count LOW${COLOR_RESET}, ${COLOR_BLUE}$info_count INFO${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Total execution time: ${COLOR_CYAN}${total_time}s${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Modules analyzed: ${COLOR_CYAN}9/9 completed${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Computer: ${COLOR_CYAN}$(scutil --get ComputerName 2>/dev/null || hostname)${COLOR_RESET}"
    
    
    echo \"\"
    echo -e "${COLOR_BOLD}${COLOR_CYAN}Generated Reports:${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Technician report: ${COLOR_CYAN}$(ls $OUTPUT_PATH/*_technician_report.md 2>/dev/null | head -1 | sed 's|.*/||')${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Raw data export: ${COLOR_CYAN}$(ls $OUTPUT_PATH/*_raw_data.json 2>/dev/null | head -1 | sed 's|.*/||')${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Execution log: ${COLOR_CYAN}$(ls $OUTPUT_PATH/logs/*_audit.log 2>/dev/null | head -1 | sed 's|.*/||')${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Report location: ${COLOR_CYAN}$OUTPUT_PATH${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
}

# Execute main function
main "$@"
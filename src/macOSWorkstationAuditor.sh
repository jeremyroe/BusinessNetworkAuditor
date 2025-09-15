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

# Helper function for colored progress output (matches Windows PowerShell colors)
print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        "STARTING")
            echo "${message}..."
            ;;
        "COMPLETE")
            echo -e "  ${COLOR_GREEN}→ ${message}: COMPLETE${COLOR_RESET}"
            ;;
        "FAILED")
            echo -e "  ${COLOR_RED}→ ${message}: FAILED${COLOR_RESET}"
            ;;
        "HEADER")
            echo -e "${COLOR_BOLD}${COLOR_BLUE}${message}${COLOR_RESET}"
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

# Data collection functions
collect_system_information() {
    print_status "STARTING" "Collecting system information"
    log_message "INFO" "Collecting system information..." "SYSTEM"
    
    # Load system information module
    if load_module "get_system_information"; then
        get_system_information_data
        print_status "COMPLETE" "System information"
    else
        print_status "FAILED" "System information"
        log_message "ERROR" "Failed to load system information module" "SYSTEM"
    fi
}

collect_security_settings() {
    print_status "STARTING" "Analyzing security settings"
    log_message "INFO" "Analyzing security settings..." "SECURITY"
    
    if load_module "get_security_settings"; then
        get_security_settings_data
        print_status "COMPLETE" "Security analysis"
    else
        print_status "FAILED" "Security analysis"
        log_message "ERROR" "Failed to load security settings module" "SECURITY"
    fi
}

collect_software_inventory() {
    print_status "STARTING" "Collecting software inventory"
    log_message "INFO" "Collecting software inventory..." "SOFTWARE"
    
    if load_module "get_software_inventory"; then
        get_software_inventory_data
        print_status "COMPLETE" "Software inventory"
    else
        print_status "FAILED" "Software inventory"
        log_message "ERROR" "Failed to load software inventory module" "SOFTWARE"
    fi
}

collect_network_analysis() {
    print_status "STARTING" "Analyzing network configuration"
    log_message "INFO" "Analyzing network configuration..." "NETWORK"
    
    if load_module "get_network_analysis"; then
        get_network_analysis_data
        print_status "COMPLETE" "Network analysis"
    else
        print_status "FAILED" "Network analysis"
        log_message "ERROR" "Failed to load network analysis module" "NETWORK"
    fi
}

collect_user_account_analysis() {
    print_status "STARTING" "Analyzing user accounts"
    log_message "INFO" "Analyzing user accounts..." "USERS"
    
    if load_module "get_user_account_analysis"; then
        get_user_account_analysis_data
        print_status "COMPLETE" "User account analysis"
    else
        print_status "FAILED" "User account analysis"
        log_message "ERROR" "Failed to load user account analysis module" "USERS"
    fi
}

collect_patch_status() {
    print_status "STARTING" "Checking patch status"
    log_message "INFO" "Checking patch status..." "PATCHING"
    
    if load_module "get_patch_status"; then
        get_patch_status_data
        print_status "COMPLETE" "Patch analysis"
    else
        print_status "FAILED" "Patch analysis"
        log_message "ERROR" "Failed to load patch status module" "PATCHING"
    fi
}

collect_disk_space_analysis() {
    print_status "STARTING" "Analyzing disk space"
    log_message "INFO" "Analyzing disk space..." "STORAGE"
    
    if load_module "get_disk_space_analysis"; then
        get_disk_space_analysis_data
        print_status "COMPLETE" "Disk analysis"
    else
        print_status "FAILED" "Disk analysis"
        log_message "ERROR" "Failed to load disk space analysis module" "STORAGE"
    fi
}

collect_memory_analysis() {
    print_status "STARTING" "Analyzing memory usage"
    log_message "INFO" "Analyzing memory usage..." "MEMORY"
    
    if load_module "get_memory_analysis"; then
        get_memory_analysis_data
        print_status "COMPLETE" "Memory analysis"
    else
        print_status "FAILED" "Memory analysis"
        log_message "ERROR" "Failed to load memory analysis module" "MEMORY"
    fi
}

collect_process_analysis() {
    print_status "STARTING" "Analyzing running processes"
    log_message "INFO" "Analyzing running processes..." "PROCESSES"
    
    if load_module "get_process_analysis"; then
        get_process_analysis_data
        print_status "COMPLETE" "Process analysis"
    else
        print_status "FAILED" "Process analysis"
        log_message "ERROR" "Failed to load process analysis module" "PROCESSES"
    fi
}

# Report generation
generate_reports() {
    echo "Generating assessment reports..."
    log_message "INFO" "Generating assessment reports..." "REPORT"
    
    # Load report generation module
    if load_module "export_reports"; then
        export_markdown_report
        export_raw_data_json
        print_status "COMPLETE" "Report generation"
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
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_WHITE}macOS Workstation IT Assessment Tool v$CONFIG_VERSION${COLOR_RESET}"
    echo -e "${COLOR_BOLD}Computer: ${COLOR_CYAN}$COMPUTER_NAME${COLOR_RESET}"
    echo -e "${COLOR_BOLD}Started: ${COLOR_CYAN}$(date)${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
    
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
    
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_GREEN}✓ Assessment completed successfully!${COLOR_RESET}"
    echo -e "${COLOR_BOLD}Reports saved to: ${COLOR_CYAN}$OUTPUT_PATH${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
}

# Execute main function
main "$@"
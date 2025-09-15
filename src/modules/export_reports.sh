#!/bin/bash

# macOSWorkstationAuditor - Report Export Module
# Version 1.0.0

# Global variables for report generation (bash 3.2 compatible)
ALL_FINDINGS=()
RISK_COUNT_HIGH=0
RISK_COUNT_MEDIUM=0
RISK_COUNT_LOW=0
RISK_COUNT_INFO=0

export_markdown_report() {
    log_message "INFO" "Generating technician report..." "REPORT"
    
    # Collect all findings from modules
    collect_all_findings
    
    # Generate technician report (matching Windows format)
    local report_file="$OUTPUT_PATH/${BASE_FILENAME}_technician_report.md"
    
    generate_markdown_header > "$report_file"
    generate_executive_summary >> "$report_file"
    generate_critical_action_items >> "$report_file"
    generate_additional_information >> "$report_file"
    generate_system_configuration >> "$report_file"
    generate_recommendations >> "$report_file"
    generate_markdown_footer >> "$report_file"
    
    log_message "SUCCESS" "Technician report generated: $report_file" "REPORT"
}

export_raw_data_json() {
    log_message "INFO" "Generating JSON raw data export..." "REPORT"
    
    local json_file="$OUTPUT_PATH/${BASE_FILENAME}_raw_data.json"
    
    # Generate JSON structure matching Windows version format
    cat > "$json_file" << EOF
{
  "metadata": {
    "computer_name": "$COMPUTER_NAME",
    "audit_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "tool_version": "$CONFIG_VERSION",
    "platform": "macOS",
    "os_version": "$(sw_vers -productVersion)",
    "os_build": "$(sw_vers -buildVersion)",
    "audit_duration_seconds": $(($(date +%s) - START_TIME))
  },
  "system_context": {
    "os_info": {
      "caption": "$(sw_vers -productName) $(sw_vers -productVersion)",
      "version": "$(sw_vers -productVersion)",
      "build_number": "$(sw_vers -buildVersion)",
      "architecture": "$(uname -m)",
      "last_boot_time": "$(date -r $(sysctl -n kern.boottime | awk '{print $4}' | tr -d ',') '+%Y-%m-%d %H:%M:%S')"
    },
    "hardware_info": {
      "model": "$(sysctl -n hw.model)",
      "total_memory_gb": $(echo "scale=2; $(sysctl -n hw.memsize) / 1073741824" | bc),
      "cpu_cores": $(sysctl -n hw.ncpu)
    },
    "domain": "$(hostname | cut -d. -f2- || echo 'WORKGROUP')",
    "computer_name": "$COMPUTER_NAME"
  },
  "compliance_framework": {
    "findings": [
EOF

    # Add all findings as JSON
    local first_finding=true
    for finding in "${ALL_FINDINGS[@]}"; do
        if [[ "$first_finding" == true ]]; then
            first_finding=false
        else
            echo "," >> "$json_file"
        fi
        
        # Parse JSON finding using native bash/sed/awk (no Python dependency)
        local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
        local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
        
        # Set defaults if parsing failed
        [[ -z "$category" ]] && category="Unknown"
        [[ -z "$item" ]] && item="Unknown"
        [[ -z "$value" ]] && value="Unknown"
        [[ -z "$risk_level" ]] && risk_level="INFO"
        
        # Generate finding ID
        local finding_id="macOS-$(echo "$category$item" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd '[:alnum:]-')"
        
        cat >> "$json_file" << EOF
      {
        "finding_id": "$finding_id",
        "category": "$category",
        "item": "$item",
        "value": "$value",
        "requirement": "$details",
        "risk_level": "$risk_level",
        "recommendation": "$recommendation",
        "framework": "macOS_Security_Assessment"
      }
EOF
    done

    cat >> "$json_file" << EOF
    ]
  },
  "summary": {
    "total_findings": ${#ALL_FINDINGS[@]},
    "risk_distribution": {
      "HIGH": $RISK_COUNT_HIGH,
      "MEDIUM": $RISK_COUNT_MEDIUM,
      "LOW": $RISK_COUNT_LOW,
      "INFO": $RISK_COUNT_INFO
    }
  }
}
EOF

    log_message "SUCCESS" "JSON raw data exported: $json_file" "REPORT"
}

collect_all_findings() {
    log_message "INFO" "Collecting findings from all modules..." "REPORT"
    
    # Initialize arrays and counters
    ALL_FINDINGS=()
    RISK_COUNT_HIGH=0
    RISK_COUNT_MEDIUM=0
    RISK_COUNT_LOW=0
    RISK_COUNT_INFO=0
    
    # Collect findings from each module if functions exist
    local module_functions=(
        "get_system_findings"
        "get_security_findings"
        "get_software_findings"
        "get_network_findings"
        "get_user_findings"
        "get_patch_findings"
        "get_disk_findings"
        "get_memory_findings"
        "get_process_findings"
    )
    
    for func in "${module_functions[@]}"; do
        if declare -f "$func" >/dev/null 2>&1; then
            log_message "INFO" "Collecting findings from $func..." "REPORT"
            while IFS= read -r finding; do
                if [[ -n "$finding" ]]; then
                    ALL_FINDINGS+=("$finding")
                    
                    # Count risk levels using native bash
                    local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                    [[ -z "$risk_level" ]] && risk_level="INFO"
                    case "$risk_level" in
                        "HIGH") ((RISK_COUNT_HIGH++)) ;;
                        "MEDIUM") ((RISK_COUNT_MEDIUM++)) ;;
                        "LOW") ((RISK_COUNT_LOW++)) ;;
                        *) ((RISK_COUNT_INFO++)) ;;
                    esac
                fi
            done < <($func 2>/dev/null || echo "")
        fi
    done
    
    log_message "SUCCESS" "Collected ${#ALL_FINDINGS[@]} total findings" "REPORT"
}

generate_markdown_header() {
    cat << EOF
# macOS Workstation Security Audit Report

**Computer:** $COMPUTER_NAME
**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Tool Version:** macOS Workstation Auditor v$CONFIG_VERSION

EOF
}

generate_executive_summary() {
    cat << EOF
## Executive Summary

| Risk Level | Count | Priority |
|------------|-------|----------|
| HIGH | $RISK_COUNT_HIGH | Immediate Action Required |
| MEDIUM | $RISK_COUNT_MEDIUM | Review and Plan Remediation |
| LOW | $RISK_COUNT_LOW | Monitor and Maintain |
| INFO | $RISK_COUNT_INFO | Informational |

EOF
}

generate_critical_action_items() {
    # Only generate this section if there are HIGH or MEDIUM risk items
    if [[ $RISK_COUNT_HIGH -gt 0 || $RISK_COUNT_MEDIUM -gt 0 ]]; then
        cat << EOF
## Critical Action Items

EOF
        
        if [[ $RISK_COUNT_HIGH -gt 0 ]]; then
            cat << EOF
### HIGH PRIORITY (Immediate Action Required)

EOF
            for finding in "${ALL_FINDINGS[@]}"; do
                local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                [[ -z "$finding_risk" ]] && finding_risk="INFO"
                
                if [[ "$finding_risk" == "HIGH" ]]; then
                    local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                    local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
                    local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                    local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                    local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
                    
                    [[ -z "$category" ]] && category="Unknown"
                    [[ -z "$item" ]] && item="Unknown"
                    [[ -z "$value" ]] && value="Unknown"
                    
                    cat << EOF
- **$category - $item:** $value
  - Details: $details
EOF
                    if [[ -n "$recommendation" ]]; then
                        cat << EOF
  - Recommendation: $recommendation
EOF
                    fi
                    echo ""
                fi
            done
        fi
        
        if [[ $RISK_COUNT_MEDIUM -gt 0 ]]; then
            cat << EOF
### MEDIUM PRIORITY (Review and Plan)

EOF
            for finding in "${ALL_FINDINGS[@]}"; do
                local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                [[ -z "$finding_risk" ]] && finding_risk="INFO"
                
                if [[ "$finding_risk" == "MEDIUM" ]]; then
                    local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                    local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
                    local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                    local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                    local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
                    
                    [[ -z "$category" ]] && category="Unknown"
                    [[ -z "$item" ]] && item="Unknown"
                    [[ -z "$value" ]] && value="Unknown"
                    
                    cat << EOF
- **$category - $item:** $value
  - Details: $details
EOF
                    if [[ -n "$recommendation" ]]; then
                        cat << EOF
  - Recommendation: $recommendation
EOF
                    fi
                    echo ""
                fi
            done
        fi
    fi
}

generate_additional_information() {
    # Get LOW and INFO items, grouped by category, excluding categories that appear in Critical Action Items
    local additional_items=()
    local critical_categories=()
    
    # First, collect categories that appear in HIGH/MEDIUM findings
    for finding in "${ALL_FINDINGS[@]}"; do
        local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        [[ -z "$finding_risk" ]] && finding_risk="INFO"
        
        if [[ "$finding_risk" == "HIGH" || "$finding_risk" == "MEDIUM" ]]; then
            local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
            [[ -n "$category" ]] && critical_categories+=("$category")
        fi
    done
    
    # Collect LOW and INFO items not in critical categories
    for finding in "${ALL_FINDINGS[@]}"; do
        local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        [[ -z "$finding_risk" ]] && finding_risk="INFO"
        
        if [[ "$finding_risk" == "LOW" || "$finding_risk" == "INFO" ]]; then
            local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
            
            # Check if this category appears in critical findings
            local is_critical_category=false
            for crit_cat in "${critical_categories[@]}"; do
                if [[ "$category" == "$crit_cat" ]]; then
                    is_critical_category=true
                    break
                fi
            done
            
            if [[ "$is_critical_category" == false ]]; then
                additional_items+=("$finding")
            fi
        fi
    done
    
    if [[ ${#additional_items[@]} -gt 0 ]]; then
        cat << EOF
## Additional Information

EOF
        
        # Group by category
        local categories=()
        for finding in "${additional_items[@]}"; do
            local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
            [[ -z "$category" ]] && category="Unknown"
            
            # Add to categories if not already present
            local category_exists=false
            for existing_cat in "${categories[@]}"; do
                if [[ "$existing_cat" == "$category" ]]; then
                    category_exists=true
                    break
                fi
            done
            [[ "$category_exists" == false ]] && categories+=("$category")
        done
        
        # Sort and output categories
        for category in $(printf '%s\n' "${categories[@]}" | sort); do
            cat << EOF
### $category

EOF
            
            for finding in "${additional_items[@]}"; do
                local finding_category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                [[ -z "$finding_category" ]] && finding_category="Unknown"
                
                if [[ "$finding_category" == "$category" ]]; then
                    local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
                    local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                    local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                    local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
                    local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                    
                    [[ -z "$item" ]] && item="Unknown"
                    [[ -z "$value" ]] && value="Unknown"
                    [[ -z "$risk_level" ]] && risk_level="INFO"
                    
                    local risk_icon="[INFO]"
                    [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
                    
                    cat << EOF
**$risk_icon $item:** $value

- **Details:** $details
EOF
                    if [[ -n "$recommendation" ]]; then
                        cat << EOF
- **Recommendation:** $recommendation
EOF
                    fi
                    echo ""
                fi
            done
        done
    fi
}

generate_system_configuration() {
    cat << EOF
## System Configuration Details

EOF
    
    # Get system information findings
    for finding in "${ALL_FINDINGS[@]}"; do
        local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
        
        if [[ "$category" == "System" ]]; then
            local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            
            [[ -z "$item" ]] && item="Unknown"
            [[ -z "$value" ]] && value="Unknown"
            
            cat << EOF
- **$item:** $value - $details
EOF
        fi
    done
    echo ""
}

generate_recommendations() {
    # Collect all recommendations from findings
    local recommendations=()
    local rec_counts=()
    
    for finding in "${ALL_FINDINGS[@]}"; do
        local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
        
        if [[ -n "$recommendation" && "$recommendation" != "" ]]; then
            # Check if this recommendation already exists
            local rec_exists=false
            local rec_index=0
            
            for i in "${!recommendations[@]}"; do
                if [[ "${recommendations[$i]}" == "$recommendation" ]]; then
                    rec_exists=true
                    rec_index=$i
                    break
                fi
            done
            
            if [[ "$rec_exists" == true ]]; then
                # Increment count
                rec_counts[$rec_index]=$((${rec_counts[$rec_index]} + 1))
            else
                # Add new recommendation
                recommendations+=("$recommendation")
                rec_counts+=(1)
            fi
        fi
    done
    
    if [[ ${#recommendations[@]} -gt 0 ]]; then
        cat << EOF
## Recommendations

EOF
        
        for i in "${!recommendations[@]}"; do
            cat << EOF
- **${recommendations[$i]}**
  - Affected Items: ${rec_counts[$i]}

EOF
        done
    fi
}

generate_markdown_footer() {
    cat << EOF
---

*This report was generated by macOS Workstation Auditor v$CONFIG_VERSION*

*For detailed data analysis and aggregation, refer to the corresponding JSON export.*

EOF
}

# Main report export functions called by the main script
export_reports() {
    export_markdown_report
    export_raw_data_json
}
#!/bin/bash

# macOSWorkstationAuditor - Network Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a NETWORK_FINDINGS=()

get_network_analysis_data() {
    log_message "INFO" "Analyzing network configuration..." "NETWORK"
    
    # Initialize findings array
    NETWORK_FINDINGS=()
    
    # Check network interfaces
    check_network_interfaces
    
    # Check WiFi configuration
    check_wifi_configuration
    
    # Check DNS settings
    check_dns_configuration
    
    # Check active network connections
    check_network_connections
    
    # Check network sharing services
    check_network_sharing
    
    # Check VPN connections
    check_vpn_connections
    
    log_message "SUCCESS" "Network analysis completed - ${#NETWORK_FINDINGS[@]} findings" "NETWORK"
}

check_network_interfaces() {
    log_message "INFO" "Checking network interfaces..." "NETWORK"
    
    # Get network interface information
    local interfaces=$(networksetup -listallhardwareports 2>/dev/null)
    local active_interfaces=0
    local ethernet_found=false
    local wifi_found=false
    
    # Count active network interfaces
    while IFS= read -r line; do
        if echo "$line" | grep -q "Device:"; then
            local device=$(echo "$line" | awk '{print $2}')
            if ifconfig "$device" 2>/dev/null | grep -q "status: active"; then
                ((active_interfaces++))
                if echo "$line" | grep -qi "ethernet"; then
                    ethernet_found=true
                elif echo "$line" | grep -qi "wi-fi"; then
                    wifi_found=true
                fi
            fi
        fi
    done <<< "$interfaces"
    
    # Report interface status
    local interface_details=""
    if [[ "$ethernet_found" == true && "$wifi_found" == true ]]; then
        interface_details="Both Ethernet and Wi-Fi active"
    elif [[ "$ethernet_found" == true ]]; then
        interface_details="Ethernet connection active"
    elif [[ "$wifi_found" == true ]]; then
        interface_details="Wi-Fi connection active"
    else
        interface_details="Connection type unknown"
    fi
    
    add_network_finding "Network" "Active Interfaces" "$active_interfaces" "$interface_details" "INFO" ""
    
    # Get IP configuration for primary interface
    local primary_ip=$(route get default 2>/dev/null | grep interface | awk '{print $2}')
    if [[ -n "$primary_ip" ]]; then
        local ip_address=$(ifconfig "$primary_ip" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        local subnet_mask=$(ifconfig "$primary_ip" 2>/dev/null | grep "inet " | awk '{print $4}' | head -1)
        
        if [[ -n "$ip_address" ]]; then
            add_network_finding "Network" "Primary IP Address" "$ip_address" "Interface: $primary_ip, Mask: $subnet_mask" "INFO" ""
        fi
    fi
}

check_wifi_configuration() {
    log_message "INFO" "Checking Wi-Fi configuration..." "NETWORK"
    
    # Check if Wi-Fi is enabled
    local wifi_power=$(networksetup -getairportpower en0 2>/dev/null)
    local wifi_status="Unknown"
    
    if echo "$wifi_power" | grep -q "On"; then
        wifi_status="Enabled"
    elif echo "$wifi_power" | grep -q "Off"; then
        wifi_status="Disabled"
    fi
    
    add_network_finding "Network" "Wi-Fi Status" "$wifi_status" "Airport power status" "INFO" ""
    
    # Check current Wi-Fi network
    if [[ "$wifi_status" == "Enabled" ]]; then
        local current_ssid=$(networksetup -getairportnetwork en0 2>/dev/null | cut -d: -f2 | sed 's/^ *//')
        
        if [[ -n "$current_ssid" && "$current_ssid" != "You are not associated with an AirPort network." ]]; then
            # Check for open networks (security risk)
            local security_info=$(security find-generic-password -D "AirPort network password" -a "$current_ssid" -g 2>&1)
            local is_open=false
            
            if echo "$security_info" | grep -q "could not be found"; then
                is_open=true
            fi
            
            local risk_level="INFO"
            local recommendation=""
            
            if [[ "$is_open" == true ]]; then
                risk_level="HIGH"
                recommendation="Connected to open Wi-Fi network. Use VPN or avoid transmitting sensitive data"
            fi
            
            add_network_finding "Network" "Current Wi-Fi Network" "$current_ssid" "Currently connected SSID" "$risk_level" "$recommendation"
        fi
        
        # Check for saved networks (potential security exposure)
        local saved_networks=$(networksetup -listpreferredwirelessnetworks en0 2>/dev/null | grep -v "Preferred networks" | wc -l | tr -d ' ')
        
        local saved_risk="INFO"
        local saved_recommendation=""
        
        if [[ $saved_networks -gt 20 ]]; then
            saved_risk="LOW"
            saved_recommendation="Large number of saved Wi-Fi networks may pose security risk. Consider removing unused networks"
        fi
        
        add_network_finding "Network" "Saved Wi-Fi Networks" "$saved_networks networks" "Stored wireless network profiles" "$saved_risk" "$saved_recommendation"
    fi
}

check_dns_configuration() {
    log_message "INFO" "Checking DNS configuration..." "NETWORK"
    
    # Get DNS servers
    local dns_servers=$(scutil --dns 2>/dev/null | grep nameserver | awk '{print $3}' | sort -u | head -5)
    local dns_count=$(echo "$dns_servers" | wc -l | tr -d ' ')
    
    if [[ -n "$dns_servers" ]]; then
        local dns_list=$(echo "$dns_servers" | tr '\n' ', ' | sed 's/, $//')
        add_network_finding "Network" "DNS Servers" "$dns_count configured" "Servers: $dns_list" "INFO" ""
        
        # Check for common public DNS servers
        local public_dns=false
        while IFS= read -r dns; do
            case "$dns" in
                "8.8.8.8"|"8.8.4.4"|"1.1.1.1"|"1.0.0.1"|"208.67.222.222"|"208.67.220.220")
                    public_dns=true
                    break
                    ;;
            esac
        done <<< "$dns_servers"
        
        if [[ "$public_dns" == true ]]; then
            add_network_finding "Network" "Public DNS Detected" "Yes" "Using public DNS servers (Google, Cloudflare, etc.)" "LOW" "Consider using organization DNS servers for corporate networks"
        fi
    else
        add_network_finding "Network" "DNS Configuration" "Not Found" "Could not determine DNS configuration" "LOW" "Verify DNS settings are properly configured"
    fi
}

check_network_connections() {
    log_message "INFO" "Checking active network connections..." "NETWORK"
    
    # Check for listening services
    local listening_ports=$(netstat -an 2>/dev/null | grep LISTEN | wc -l | tr -d ' ')
    add_network_finding "Network" "Listening Services" "$listening_ports ports" "Services accepting network connections" "INFO" ""
    
    # Check for high-risk ports
    local risky_ports=("22" "23" "80" "443" "3389" "5900" "5901")
    local found_risky=()
    
    for port in "${risky_ports[@]}"; do
        if netstat -an 2>/dev/null | grep LISTEN | grep -q ":$port "; then
            case "$port" in
                "22") found_risky+=("SSH ($port)") ;;
                "23") found_risky+=("Telnet ($port)") ;;
                "80") found_risky+=("HTTP ($port)") ;;
                "443") found_risky+=("HTTPS ($port)") ;;
                "3389") found_risky+=("RDP ($port)") ;;
                "5900"|"5901") found_risky+=("VNC ($port)") ;;
            esac
        fi
    done
    
    if [[ ${#found_risky[@]} -gt 0 ]]; then
        local risky_list=$(IFS=", "; echo "${found_risky[*]}")
        local risk_level="MEDIUM"
        local recommendation="Review listening services for security implications. Disable unnecessary services"
        
        add_network_finding "Security" "High-Risk Listening Ports" "${#found_risky[@]} detected" "Found: $risky_list" "$risk_level" "$recommendation"
    fi
    
    # Check for established connections
    local established_connections=$(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l | tr -d ' ')
    add_network_finding "Network" "Established Connections" "$established_connections" "Active outbound network connections" "INFO" ""
}

check_network_sharing() {
    log_message "INFO" "Checking network sharing services..." "NETWORK"
    
    # Check common sharing services
    local sharing_services=(
        "Screen Sharing:ARDAgent"
        "File Sharing:AppleFileServer"
        "Remote Login:RemoteLogin"
        "Remote Management:ARDAgent"
        "Internet Sharing:InternetSharing"
        "Bluetooth Sharing:BluetoothSharing"
    )
    
    local enabled_sharing=()
    local risky_sharing=()
    
    for service in "${sharing_services[@]}"; do
        local service_name=$(echo "$service" | cut -d: -f1)
        local service_process=$(echo "$service" | cut -d: -f2)
        
        # Check if service is running
        if pgrep -f "$service_process" >/dev/null 2>&1; then
            enabled_sharing+=("$service_name")
            
            # Mark potentially risky services
            case "$service_name" in
                "Screen Sharing"|"Remote Login"|"Remote Management")
                    risky_sharing+=("$service_name")
                    ;;
            esac
        fi
    done
    
    if [[ ${#enabled_sharing[@]} -gt 0 ]]; then
        local sharing_list=$(IFS=", "; echo "${enabled_sharing[*]}")
        add_network_finding "Network" "Enabled Sharing Services" "${#enabled_sharing[@]} services" "Active: $sharing_list" "INFO" ""
        
        if [[ ${#risky_sharing[@]} -gt 0 ]]; then
            local risky_list=$(IFS=", "; echo "${risky_sharing[*]}")
            add_network_finding "Security" "Remote Access Services" "${#risky_sharing[@]} enabled" "Services: $risky_list" "MEDIUM" "Review remote access services for security and business justification"
        fi
    else
        add_network_finding "Network" "Sharing Services" "None Active" "No network sharing services detected" "INFO" ""
    fi
}

check_vpn_connections() {
    log_message "INFO" "Checking VPN connections..." "NETWORK"
    
    # Check for VPN interfaces
    local vpn_interfaces=$(ifconfig 2>/dev/null | grep -E "^(utun|ppp|ipsec)" | cut -d: -f1)
    local vpn_count=0
    local active_vpn=false
    
    while IFS= read -r interface; do
        if [[ -n "$interface" ]]; then
            ((vpn_count++))
            if ifconfig "$interface" 2>/dev/null | grep -q "inet"; then
                active_vpn=true
            fi
        fi
    done <<< "$vpn_interfaces"
    
    if [[ $vpn_count -gt 0 ]]; then
        local vpn_status="Configured"
        if [[ "$active_vpn" == true ]]; then
            vpn_status="Active"
        fi
        
        add_network_finding "Network" "VPN Configuration" "$vpn_status" "$vpn_count VPN interfaces found" "INFO" ""
    else
        add_network_finding "Network" "VPN Configuration" "None Detected" "No VPN interfaces found" "INFO" ""
    fi
    
    # Check for common VPN applications
    local vpn_apps=(
        "NordVPN.app"
        "ExpressVPN.app"
        "Tunnelblick.app"
        "Viscosity.app"
        "SurfShark.app"
        "CyberGhost.app"
        "Private Internet Access.app"
    )
    
    local found_vpn_apps=()
    for vpn_app in "${vpn_apps[@]}"; do
        if [[ -d "/Applications/$vpn_app" ]]; then
            local app_name=$(basename "$vpn_app" .app)
            found_vpn_apps+=("$app_name")
        fi
    done
    
    if [[ ${#found_vpn_apps[@]} -gt 0 ]]; then
        local vpn_app_list=$(IFS=", "; echo "${found_vpn_apps[*]}")
        add_network_finding "Network" "VPN Applications" "${#found_vpn_apps[@]} installed" "Found: $vpn_app_list" "INFO" ""
    fi
}

# Helper function to add network findings to the array
add_network_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    NETWORK_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_network_findings() {
    printf '%s\n' "${NETWORK_FINDINGS[@]}"
}
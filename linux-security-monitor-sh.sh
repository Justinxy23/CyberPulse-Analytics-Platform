#!/bin/bash

# CyberPulse Analytics Platform - Linux Security Monitor
# Author: Justin Christopher Weaver
# Description: Comprehensive Linux security monitoring and auditing script
# Compatible with: Ubuntu, Debian, RHEL, CentOS, Fedora

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_VERSION="1.0.0"
SCAN_TYPE="${1:-standard}"
OUTPUT_DIR="${2:-./security_audit_$(date +%Y%m%d_%H%M%S)}"
API_ENDPOINT="${CYBERPULSE_API:-http://localhost:8080/api/v1/audit}"
HOSTNAME=$(hostname)
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Security score (starts at 100)
SECURITY_SCORE=100

# Findings array
declare -a FINDINGS
declare -a CRITICAL_FINDINGS
declare -a HIGH_FINDINGS
declare -a MEDIUM_FINDINGS
declare -a LOW_FINDINGS

# Create output directory
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/security_audit.log"

# ASCII Banner
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║           CyberPulse Linux Security Monitor v1.0              ║
║                  Author: Justin C. Weaver                     ║
╚═══════════════════════════════════════════════════════════════╝
EOF

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO")
            echo -e "${BLUE}[*]${NC} $message"
            ;;
        "OK")
            echo -e "${GREEN}[+]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[!]${NC} $message"
            ;;
        "CRITICAL")
            echo -e "${RED}[!!!]${NC} $message"
            ;;
    esac
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$status] $message" >> "$LOG_FILE"
}

# Add finding to results
add_finding() {
    local severity=$1
    local category=$2
    local finding=$3
    local recommendation=$4
    
    local finding_json=$(cat <<EOF
{
    "severity": "$severity",
    "category": "$category",
    "finding": "$finding",
    "recommendation": "$recommendation",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
)
    
    FINDINGS+=("$finding_json")
    
    case $severity in
        "CRITICAL")
            CRITICAL_FINDINGS+=("$finding")
            SECURITY_SCORE=$((SECURITY_SCORE - 10))
            print_status "CRITICAL" "$finding"
            ;;
        "HIGH")
            HIGH_FINDINGS+=("$finding")
            SECURITY_SCORE=$((SECURITY_SCORE - 5))
            print_status "WARNING" "$finding"
            ;;
        "MEDIUM")
            MEDIUM_FINDINGS+=("$finding")
            SECURITY_SCORE=$((SECURITY_SCORE - 2))
            print_status "WARNING" "$finding"
            ;;
        "LOW")
            LOW_FINDINGS+=("$finding")
            SECURITY_SCORE=$((SECURITY_SCORE - 1))
            print_status "INFO" "$finding"
            ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "WARNING" "Not running as root. Some checks may be limited."
        return 1
    fi
    return 0
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    print_status "INFO" "Detected OS: $OS $VER"
    echo "$OS|$VER" > "$OUTPUT_DIR/system_info.txt"
}

# System information gathering
gather_system_info() {
    print_status "INFO" "Gathering system information..."
    
    {
        echo "=== System Information ==="
        echo "Hostname: $HOSTNAME"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
        echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
        echo "Uptime: $(uptime -p)"
        echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
        echo "SELinux Status: $(getenforce 2>/dev/null || echo 'Not installed')"
        echo "AppArmor Status: $(aa-status 2>/dev/null | grep -m1 'profiles are loaded' || echo 'Not installed')"
    } > "$OUTPUT_DIR/system_info_detailed.txt"
}

# Check kernel version and known vulnerabilities
check_kernel_vulnerabilities() {
    print_status "INFO" "Checking kernel vulnerabilities..."
    
    local kernel_version=$(uname -r)
    
    # Check for old kernel versions
    local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
    
    if [ "$kernel_major" -lt 5 ] || ([ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -lt 10 ]); then
        add_finding "HIGH" "Kernel" "Outdated kernel version: $kernel_version" \
            "Update to the latest stable kernel version"
    fi
    
    # Check for specific vulnerability mitigations
    if [ -r /sys/devices/system/cpu/vulnerabilities/spectre_v1 ]; then
        for vuln in /sys/devices/system/cpu/vulnerabilities/*; do
            local vuln_name=$(basename "$vuln")
            local vuln_status=$(cat "$vuln" 2>/dev/null || echo "Unknown")
            
            if [[ "$vuln_status" == *"Vulnerable"* ]]; then
                add_finding "HIGH" "CPU Vulnerability" \
                    "CPU vulnerable to $vuln_name: $vuln_status" \
                    "Apply kernel updates or microcode updates"
            fi
            
            echo "$vuln_name: $vuln_status" >> "$OUTPUT_DIR/cpu_vulnerabilities.txt"
        done
    fi
}

# User and authentication checks
check_users_auth() {
    print_status "INFO" "Checking user accounts and authentication..."
    
    # Check for users with UID 0 (root privileges)
    local root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    if [ $(echo "$root_users" | wc -l) -gt 1 ]; then
        add_finding "CRITICAL" "Users" \
            "Multiple users with UID 0: $root_users" \
            "Only root should have UID 0"
    fi
    
    # Check for users without passwords
    if [ -r /etc/shadow ]; then
        local no_pass_users=$(awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow | grep -v '^$')
        if [ -n "$no_pass_users" ]; then
            for user in $no_pass_users; do
                # Check if user has a shell
                local user_shell=$(getent passwd "$user" | cut -d: -f7)
                if [[ "$user_shell" != "/sbin/nologin" && "$user_shell" != "/bin/false" ]]; then
                    add_finding "HIGH" "Users" \
                        "User '$user' has no password but has shell access" \
                        "Set a strong password or disable the account"
                fi
            done
        fi
    fi
    
    # Check password aging
    if [ -r /etc/login.defs ]; then
        local pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        local pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
        local pass_warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
        
        if [ "$pass_max_days" -gt 90 ] || [ "$pass_max_days" -eq 99999 ]; then
            add_finding "MEDIUM" "Password Policy" \
                "Password maximum age is $pass_max_days days" \
                "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs"
        fi
    fi
    
    # Check sudo configuration
    if [ -f /etc/sudoers ]; then
        # Check for NOPASSWD entries
        if grep -E "NOPASSWD|!authenticate" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#'; then
            add_finding "HIGH" "Sudo" \
                "NOPASSWD sudo entries found" \
                "Review and remove unnecessary NOPASSWD entries"
        fi
    fi
}

# SSH configuration audit
check_ssh_config() {
    print_status "INFO" "Auditing SSH configuration..."
    
    if [ -f /etc/ssh/sshd_config ]; then
        local ssh_config="/etc/ssh/sshd_config"
        
        # Check root login
        if grep -E "^PermitRootLogin\s+yes" "$ssh_config" >/dev/null 2>&1; then
            add_finding "HIGH" "SSH" \
                "SSH root login is enabled" \
                "Set 'PermitRootLogin no' in sshd_config"
        fi
        
        # Check password authentication
        if ! grep -E "^PasswordAuthentication\s+no" "$ssh_config" >/dev/null 2>&1; then
            add_finding "MEDIUM" "SSH" \
                "SSH password authentication is enabled" \
                "Use key-based authentication and disable passwords"
        fi
        
        # Check SSH protocol version
        if grep -E "^Protocol\s+1" "$ssh_config" >/dev/null 2>&1; then
            add_finding "CRITICAL" "SSH" \
                "SSH Protocol 1 is enabled" \
                "Use only SSH Protocol 2"
        fi
        
        # Check empty passwords
        if grep -E "^PermitEmptyPasswords\s+yes" "$ssh_config" >/dev/null 2>&1; then
            add_finding "CRITICAL" "SSH" \
                "SSH permits empty passwords" \
                "Set 'PermitEmptyPasswords no'"
        fi
        
        # Check SSH keys
        local weak_keys=$(find /home /root -name "id_rsa" -o -name "id_dsa" 2>/dev/null | while read key; do
            if [ -f "$key" ]; then
                local perms=$(stat -c %a "$key" 2>/dev/null)
                if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
                    echo "$key"
                fi
            fi
        done)
        
        if [ -n "$weak_keys" ]; then
            add_finding "HIGH" "SSH" \
                "SSH private keys with weak permissions found" \
                "Set permissions to 600 for private keys"
        fi
    fi
}

# Network security checks
check_network_security() {
    print_status "INFO" "Checking network security..."
    
    # Check for listening services
    local listening_ports=$(ss -tlnp 2>/dev/null | grep LISTEN || netstat -tlnp 2>/dev/null | grep LISTEN)
    echo "$listening_ports" > "$OUTPUT_DIR/listening_ports.txt"
    
    # Check for common vulnerable ports
    local vulnerable_ports=(23 111 139 445 3389 5900 6379 27017 9200)
    for port in "${vulnerable_ports[@]}"; do
        if echo "$listening_ports" | grep -q ":$port "; then
            case $port in
                23) service="Telnet" ;;
                111) service="RPC" ;;
                139|445) service="SMB/NetBIOS" ;;
                3389) service="RDP" ;;
                5900) service="VNC" ;;
                6379) service="Redis" ;;
                27017) service="MongoDB" ;;
                9200) service="Elasticsearch" ;;
            esac
            add_finding "HIGH" "Network" \
                "Potentially vulnerable service $service listening on port $port" \
                "Disable or secure the service, use firewall rules"
        fi
    done
    
    # Check IP forwarding
    if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]; then
        add_finding "MEDIUM" "Network" \
            "IP forwarding is enabled" \
            "Disable if not required: sysctl -w net.ipv4.ip_forward=0"
    fi
    
    # Check for promiscuous mode
    local promisc_interfaces=$(ip link show | grep -B1 PROMISC | grep -E "^[0-9]+:" | cut -d: -f2)
    if [ -n "$promisc_interfaces" ]; then
        add_finding "HIGH" "Network" \
            "Network interfaces in promiscuous mode: $promisc_interfaces" \
            "Investigate why promiscuous mode is enabled"
    fi
}

# Firewall checks
check_firewall() {
    print_status "INFO" "Checking firewall configuration..."
    
    # Check iptables
    if command -v iptables >/dev/null 2>&1; then
        local iptables_rules=$(iptables -L -n 2>/dev/null | grep -c "^Chain")
        if [ "$iptables_rules" -le 3 ]; then
            add_finding "HIGH" "Firewall" \
                "iptables has minimal or no rules configured" \
                "Configure iptables rules or use UFW/firewalld"
        fi
    fi
    
    # Check UFW (Ubuntu)
    if command -v ufw >/dev/null 2>&1; then
        local ufw_status=$(ufw status | grep -i "status:" | awk '{print $2}')
        if [ "$ufw_status" != "active" ]; then
            add_finding "HIGH" "Firewall" \
                "UFW firewall is not active" \
                "Enable UFW: ufw enable"
        fi
    fi
    
    # Check firewalld (RHEL/CentOS)
    if command -v firewall-cmd >/dev/null 2>&1; then
        if ! systemctl is-active firewalld >/dev/null 2>&1; then
            add_finding "HIGH" "Firewall" \
                "firewalld is not running" \
                "Start and enable firewalld"
        fi
    fi
}

# Check running processes
check_processes() {
    print_status "INFO" "Analyzing running processes..."
    
    # Check for suspicious processes
    local suspicious_processes=$(ps aux | grep -E "(nc |netcat|nmap|tcpdump|wireshark)" | grep -v grep)
    if [ -n "$suspicious_processes" ]; then
        add_finding "MEDIUM" "Processes" \
            "Potentially suspicious processes detected" \
            "Review running processes for unauthorized tools"
    fi
    
    # Check for deleted binaries still running
    local deleted_binaries=$(ls -l /proc/*/exe 2>/dev/null | grep deleted)
    if [ -n "$deleted_binaries" ]; then
        add_finding "HIGH" "Processes" \
            "Processes running from deleted binaries detected" \
            "Investigate processes running deleted executables"
    fi
    
    # Save process list
    ps auxf > "$OUTPUT_DIR/process_list.txt"
}

# File system checks
check_filesystem() {
    print_status "INFO" "Checking file system security..."
    
    # Check for world-writable files
    local world_writable=$(find / -xdev -type f -perm -0002 2>/dev/null | head -20)
    if [ -n "$world_writable" ]; then
        local count=$(echo "$world_writable" | wc -l)
        add_finding "MEDIUM" "Filesystem" \
            "Found $count world-writable files" \
            "Review and fix permissions on world-writable files"
        echo "$world_writable" > "$OUTPUT_DIR/world_writable_files.txt"
    fi
    
    # Check for SUID/SGID files
    local suid_files=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
    echo "$suid_files" > "$OUTPUT_DIR/suid_sgid_files.txt"
    
    # Check for unusual SUID binaries
    local expected_suid="/usr/bin/sudo|/usr/bin/passwd|/usr/bin/su|/bin/mount|/bin/ping"
    local unusual_suid=$(echo "$suid_files" | grep -vE "$expected_suid")
    if [ -n "$unusual_suid" ]; then
        add_finding "HIGH" "Filesystem" \
            "Unusual SUID/SGID binaries found" \
            "Review unexpected SUID/SGID files for security risks"
    fi
    
    # Check /tmp permissions
    local tmp_perms=$(stat -c %a /tmp 2>/dev/null)
    if [ "$tmp_perms" != "1777" ]; then
        add_finding "MEDIUM" "Filesystem" \
            "/tmp has incorrect permissions: $tmp_perms" \
            "Set /tmp permissions to 1777"
    fi
}

# Check for rootkits
check_rootkits() {
    print_status "INFO" "Checking for rootkits..."
    
    # Basic rootkit checks
    # Check for hidden processes
    local ps_count=$(ps aux | wc -l)
    local proc_count=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
    
    if [ $((proc_count - ps_count)) -gt 5 ]; then
        add_finding "CRITICAL" "Rootkit" \
            "Possible hidden processes detected" \
            "Run comprehensive rootkit scanner (rkhunter/chkrootkit)"
    fi
    
    # Check for kernel module hiding
    if [ -f /proc/modules ]; then
        local lsmod_count=$(lsmod | wc -l)
        local proc_modules_count=$(wc -l < /proc/modules)
        
        if [ "$lsmod_count" -ne "$proc_modules_count" ]; then
            add_finding "HIGH" "Rootkit" \
                "Kernel module count mismatch" \
                "Possible kernel-level rootkit activity"
        fi
    fi
}

# Check system logs
check_logs() {
    print_status "INFO" "Analyzing system logs..."
    
    # Check for authentication failures
    local auth_log="/var/log/auth.log"
    [ ! -f "$auth_log" ] && auth_log="/var/log/secure"
    
    if [ -f "$auth_log" ]; then
        local failed_logins=$(grep -i "failed\|failure" "$auth_log" 2>/dev/null | tail -100 | wc -l)
        if [ "$failed_logins" -gt 50 ]; then
            add_finding "HIGH" "Logs" \
                "High number of authentication failures: $failed_logins in recent logs" \
                "Investigate failed login attempts, consider fail2ban"
        fi
        
        # Check for successful root logins
        local root_logins=$(grep "Accepted.*for root" "$auth_log" 2>/dev/null | tail -20)
        if [ -n "$root_logins" ]; then
            add_finding "MEDIUM" "Logs" \
                "Direct root logins detected" \
                "Use sudo instead of direct root login"
        fi
    fi
}

# Check package management
check_packages() {
    print_status "INFO" "Checking package management..."
    
    # Check for available updates
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1
        local updates=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst")
        if [ "$updates" -gt 0 ]; then
            local security_updates=$(apt-get -s upgrade 2>/dev/null | grep -c "Security")
            if [ "$security_updates" -gt 0 ]; then
                add_finding "HIGH" "Packages" \
                    "$security_updates security updates available" \
                    "Install security updates immediately"
            else
                add_finding "MEDIUM" "Packages" \
                    "$updates package updates available" \
                    "Keep system packages up to date"
            fi
        fi
    elif command -v yum >/dev/null 2>&1; then
        local updates=$(yum check-update 2>/dev/null | grep -v "^$" | tail -n +3 | wc -l)
        if [ "$updates" -gt 0 ]; then
            add_finding "MEDIUM" "Packages" \
                "$updates package updates available" \
                "Keep system packages up to date"
        fi
    fi
}

# Generate JSON report
generate_json_report() {
    print_status "INFO" "Generating JSON report..."
    
    # Ensure score doesn't go below 0
    [ $SECURITY_SCORE -lt 0 ] && SECURITY_SCORE=0
    
    cat > "$OUTPUT_DIR/security_audit.json" <<EOF
{
    "scan_info": {
        "hostname": "$HOSTNAME",
        "scan_type": "$SCAN_TYPE",
        "timestamp": "$SCAN_TIMESTAMP",
        "version": "$SCRIPT_VERSION"
    },
    "security_score": $SECURITY_SCORE,
    "summary": {
        "critical": ${#CRITICAL_FINDINGS[@]},
        "high": ${#HIGH_FINDINGS[@]},
        "medium": ${#MEDIUM_FINDINGS[@]},
        "low": ${#LOW_FINDINGS[@]}
    },
    "findings": [
$(printf '%s\n' "${FINDINGS[@]}" | paste -sd',')
    ]
}
EOF
}

# Generate HTML report
generate_html_report() {
    print_status "INFO" "Generating HTML report..."
    
    cat > "$OUTPUT_DIR/security_audit.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>CyberPulse Linux Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #1a1f3a; color: white; padding: 20px; border-radius: 10px; }
        .score { font-size: 72px; font-weight: bold; text-align: center; margin: 20px; }
        .score.good { color: #10b981; }
        .score.warning { color: #f59e0b; }
        .score.bad { color: #ef4444; }
        .summary { display: flex; justify-content: space-around; margin: 20px 0; }
        .summary-item { text-align: center; padding: 20px; background: white; border-radius: 10px; }
        .findings { background: white; padding: 20px; border-radius: 10px; margin-top: 20px; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid; }
        .finding.CRITICAL { border-color: #ef4444; background-color: #fee; }
        .finding.HIGH { border-color: #f59e0b; background-color: #fef3c7; }
        .finding.MEDIUM { border-color: #3b82f6; background-color: #dbeafe; }
        .finding.LOW { border-color: #10b981; background-color: #d1fae5; }
    </style>
</head>
<body>
    <div class="header">
        <h1>CyberPulse Linux Security Audit Report</h1>
        <p>Host: $HOSTNAME | Date: $SCAN_TIMESTAMP</p>
    </div>
    
    <div class="score $([ $SECURITY_SCORE -ge 80 ] && echo 'good' || ([ $SECURITY_SCORE -ge 60 ] && echo 'warning' || echo 'bad'))">
        $SECURITY_SCORE/100
    </div>
    
    <div class="summary">
        <div class="summary-item">
            <h3>Critical</h3>
            <div style="font-size: 36px; color: #ef4444;">${#CRITICAL_FINDINGS[@]}</div>
        </div>
        <div class="summary-item">
            <h3>High</h3>
            <div style="font-size: 36px; color: #f59e0b;">${#HIGH_FINDINGS[@]}</div>
        </div>
        <div class="summary-item">
            <h3>Medium</h3>
            <div style="font-size: 36px; color: #3b82f6;">${#MEDIUM_FINDINGS[@]}</div>
        </div>
        <div class="summary-item">
            <h3>Low</h3>
            <div style="font-size: 36px; color: #10b981;">${#LOW_FINDINGS[@]}</div>
        </div>
    </div>
    
    <div class="findings">
        <h2>Security Findings</h2>
EOF

    # Add findings to HTML
    for finding in "${FINDINGS[@]}"; do
        local severity=$(echo "$finding" | grep -oP '"severity":\s*"\K[^"]+')
        local category=$(echo "$finding" | grep -oP '"category":\s*"\K[^"]+')
        local desc=$(echo "$finding" | grep -oP '"finding":\s*"\K[^"]+')
        local rec=$(echo "$finding" | grep -oP '"recommendation":\s*"\K[^"]+')
        
        cat >> "$OUTPUT_DIR/security_audit.html" <<EOF
        <div class="finding $severity">
            <strong>[$severity]</strong> $desc<br>
            <small>Category: $category</small><br>
            <em>Recommendation: $rec</em>
        </div>
EOF
    done
    
    echo "</div></body></html>" >> "$OUTPUT_DIR/security_audit.html"
}

# Main execution
main() {
    log "Starting CyberPulse Linux Security Monitor v$SCRIPT_VERSION"
    log "Scan type: $SCAN_TYPE"
    
    # Check if running as root
    check_root
    
    # Detect distribution
    detect_distro
    
    # Run security checks
    gather_system_info
    check_kernel_vulnerabilities
    check_users_auth
    check_ssh_config
    check_network_security
    check_firewall
    check_processes
    
    if [ "$SCAN_TYPE" != "quick" ]; then
        check_filesystem
        check_logs
        check_packages
    fi
    
    if [ "$SCAN_TYPE" == "comprehensive" ]; then
        check_rootkits
    fi
    
    # Generate reports
    generate_json_report
    generate_html_report
    
    # Display summary
    echo
    print_status "OK" "Security audit completed!"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "Security Score: $([ $SECURITY_SCORE -ge 80 ] && echo -e "${GREEN}$SECURITY_SCORE/100${NC}" || ([ $SECURITY_SCORE -ge 60 ] && echo -e "${YELLOW}$SECURITY_SCORE/100${NC}" || echo -e "${RED}$SECURITY_SCORE/100${NC}"))"
    echo -e "Critical Findings: ${RED}${#CRITICAL_FINDINGS[@]}${NC}"
    echo -e "High Findings: ${YELLOW}${#HIGH_FINDINGS[@]}${NC}"
    echo -e "Medium Findings: ${BLUE}${#MEDIUM_FINDINGS[@]}${NC}"
    echo -e "Low Findings: ${GREEN}${#LOW_FINDINGS[@]}${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo
    print_status "OK" "Reports saved to: $OUTPUT_DIR"
    
    # Optional: Send to API
    if [ -n "${SEND_TO_API:-}" ]; then
        print_status "INFO" "Sending results to API..."
        if command -v curl >/dev/null 2>&1; then
            curl -X POST -H "Content-Type: application/json" \
                -d @"$OUTPUT_DIR/security_audit.json" \
                "$API_ENDPOINT" >/dev/null 2>&1 && \
                print_status "OK" "Results sent to API" || \
                print_status "WARNING" "Failed to send results to API"
        fi
    fi
}

# Run main function
main "$@"
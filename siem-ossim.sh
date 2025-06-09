#!/bin/bash
# AlienVault OSSIM SIEM Script
# Automates log analysis and threat response

LOG_FILE="/var/log/siem-ossim.log"
ALERT_THRESHOLD=5
IP_BLACKLIST="/etc/ossim_blacklist.txt"

# Function to analyze logs for suspicious activity
analyze_logs() {
    echo "Analyzing logs for potential threats..."
    suspicious_ips=$(grep -E "AUTH_FAILURE|PORT_SCAN|MALWARE_ALERT|DDOS_ATTEMPT" "$LOG_FILE" | awk '{print $4}' | sort | uniq -c | awk '$1 >= '$ALERT_THRESHOLD' {print $2}')
    
    for ip in $suspicious_ips; do
        echo "Threat detected from IP: $ip"
        echo "$ip" >> "$IP_BLACKLIST"
        block_ip "$ip"
    done
}

# Function to block suspicious IPs
block_ip() {
    local ip=$1
    echo "Blocking IP: $ip"
    iptables -A INPUT -s "$ip" -j DROP
}

# Simulate log generation
generate_event() {
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    EVENT_TYPE=$1
    MESSAGE=$2
    IP=$3

    echo "$TIMESTAMP - $EVENT_TYPE - $MESSAGE - $IP" >> "$LOG_FILE"
    echo "[LOGGED] $TIMESTAMP - $EVENT_TYPE - $MESSAGE - $IP"
}

# Simulate security events
echo "Starting OSSIM SIEM event simulation..."
sleep 2

generate_event "AUTH_FAILURE" "User 'admin' failed to authenticate" "192.168.1.100"
generate_event "PORT_SCAN" "Multiple connection attempts detected" "203.0.113.45"
generate_event "MALWARE_ALERT" "Suspicious activity detected on server 'web01'" "198.51.100.23"
generate_event "DDOS_ATTEMPT" "High traffic volume detected" "203.0.113.45"
generate_event "PORT_SCAN" "Multiple connection attempts detected" "203.0.113.45"

# Analyze logs and take action
analyze_logs

echo "SIEM-OSSIM script execution complete."

exit 0
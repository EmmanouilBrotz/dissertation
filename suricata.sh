#!/bin/bash

################################################################################
# Suricata IDS/IPS Configuration Script
# Purpose: Configure Suricata for maximum network security monitoring
# Network: 192.168.10.0/24
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Suricata Configuration Script${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
   echo -e "${RED}Please run as root or with sudo${NC}"
   exit 1
fi

# Prompt for network interface
echo -e "${YELLOW}Enter your monitoring network interface (e.g., ens18, eth0):${NC}"
read -r INTERFACE

if [ -z "$INTERFACE" ]; then
    echo -e "${RED}No interface provided. Exiting.${NC}"
    exit 1
fi

# Verify interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${RED}Interface $INTERFACE not found!${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Using interface: $INTERFACE${NC}"

# Backup original config
BACKUP_DIR="/root/suricata_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp /etc/suricata/suricata.yaml "$BACKUP_DIR/" 2>/dev/null || true
echo -e "${YELLOW}[*] Original config backed up to: $BACKUP_DIR${NC}"

################################################################################
# Configure Suricata YAML
################################################################################
echo -e "${GREEN}[+] Configuring Suricata...${NC}"

cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---

# Suricata Configuration for 192.168.10.0/24 Network
# Optimized for IDS/IPS operation

vars:
  address-groups:
    HOME_NET: "[192.168.10.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    
    HTTP_SERVERS: "[192.168.10.50]"  # ELK Stack
    SMTP_SERVERS: "[$HOME_NET]"
    SQL_SERVERS: "[$HOME_NET]"
    DNS_SERVERS: "[192.168.10.1]"    # pfSense
    TELNET_SERVERS: "[$HOME_NET]"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "[$HOME_NET]"
    DNP3_SERVER: "[$HOME_NET]"
    DNP3_CLIENT: "[$HOME_NET]"
    MODBUS_CLIENT: "[$HOME_NET]"
    MODBUS_SERVER: "[$HOME_NET]"
    ENIP_CLIENT: "[$HOME_NET]"
    ENIP_SERVER: "[$HOME_NET]"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "80,110,143"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

# Default logging directory
default-log-dir: /var/log/suricata/

stats:
  enabled: yes
  interval: 30

outputs:
  # Fast log (alerts only)
  - fast:
      enabled: yes
      filename: fast.log
      append: yes

  # EVE JSON output (for ELK Stack integration)
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      community-id-seed: 0
      
      types:
        - alert:
            tagged-packets: yes
            metadata: yes
        - anomaly:
            enabled: yes
            types:
              decode: yes
              stream: yes
              applayer: yes
        - http:
            extended: yes
            custom: [Accept-Encoding, Accept-Language, Authorization]
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
            session-resumption: yes
        - files:
            force-magic: yes
            force-hash: [md5, sha1, sha256]
        - smtp:
            extended: yes
        - ssh
        - stats:
            totals: yes
            threads: yes
            deltas: yes
        - flow
        - netflow

  # Unified2 output (for legacy SIEM)
  - unified2-alert:
      enabled: no

  # HTTP request log
  - http-log:
      enabled: yes
      filename: http.log
      append: yes

  # TLS handshake log
  - tls-log:
      enabled: yes
      filename: tls.log
      append: yes
      extended: yes

  # DNS transaction log
  - dns-log:
      enabled: yes
      filename: dns.log
      append: yes

  # File extraction (malware samples)
  - file-store:
      version: 2
      enabled: yes
      dir: /var/log/suricata/files
      force-magic: yes
      force-hash: [md5, sha256]
      
  # Packet log (full packets for alerts)
  - pcap-log:
      enabled: yes
      filename: log.pcap
      limit: 100mb
      max-files: 10
      compression: none
      mode: normal
      use-stream-depth: no
      honor-pass-rules: no

# Logging configuration
logging:
  default-log-level: notice
  default-output-filter:
  
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: suricata.log
    - syslog:
        enabled: yes
        facility: local5
        format: "[%i] <%d> -- "

# Application layer protocols
app-layer:
  protocols:
    rfb:
      enabled: yes
      detection-ports:
        dp: 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909
    
    mqtt:
      enabled: yes
    
    krb5:
      enabled: yes
    
    snmp:
      enabled: yes
    
    ikev2:
      enabled: yes
    
    tls:
      enabled: yes
      detection-ports:
        dp: 443
      ja3-fingerprints: yes
    
    dcerpc:
      enabled: yes
    
    ftp:
      enabled: yes
    
    rdp:
      enabled: yes
    
    ssh:
      enabled: yes
    
    http2:
      enabled: yes
    
    smtp:
      enabled: yes
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: yes
    
    imap:
      enabled: yes
    
    smb:
      enabled: yes
      detection-ports:
        dp: 139, 445
    
    nfs:
      enabled: yes
    
    tftp:
      enabled: yes
    
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          http-body-inline: auto
          swf-decompression:
            enabled: yes
            type: both
            compress-depth: 0
            decompress-depth: 0
          double-decode-path: no
          double-decode-query: no
    
    modbus:
      enabled: yes
      detection-ports:
        dp: 502
      stream-depth: 0
    
    dnp3:
      enabled: yes
      detection-ports:
        dp: 20000
    
    enip:
      enabled: yes
      detection-ports:
        dp: 44818
        sp: 44818
    
    ntp:
      enabled: yes
    
    dhcp:
      enabled: yes

# Performance tuning
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "all" ]
  detect-thread-ratio: 1.0

# Capture settings
af-packet:
  - interface: ${INTERFACE}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 2048
    block-size: 32768

# Flow settings
flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30

# Stream engine
stream:
  memcap: 64mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

# Host table
host:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb

# IP Reputation (disabled - no reputation files configured)
# reputation-categories-file: /etc/suricata/iprep/categories.txt
# default-reputation-path: /etc/suricata/iprep
# reputation-files:

# Defragmentation
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

# Detection engine
detect:
  profile: high
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000
  prefilter:
    default: mpm

# Profiling
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    limit: 10
    json: yes
  keywords:
    enabled: yes
    filename: keyword_perf.log
    append: yes
  prefilter:
    enabled: yes
    filename: prefilter_perf.log
    append: yes
  rulegroups:
    enabled: yes
    filename: rule_group_perf.log
    append: yes
  packets:
    enabled: yes
    filename: packet_stats.log
    append: yes
    csv:
      enabled: no

# Packet acquisition
pcap:
  - interface: ${INTERFACE}

# PCAP file processing
pcap-file:
  checksum-checks: auto

# Rule files (managed by suricata-update)
default-rule-path: /var/lib/suricata/rules
rule-files:
  - "*.rules"

# Classification config
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
threshold-file: /etc/suricata/threshold.config

# GeoIP (optional, requires GeoIP database)
#geoip-database: /usr/share/GeoIP/GeoLite2-Country.mmdb

# Unix command socket
unix-command:
  enabled: yes
  filename: /var/run/suricata/suricata-command.socket

# Exception policy
exception-policy: auto

EOF

echo -e "${GREEN}[+] Suricata configuration created${NC}"

################################################################################
# Create threshold configuration (reduce false positives)
################################################################################
echo -e "${GREEN}[+] Configuring alert thresholds...${NC}"

# Backup existing threshold config if it exists
cp /etc/suricata/threshold.config "$BACKUP_DIR/threshold.config" 2>/dev/null || true

cat > /etc/suricata/threshold.config << 'EOF'
# Threshold configuration to reduce false positives
# Format: threshold gen_id <gid>, sig_id <sid>, type <threshold|limit|both>, track <by_src|by_dst>, count <N>, seconds <T>

# Example: Suppress noisy DNS rules
# suppress gen_id 1, sig_id 2100498

# Rate limit SSH brute force alerts (max 1 alert per 60 seconds per source)
threshold gen_id 1, sig_id 2001219, type limit, track by_src, count 1, seconds 60

# Rate limit port scan alerts
threshold gen_id 1, sig_id 2000538, type threshold, track by_src, count 10, seconds 60
EOF

################################################################################
# Create custom local rules
################################################################################
echo -e "${GREEN}[+] Creating local custom rules...${NC}"

# Create rules directory if it doesn't exist
mkdir -p /etc/suricata/rules

cat > /etc/suricata/rules/local.rules << 'EOF'
# Local custom rules for 192.168.10.0/24 network

# Alert on outbound connections to known malicious IPs (example)
# alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Possible Malware C2 Traffic"; flow:to_server; threshold:type limit, track by_src, count 1, seconds 60; classtype:trojan-activity; sid:9000001; rev:1;)

# Alert on suspicious internal port scans
alert tcp $HOME_NET any -> $HOME_NET any (msg:"LOCAL Possible Internal Port Scan"; flags:S; threshold:type threshold, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:9000002; rev:1;)

# Alert on SMB connections from external (should be blocked by firewall anyway)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"LOCAL External SMB Access Attempt"; flow:to_server,established; classtype:attempted-admin; sid:9000003; rev:1;)

# Alert on SSH connections from external to non-Jump Host
alert tcp $EXTERNAL_NET any -> $HOME_NET !$SSH_PORTS (msg:"LOCAL SSH Connection to Non-Standard Port from External"; flow:to_server,established; classtype:attempted-admin; sid:9000004; rev:1;)

# Monitor file downloads from external sources
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Executable File Download"; flow:established,to_client; fileext:"exe"; classtype:policy-violation; sid:9000005; rev:1;)

# Detect potential data exfiltration (large outbound transfers)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL Large Outbound Data Transfer"; flow:to_server; dsize:>1000000; threshold:type limit, track by_src, count 1, seconds 300; classtype:potential-corporate-privacy-violation; sid:9000006; rev:1;)
EOF

################################################################################
# Set up log directory permissions
################################################################################
echo -e "${GREEN}[+] Setting up log directories...${NC}"

mkdir -p /var/log/suricata/files
mkdir -p /var/lib/suricata/rules
chown -R suricata:suricata /var/log/suricata
chmod -R 755 /var/log/suricata

################################################################################
# Update Suricata rules
################################################################################
echo -e "${GREEN}[+] Updating Suricata rulesets...${NC}"
echo -e "${YELLOW}[*] This may take a few minutes...${NC}"

# Run suricata-update to download rules
suricata-update

# Verify rules were downloaded
if [ ! -f /var/lib/suricata/rules/suricata.rules ]; then
    echo -e "${RED}[!] Warning: Rules file not found after update${NC}"
    echo -e "${YELLOW}[*] Creating empty rules file for now...${NC}"
    touch /var/lib/suricata/rules/suricata.rules
fi

################################################################################
# Configure log rotation
################################################################################
echo -e "${GREEN}[+] Configuring log rotation...${NC}"

cat > /etc/logrotate.d/suricata << 'EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
    create 0640 suricata suricata
}

/var/log/suricata/*.pcap {
    daily
    rotate 3
    missingok
    notifempty
    compress
    delaycompress
    create 0640 suricata suricata
}
EOF

################################################################################
# Enable and start Suricata
################################################################################
echo -e "${GREEN}[+] Enabling Suricata service...${NC}"

# Test configuration
echo -e "${YELLOW}[*] Testing Suricata configuration...${NC}"
if suricata -T -c /etc/suricata/suricata.yaml -v; then
    echo -e "${GREEN}[+] Configuration test passed!${NC}"
else
    echo -e "${RED}[!] Configuration test failed! Check the output above.${NC}"
    exit 1
fi

# Enable and start service
systemctl enable suricata
systemctl restart suricata

# Wait for startup
sleep 5

# Check status
if systemctl is-active --quiet suricata; then
    echo -e "${GREEN}[+] Suricata is running!${NC}"
else
    echo -e "${RED}[!] Suricata failed to start. Check logs:${NC}"
    echo -e "${YELLOW}    sudo journalctl -u suricata -n 50${NC}"
    exit 1
fi

################################################################################
# Create monitoring script
################################################################################
echo -e "${GREEN}[+] Creating monitoring script...${NC}"

cat > /usr/local/bin/suricata-stats.sh << 'EOF'
#!/bin/bash
# Quick Suricata statistics viewer

echo "=== Suricata Status ==="
systemctl status suricata --no-pager | head -n 5

echo ""
echo "=== Recent Alerts (last 10) ==="
tail -n 10 /var/log/suricata/fast.log 2>/dev/null || echo "No alerts yet"

echo ""
echo "=== Statistics ==="
suricatasc -c "dump-counters" 2>/dev/null | jq '.message' 2>/dev/null | head -n 20 || echo "Statistics not available"

echo ""
echo "=== Top Alert Types (last 100 alerts) ==="
grep -oP 'Classification: \K[^]]+' /var/log/suricata/fast.log 2>/dev/null | tail -n 100 | sort | uniq -c | sort -rn | head -n 10 || echo "No classification data"
EOF

chmod +x /usr/local/bin/suricata-stats.sh

################################################################################
# Summary
################################################################################
echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Suricata Configuration Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "${YELLOW}Configuration Summary:${NC}"
echo -e "  Interface: $INTERFACE"
echo -e "  Home Network: 192.168.10.0/24"
echo -e "  Log Directory: /var/log/suricata/"
echo -e "  Rules Directory: /var/lib/suricata/rules/"
echo ""
echo -e "${YELLOW}Important Commands:${NC}"
echo -e "  Check status:        ${GREEN}sudo systemctl status suricata${NC}"
echo -e "  View live alerts:    ${GREEN}sudo tail -f /var/log/suricata/fast.log${NC}"
echo -e "  View statistics:     ${GREEN}sudo /usr/local/bin/suricata-stats.sh${NC}"
echo -e "  Update rules:        ${GREEN}sudo suricata-update${NC}"
echo -e "  Restart Suricata:    ${GREEN}sudo systemctl restart suricata${NC}"
echo -e "  Test config:         ${GREEN}sudo suricata -T -c /etc/suricata/suricata.yaml${NC}"
echo ""
echo -e "${YELLOW}Log Files:${NC}"
echo -e "  Fast alerts:         /var/log/suricata/fast.log"
echo -e "  EVE JSON (for ELK):  /var/log/suricata/eve.json"
echo -e "  HTTP logs:           /var/log/suricata/http.log"
echo -e "  DNS logs:            /var/log/suricata/dns.log"
echo -e "  TLS logs:            /var/log/suricata/tls.log"
echo -e "  Packet captures:     /var/log/suricata/log.pcap"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Monitor alerts: ${GREEN}sudo tail -f /var/log/suricata/fast.log${NC}"
echo -e "  2. Generate test traffic and verify detection"
echo -e "  3. Configure ELK Stack to ingest /var/log/suricata/eve.json"
echo -e "  4. Fine-tune rules based on your environment"
echo -e "  5. Set up Filebeat to ship logs to ELK (recommended)"
echo ""
echo -e "${GREEN}Suricata is now protecting your network!${NC}"
echo ""
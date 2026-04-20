#!/bin/bash
# pfSense Auto-Block Script (Debugged)

PFSENSE_HOST="192.168.10.1"
PFSENSE_PORT="51822"
PFSENSE_USER="admin"
PFSENSE_PASS='&a76?4:q!27-Tf/GCoeR{/*umH]Wm7n7'
PFSENSE_SSH_KEY="/root/.ssh/pfsense_key"

# Read input
INPUT_JSON=$(cat)

# Debug: log what we received
echo "$(date) - Received JSON: $INPUT_JSON" >> /var/ossec/logs/active-responses.log

# Try multiple ways to extract source IP
SRCIP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip' 2>/dev/null)
if [ -z "$SRCIP" ] || [ "$SRCIP" = "null" ]; then
  SRCIP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.src_ip' 2>/dev/null)
fi
if [ -z "$SRCIP" ] || [ "$SRCIP" = "null" ]; then
  SRCIP=$(echo "$INPUT_JSON" | jq -r '.data.srcip' 2>/dev/null)
fi
if [ -z "$SRCIP" ] || [ "$SRCIP" = "null" ]; then
  SRCIP=$(echo "$INPUT_JSON" | jq -r '.srcip' 2>/dev/null)
fi

# Debug: log what IP we extracted
echo "$(date) - Extracted IP: $SRCIP" >> /var/ossec/logs/active-responses.log

# Validate IP
if [ -z "$SRCIP" ] || [ "$SRCIP" = "null" ]; then
  echo "$(date) - No valid source IP in alert" >> /var/ossec/logs/active-responses.log
  exit 0
fi

RULE_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.rule.id' 2>/dev/null)
if [ -z "$RULE_ID" ] || [ "$RULE_ID" = "null" ]; then
  RULE_ID="unknown"
fi

echo "$(date) - Blocking IP: $SRCIP (Rule: $RULE_ID)" >> /var/ossec/logs/active-responses.log

# Create PHP command
PHP_CMD="php -r '
require_once(\"/etc/inc/config.inc\");
require_once(\"/etc/inc/util.inc\");
\$config = parse_config(true);
foreach (\$config[\"aliases\"][\"alias\"] as &\$alias) {
  if (\$alias[\"name\"] == \"wazuh_blocklist\") {
    \$ips = explode(\" \", \$alias[\"address\"]);
    if (!in_array(\"$SRCIP\", \$ips)) {
      \$ips[] = \"$SRCIP\";
      \$alias[\"address\"] = implode(\" \", \$ips);
      write_config(\"Wazuh blocked $SRCIP\");
      filter_configure();
      echo \"Blocked: $SRCIP\";
    } else {
      echo \"Already blocked: $SRCIP\";
    }
    break;
  }
}
'"

# Execute on pfSense
OUTPUT=$(sshpass -p "$PFSENSE_PASS" ssh -i "$PFSENSE_SSH_KEY" -p "$PFSENSE_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$PFSENSE_USER@$PFSENSE_HOST" "$PHP_CMD" 2>&1)

echo "$(date) - pfSense response: $OUTPUT" >> /var/ossec/logs/active-responses.log
exit 0
#!/bin/bash
# File Quarantine Script (Local Execution)
# Runs ON the agent to quarantine files locally

# Read Wazuh alert data
read INPUT_JSON

FILEPATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path // empty' 2>/dev/null)
RULE_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.rule.id // "unknown"' 2>/dev/null)

# Validate filepath
if [ -z "$FILEPATH" ] || [ "$FILEPATH" = "null" ]; then
  echo "$(date) - No valid file path in alert" >> /var/ossec/logs/active-responses.log
  exit 0
fi

QUARANTINEDIR="/var/ossec/quarantine"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
FILENAME=$(basename "$FILEPATH")

# Log action
echo "$(date) - Quarantining file: $FILEPATH (Rule: $RULE_ID)" >> /var/ossec/logs/active-responses.log

# Create quarantine directory
mkdir -p "$QUARANTINEDIR"

# Check if file exists
if [ ! -f "$FILEPATH" ]; then
  echo "$(date) - File not found: $FILEPATH" >> /var/ossec/logs/active-responses.log
  exit 0
fi

# Move file to quarantine
mv "$FILEPATH" "$QUARANTINEDIR/${FILENAME}.${TIMESTAMP}"

# Remove all permissions
chmod 000 "$QUARANTINEDIR/${FILENAME}.${TIMESTAMP}"

echo "$(date) - Successfully quarantined: $FILEPATH -> $QUARANTINEDIR/${FILENAME}.${TIMESTAMP}" >> /var/ossec/logs/active-responses.log

exit 0
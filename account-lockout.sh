#!/bin/bash
# Account Lockout Script
# Disables user accounts after suspicious activity

# Read Wazuh alert data
read INPUT_JSON
USERNAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.dstuser)
AGENT_NAME=$(echo $INPUT_JSON | jq -r .parameters.alert.agent.name)
RULE_ID=$(echo $INPUT_JSON | jq -r .parameters.alert.rule.id)

# Log action
echo "$(date) - Locking account: $USERNAME on agent: $AGENT_NAME (Rule: $RULE_ID)" >> /var/ossec/logs/active-responses.log

# Send command to agent to lock account
/var/ossec/bin/agent_control -b $AGENT_NAME -e "usermod -L $USERNAME"

# Also disable SSH login
/var/ossec/bin/agent_control -b $AGENT_NAME -e "usermod -s /usr/sbin/nologin $USERNAME"

exit 0
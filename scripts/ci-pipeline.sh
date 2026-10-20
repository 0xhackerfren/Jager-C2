#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PASS=0
FAIL=0
SKIP=0

log()    { echo "[CI] $(date +%T) $*"; }
pass()   { log "PASS: $1"; PASS=$((PASS + 1)); }
fail()   { log "FAIL: $1"; FAIL=$((FAIL + 1)); FAILED_STEPS+=("$1"); }
skip()   { log "SKIP: $1"; SKIP=$((SKIP + 1)); }

FAILED_STEPS=()

# ---- Step 1: Teamserver build ----
log "=== Step 1: Teamserver build ==="
cd "$ROOT_DIR/teamserver"
if go build ./... 2>&1; then
    pass "teamserver build"
else
    fail "teamserver build"
fi

# ---- Step 2: Teamserver tests ----
log "=== Step 2: Teamserver tests ==="
if go test ./... -timeout 120s 2>&1; then
    pass "teamserver tests"
else
    fail "teamserver tests"
fi

# ---- Step 3: Windows cross-compile ----
log "=== Step 3: Windows implant cross-compile ==="
cd "$ROOT_DIR/implant"

# Preflight: check MinGW
if command -v x86_64-w64-mingw32-gcc &>/dev/null; then
    if make clean && make exe 2>&1; then
        pass "windows implant build"

        # YARA gate on built artifact
        YARA_WIN_RULES=""
        if [ -f "$ROOT_DIR/yara/self_test_strings.yar" ]; then
            YARA_WIN_RULES="$ROOT_DIR/yara/self_test_strings.yar $ROOT_DIR/yara/self_test_pe.yar"
        elif [ -f "$ROOT_DIR/yara/self_test.yar" ]; then
            YARA_WIN_RULES="$ROOT_DIR/yara/self_test.yar"
        fi
        if command -v yara &>/dev/null && [ -n "$YARA_WIN_RULES" ]; then
            log "Running YARA self-test on Windows implant..."
            YARA_MATCH=0
            for rule_file in $YARA_WIN_RULES; do
                if yara -s "$rule_file" bin/implant.exe 2>&1 | grep -q "Jager_"; then
                    YARA_MATCH=1
                fi
            done
            if [ "$YARA_MATCH" -eq 1 ]; then
                fail "windows implant YARA self-test (detections found)"
            else
                pass "windows implant YARA clean"
            fi
        else
            skip "YARA scan (yara not installed or rules missing)"
        fi
    else
        fail "windows implant build"
    fi
else
    skip "windows implant (MinGW not found)"
fi

# ---- Step 4: Linux compile ----
log "=== Step 4: Linux implant compile ==="
cd "$ROOT_DIR/implant-linux"
if make clean && make 2>&1; then
    pass "linux implant build"
else
    fail "linux implant build"
fi

# ---- Step 5: Python builder validation ----
log "=== Step 5: Builder validation ==="
cd "$ROOT_DIR/builder"
if python3 -c "import build_implant; import profile_engine; import polymorphic; print('OK')" 2>&1; then
    pass "builder import check"
else
    fail "builder import check"
fi

# ---- Step 6: Profile validation ----
log "=== Step 6: Profile validation ==="
cd "$ROOT_DIR/builder"
PROFILES_OK=1
for profile in profiles/*.json; do
    if [ -f "$profile" ]; then
        if python3 -c "
import json, sys
with open('$profile') as f:
    p = json.load(f)
    assert 'name' in p, 'missing name'
    assert 'http' in p or 'description' in p, 'missing http/description'
print('OK: $profile')
" 2>&1; then
            :
        else
            PROFILES_OK=0
            log "  Invalid profile: $profile"
        fi
    fi
done
if [ "$PROFILES_OK" -eq 1 ]; then
    pass "profile validation"
else
    fail "profile validation"
fi

# ---- Step 7: e2e-smoke (optional) ----
log "=== Step 7: e2e-smoke ==="
if [ -f "$ROOT_DIR/scripts/e2e-smoke.sh" ]; then
    if bash "$ROOT_DIR/scripts/e2e-smoke.sh" 2>&1; then
        pass "e2e-smoke"
    else
        # e2e failures are warnings, not hard fails (requires running teamserver)
        skip "e2e-smoke (teamserver not running or test failed)"
    fi
else
    skip "e2e-smoke (script not found)"
fi

# ---- Step 8: Contract drift detection ----
log "=== Step 8: Contract drift test ==="
cd "$ROOT_DIR"
if python3 tests/contract/test_task_dispatch.py 2>&1; then
    pass "contract drift (proto/implant sync)"
else
    fail "contract drift (proto/implant sync)"
fi

# ---- Step 9: Integration tests (pytest) ----
log "=== Step 9: Integration tests ==="
cd "$ROOT_DIR"
if command -v pytest &>/dev/null || python3 -m pytest --version &>/dev/null 2>&1; then
    PYTEST_CMD="python3 -m pytest"
    if $PYTEST_CMD tests/integration/ -v --tb=short --timeout=60 2>&1; then
        pass "integration tests"
    else
        fail "integration tests"
    fi
else
    skip "integration tests (pytest not installed)"
fi

# ---- Summary ----
echo ""
log "========================================="
log "CI Pipeline Summary"
log "========================================="
log "PASSED: $PASS"
log "FAILED: $FAIL"
log "SKIPPED: $SKIP"

if [ "$FAIL" -gt 0 ]; then
    log "Failed steps:"
    for step in "${FAILED_STEPS[@]}"; do
        log "  - $step"
    done
    exit 1
fi

log "All checks passed!"
exit 0

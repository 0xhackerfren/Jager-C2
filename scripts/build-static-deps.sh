#!/usr/bin/env bash
set -euo pipefail

# Build minimal static libcurl + OpenSSL for fully portable Linux implants.
# Produces .a archives with zero krb5/ldap/ssh2/brotli/nghttp2/3/psl deps.
# Output: $DEPS_DIR/lib/*.a  $DEPS_DIR/include/**

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAGER_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPS_DIR="${JAGER_ROOT}/deps"
BUILD_DIR="$(mktemp -d /tmp/jager-deps-build.XXXXXX)"
INSTALL_DIR="/tmp/jager-deps-install"
JOBS="$(nproc)"

CURL_VERSION="${CURL_VERSION:-8.11.1}"
CURL_TARBALL="curl-${CURL_VERSION}.tar.gz"
CURL_URL="https://curl.se/download/${CURL_TARBALL}"

cleanup() { rm -rf "$BUILD_DIR" "$INSTALL_DIR"; }
trap cleanup EXIT

rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$DEPS_DIR"/{lib,include}

echo "[*] Building minimal static libcurl ${CURL_VERSION} -> ${DEPS_DIR}"
echo "[*] Build dir: ${BUILD_DIR}"
echo "[*] Jobs: ${JOBS}"

cd "$BUILD_DIR"

if [ ! -f "$CURL_TARBALL" ]; then
    echo "[*] Downloading curl ${CURL_VERSION}..."
    wget -q "$CURL_URL" -O "$CURL_TARBALL"
fi

tar xzf "$CURL_TARBALL"
cd "curl-${CURL_VERSION}"

echo "[*] Configuring curl (minimal: OpenSSL only, no LDAP/SSH/KRB5/HTTP2/3)..."
./configure \
    --disable-shared \
    --enable-static \
    --with-openssl \
    --without-libssh2 \
    --without-libssh \
    --without-librtmp \
    --without-gsasl \
    --without-gnutls \
    --without-mbedtls \
    --without-wolfssl \
    --without-bearssl \
    --without-rustls \
    --without-hyper \
    --without-quiche \
    --without-msh3 \
    --without-winidn \
    --without-ca-fallback \
    --disable-ldap \
    --disable-ldaps \
    --without-gssapi \
    --without-nghttp2 \
    --without-nghttp3 \
    --without-ngtcp2 \
    --without-libidn2 \
    --without-libpsl \
    --without-brotli \
    --without-zstd \
    --disable-ftp \
    --disable-file \
    --disable-dict \
    --disable-gopher \
    --disable-imap \
    --disable-mqtt \
    --disable-pop3 \
    --disable-rtsp \
    --disable-smb \
    --disable-smtp \
    --disable-telnet \
    --disable-tftp \
    --disable-manual \
    --disable-docs \
    --disable-unix-sockets \
    --enable-http \
    --enable-proxy \
    --prefix="$INSTALL_DIR" \
    --silent \
    2>&1

echo "[*] Building..."
make -j"$JOBS" -s 2>&1

echo "[*] Installing to temp dir..."
make install -s 2>&1

echo "[*] Copying artifacts to ${DEPS_DIR}..."
cp -f "$INSTALL_DIR"/lib/libcurl.a "$DEPS_DIR"/lib/
cp -rf "$INSTALL_DIR"/include/curl "$DEPS_DIR"/include/
cp -rf "$INSTALL_DIR"/lib/pkgconfig "$DEPS_DIR"/lib/ 2>/dev/null || true

echo "[+] Static deps built:"
ls -la "$DEPS_DIR"/lib/libcurl.a
echo "[+] pkg-config static deps (should be minimal):"
PKG_CONFIG_PATH="${DEPS_DIR}/lib/pkgconfig" pkg-config --libs --static libcurl 2>/dev/null || echo "(pkg-config not available for custom curl)"

echo "[+] Done. Use -I${DEPS_DIR}/include -L${DEPS_DIR}/lib when building implants."

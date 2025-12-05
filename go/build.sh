#!/bin/bash
# 6319 Go Build Script
# Builds static binaries for multiple architectures

set -e

cd "$(dirname "$0")"

OUTPUT_DIR="../bin"
mkdir -p "$OUTPUT_DIR"

LDFLAGS="-s -w"

echo "[*] Building fileless loader..."

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$OUTPUT_DIR/loader_linux_amd64" ./cmd/loader
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$OUTPUT_DIR/loader_linux_arm64" ./cmd/loader
CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -ldflags="$LDFLAGS" -o "$OUTPUT_DIR/loader_linux_arm" ./cmd/loader

echo "[*] Building agent..."

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$OUTPUT_DIR/agent_linux_amd64" ./cmd/agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$OUTPUT_DIR/agent_linux_arm64" ./cmd/agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -ldflags="$LDFLAGS" -o "$OUTPUT_DIR/agent_linux_arm" ./cmd/agent

echo ""
echo "[+] Build complete:"
ls -lh "$OUTPUT_DIR"

echo ""
echo "[*] Binary sizes:"
for f in "$OUTPUT_DIR"/*; do
    size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)
    echo "    $(basename $f): $(numfmt --to=iec $size 2>/dev/null || echo "$size bytes")"
done

echo ""
echo "[*] To compress with UPX (optional):"
echo "    upx --best $OUTPUT_DIR/*"

#!/bin/bash
# Test WPScan Configuration

source config/config.sh

TARGET="xpereos.in"
PROTOCOL="https"

echo "Testing WPScan for $TARGET..."
echo "API Token Configured: ${WPSCAN_API_TOKEN:0:5}******"

echo -e "\n1. Running Connectivity Check (with SSL Checks DISABLED)..."
$WPSCAN_PATH --url "${PROTOCOL}://${TARGET}" \
    --stealthy \
    --detection-mode aggressive \
    -e u1-1 \
    --no-banner \
    --disable-tls-checks \
    --connect-timeout 30 \
    --random-user-agent \
    --verbose

echo -e "\n--------------------------------\n"

if [ -n "$WPSCAN_API_TOKEN" ]; then
    echo "2. Testing API Token Validity..."
    $WPSCAN_PATH --api-token "$WPSCAN_API_TOKEN" --status-check
fi

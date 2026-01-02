#!/bin/bash

# OWASP ZAP Daemon Integration Module (Docker-based)
# Requirements: Docker, curl, jq

TARGET=$1
OUTPUT_DIR=$2
COOKIE=$3

# ZAP API Config
ZAP_PORT=8090
ZAP_API_KEY="vapt_secret_key_123"
ZAP_URL="http://localhost:${ZAP_PORT}"

mkdir -p "${OUTPUT_DIR}"

echo "Starting ZAP Daemon Integration for ${TARGET}..." >> "${LOG_FILE}"

# Check for Docker
if ! command -v docker >/dev/null 2>&1; then
    echo "  [!] Docker not found. Cannot run ZAP Daemon." >> "${LOG_FILE}"
    exit 1
fi

# Stop any existing ZAP container
docker rm -f zap-daemon >/dev/null 2>&1

# Start ZAP in daemon mode
echo "  Starting ZAP container (zap-daemon)..." >> "${LOG_FILE}"
docker run -u zap -p ${ZAP_PORT}:8080 -d --name zap-daemon owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=${ZAP_API_KEY} >/dev/null

# Wait for ZAP to start
echo "  Waiting for ZAP API to initialize..." >> "${LOG_FILE}"
RETRIES=0
while ! curl -s "${ZAP_URL}/JSON/core/view/version/?apikey=${ZAP_API_KEY}" >/dev/null; do
    sleep 5
    RETRIES=$((RETRIES+1))
    if [ $RETRIES -gt 24 ]; then # 2 minutes
        echo "  [!] ZAP failed to start." >> "${LOG_FILE}"
        docker rm -f zap-daemon >/dev/null
        exit 1
    fi
done
echo "  [+] ZAP is ready." >> "${LOG_FILE}"

# Configure Context
CONTEXT_ID=1
# Include Target
curl -s "${ZAP_URL}/JSON/context/action/includeInContext/?apikey=${ZAP_API_KEY}&contextName=Default%20Context&regex=https://${TARGET}.*" >/dev/null

# Handle Authentication (Cookie)
if [ -n "$COOKIE" ]; then
    echo "  Configuring Authentication (Session Cookie)..." >> "${LOG_FILE}"
    # Use Replacer to inject cookie header
    curl -s "${ZAP_URL}/JSON/replacer/action/addRule/?apikey=${ZAP_API_KEY}&description=SessionCookie&enabled=true&matchType=REQ_HEADER&matchRegex=false&matchString=Cookie&replacement=${COOKIE}" >/dev/null
fi

# Spidering
echo "  Running ZAP Spider..." >> "${LOG_FILE}"
SCAN_ID=$(curl -s "${ZAP_URL}/JSON/spider/action/scan/?apikey=${ZAP_API_KEY}&url=https://${TARGET}&contextName=Default%20Context" | jq -r .scan)
while [ "$(curl -s "${ZAP_URL}/JSON/spider/view/status/?apikey=${ZAP_API_KEY}&scanId=${SCAN_ID}" | jq -r .status)" != "100" ]; do
    sleep 5
done
echo "  Spider complete." >> "${LOG_FILE}"

# Active Scan (Safety Check: Only if explicit or standard practice - sticking to simple active scan for now)
echo "  Running ZAP Active Scan..." >> "${LOG_FILE}"
SCAN_ID=$(curl -s "${ZAP_URL}/JSON/ascan/action/scan/?apikey=${ZAP_API_KEY}&url=https://${TARGET}&recurse=true&inScopeOnly=true" | jq -r .scan)

# Wait loop for active scan
while true; do
    STATUS=$(curl -s "${ZAP_URL}/JSON/ascan/view/status/?apikey=${ZAP_API_KEY}&scanId=${SCAN_ID}" | jq -r .status)
    if [ "$STATUS" == "100" ]; then break; fi
    # echo "  Scan progress: ${STATUS}%" # too verbose for log
    sleep 10
done
echo "  Active Scan complete." >> "${LOG_FILE}"

# Generate Reports
echo "  Generating Reports..." >> "${LOG_FILE}"
curl -s "${ZAP_URL}/OTHER/core/other/htmlreport/?apikey=${ZAP_API_KEY}" > "${OUTPUT_DIR}/zap_report.html"
curl -s "${ZAP_URL}/OTHER/core/other/jsonreport/?apikey=${ZAP_API_KEY}" > "${OUTPUT_DIR}/zap_report.json"

# Cleanup
echo "  Stopping ZAP container..." >> "${LOG_FILE}"
docker rm -f zap-daemon >/dev/null

echo "ZAP Integration completed." >> "${LOG_FILE}"
exit 0

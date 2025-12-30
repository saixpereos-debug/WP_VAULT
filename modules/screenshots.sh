#!/bin/bash

# Screenshot capture module - Vṛthā v2.1
# Uses gowitness v3 with explicit Chromium path

TARGET=$1
OUTPUT_DIR=$2

mkdir -p "${OUTPUT_DIR}"

# Source file for all discovered URLs
ALL_URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"
# Output file for filtered sensitive URLs
URL_LIST="${OUTPUT_DIR}/urls_to_screenshot.txt"

echo "Preparing sensitive URLs for screenshot capture..." >> "${LOG_FILE}"

# Define patterns for sensitive/interesting endpoints
SENSITIVE_PATTERNS="admin|login|dashboard|panel|console|config|backup|\.env|\.git|wp-admin|wp-login|phpmyadmin|cpanel|webmail|portal|manager|api|upload|debug|test|dev|staging|internal"

# Filter sensitive URLs from all discovered URLs
if [ -f "${ALL_URLS_FILE}" ]; then
    # Remove wildcards, then grep for sensitive patterns, unique
    grep -v "\*" "${ALL_URLS_FILE}" | grep -iE "${SENSITIVE_PATTERNS}" | sort -u > "${URL_LIST}"
    
    # If no sensitive URLs found, add the main targets
    if [ ! -s "${URL_LIST}" ]; then
        echo "  No sensitive URLs found. Adding all live hosts..." >> "${LOG_FILE}"
        grep -v "\*" "${ALL_URLS_FILE}" | head -n 10 >> "${URL_LIST}"
    fi
else
    echo "  URL file not found. Using main target." >> "${LOG_FILE}"
fi

# Always add the main target domain as fallback
echo "https://${TARGET}" >> "${URL_LIST}"
sort -u "${URL_LIST}" -o "${URL_LIST}"

# Remove any remaining invalid URLs (wildcards, empty lines)
grep -v "\*" "${URL_LIST}" | grep -E "^https?://" > "${URL_LIST}.clean"
mv "${URL_LIST}.clean" "${URL_LIST}"

URL_COUNT=$(wc -l < "${URL_LIST}" 2>/dev/null || echo "0")
echo "Taking screenshots of ${URL_COUNT} URLs using Gowitness v3 + Chromium..." >> "${LOG_FILE}"

# Check if gowitness is available
if [ ! -x "${GOWITNESS_PATH}" ]; then
    echo "Gowitness not found at ${GOWITNESS_PATH}. Skipping screenshots." >> "${LOG_FILE}"
    exit 1
fi

# Detect Chromium path
CHROMIUM_PATH=""
for browser in /usr/bin/chromium /usr/bin/chromium-browser /usr/bin/google-chrome; do
    if [ -x "$browser" ]; then
        CHROMIUM_PATH="$browser"
        break
    fi
done

if [ -z "$CHROMIUM_PATH" ]; then
    echo "No Chromium/Chrome browser found. Skipping screenshots." >> "${LOG_FILE}"
    exit 1
fi

echo "  Using browser: ${CHROMIUM_PATH}" >> "${LOG_FILE}"

# Run gowitness with explicit settings for reliability
${GOWITNESS_PATH} scan file \
    -f "${URL_LIST}" \
    --chrome-path "${CHROMIUM_PATH}" \
    --screenshot-path "${OUTPUT_DIR}" \
    --screenshot-format png \
    --delay 5 \
    -t 5 \
    -T 45 \
    --write-db \
    --write-db-uri "sqlite://${OUTPUT_DIR}/gowitness.sqlite3" \
    >> "${LOG_FILE}" 2>&1

# Count captured screenshots (gowitness v3 saves directly in screenshot-path)
SCREENSHOT_COUNT=$(find "${OUTPUT_DIR}" -maxdepth 1 -name "*.png" -type f | wc -l)

echo "  Screenshots captured: ${SCREENSHOT_COUNT}" >> "${LOG_FILE}"
echo "SCREENSHOTS_CAPTURED=${SCREENSHOT_COUNT}"

# List screenshots for report integration
find "${OUTPUT_DIR}" -maxdepth 1 -name "*.png" -type f > "${OUTPUT_DIR}/vapt_${TARGET}_screenshots_list.txt" 2>/dev/null

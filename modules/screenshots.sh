#!/bin/bash

# Screenshot capture module

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

mkdir -p "${OUTPUT_DIR}"

# Sources for screenshots
LIVE_HOSTS="${RESULTS_DIR}/httpx/live_hosts.txt"
INTERESTING_URLS="${RESULTS_DIR}/httpx/interesting_urls.txt"
ALL_URLS="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Sources for screenshots
LIVE_HOSTS="${RESULTS_DIR}/httpx/live_hosts.txt"
INTERESTING_URLS="${RESULTS_DIR}/httpx/interesting_urls.txt"
ALL_URLS="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

URL_LIST="${OUTPUT_DIR}/urls_to_screenshot.txt"
# For gowitness v3, screenshots go directly into the designated module output folder
SCREENSHOT_PATH="${OUTPUT_DIR}"
mkdir -p "${SCREENSHOT_PATH}"

# Heuristic: ONLY generate if main.sh didn't already create it via AI selector
if [ ! -s "${URL_LIST}" ]; then
    echo "  AI selection missing or empty. Using heuristic selection for screenshots..." >> "${LOG_FILE}"
    {
        [ -f "${INTERESTING_URLS}" ] && head -n 20 "${INTERESTING_URLS}"
        [ -f "${LIVE_HOSTS}" ] && head -n 10 "${LIVE_HOSTS}"
        [ -f "${ALL_URLS}" ] && head -n 20 "${ALL_URLS}"
    } | sort -u > "${URL_LIST}"
fi

if [ ! -s "${URL_LIST}" ]; then
    # Final fallback if everything else failed
    echo "  No URLs found to screenshot. Using main target." >> "${LOG_FILE}"
    echo "https://${TARGET}" > "${URL_LIST}"
fi

# Check if gowitness is available
if [ ! -x "${GOWITNESS_PATH}" ] && ! command -v gowitness >/dev/null 2>&1; then
    echo "Gowitness not found. Skipping screenshots." >> "${LOG_FILE}"
    exit 1
fi

URL_COUNT=$(wc -l < "${URL_LIST}")
echo "Taking screenshots of ${URL_COUNT} URLs using Gowitness v3..." >> "${LOG_FILE}"

# GOWITNESS v3+ syntax: gowitness scan file -f <file>
# Reference: gowitness scan file --help
${GOWITNESS_PATH} scan file -f "${URL_LIST}" \
    -t 10 \
    -T 60 \
    --screenshot-path "${SCREENSHOT_PATH}" \
    --write-db \
    --write-db-uri "sqlite://${OUTPUT_DIR}/gowitness.sqlite3" \
    ${GOWITNESS_OPTIONS} >> "${LOG_FILE}" 2>&1

# List all captured screenshots (Check both possible naming conventions)
find "${OUTPUT_DIR}/screenshots" -name "*.png" -type f > "${OUTPUT_DIR}/vapt_${TARGET}_screenshots_list.txt" 2>/dev/null

SCREENSHOT_COUNT=$(wc -l < "${OUTPUT_DIR}/vapt_${TARGET}_screenshots_list.txt" 2>/dev/null || echo "0")
echo "  Screenshots captured: ${SCREENSHOT_COUNT}" >> "${LOG_FILE}"
echo "SCREENSHOTS_CAPTURED=${SCREENSHOT_COUNT}"

#!/bin/bash

# Screenshot capture module

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

mkdir -p "${OUTPUT_DIR}"

URL_LIST="${OUTPUT_DIR}/urls_to_screenshot.txt"
if [ -f "${URLS_FILE}" ]; then
    cat "${URLS_FILE}" | head -n 50 > "${URL_LIST}"
else
    echo "https://${TARGET}" > "${URL_LIST}"
fi

if [ ! -s "${URL_LIST}" ]; then
    echo "No URLs to screenshot." >> "${LOG_FILE}"
    exit 0
fi

# Check if gowitness is available
if [ ! -x "${GOWITNESS_PATH}" ]; then
    echo "Gowitness not found at ${GOWITNESS_PATH}. Skipping screenshots." >> "${LOG_FILE}"
    exit 1
fi

URL_COUNT=$(wc -l < "${URL_LIST}")
echo "Taking screenshots of ${URL_COUNT} URLs..." >> "${LOG_FILE}"

# GOWITNESS v3+ syntax - FIXED
# The correct syntax is: gowitness file <filename>
# NOT: gowitness scan file -f <filename>
# Create screenshots subdirectory
mkdir -p "${OUTPUT_DIR}/screenshots"

# Run gowitness with correct syntax
${GOWITNESS_PATH} file "${URL_LIST}" \
    --write-db-uri="sqlite://${OUTPUT_DIR}/gowitness.sqlite3" \
    --screenshot-path="${OUTPUT_DIR}/screenshots" \
    ${GOWITNESS_OPTIONS} >> "${LOG_FILE}" 2>&1

# Check if successful
if [ $? -eq 0 ]; then
     echo "  Gowitness completed successfully." >> "${LOG_FILE}"
else
     echo "  Gowitness failed. Check log for details." >> "${LOG_FILE}"
fi

# List all captured screenshots
find "${OUTPUT_DIR}/screenshots" -name "*.png" -type f > "${OUTPUT_DIR}/vapt_${TARGET}_screenshots_list.txt" 2>/dev/null

SCREENSHOT_COUNT=$(wc -l < "${OUTPUT_DIR}/vapt_${TARGET}_screenshots_list.txt" 2>/dev/null || echo "0")
echo "  Screenshots captured: ${SCREENSHOT_COUNT}" >> "${LOG_FILE}"
echo "SCREENSHOTS_CAPTURED=${SCREENSHOT_COUNT}"

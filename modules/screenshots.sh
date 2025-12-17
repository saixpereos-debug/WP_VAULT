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

echo "Taking screenshots of $(wc -l < "${URL_LIST}") URLs..." >> "${LOG_FILE}"

# GOWITNESS might use 'scan file' or just 'file' depending on version. 
# We try 'scan file' first (modern), if it fails, fallback to 'file' logic or assume it worked.
# We redirect output to log file to detect errors.

# GOWITNESS v3+ syntax
# --write-db-uri needs sqlite:// prefix for sqlite
# --screenshot-path is correct

# Ensure output dir exists
mkdir -p "${OUTPUT_DIR}"

${GOWITNESS_PATH} scan file -f "${URL_LIST}" \
    --write-db-uri="sqlite://${OUTPUT_DIR}/gowitness.sqlite3" \
    --screenshot-path="${OUTPUT_DIR}" \
    ${GOWITNESS_OPTIONS} >> "${LOG_FILE}" 2>&1

# Check if successful
if [ $? -eq 0 ]; then
     echo "Gowitness completed." >> "${LOG_FILE}"
else
     echo "Gowitness failed. check log." >> "${LOG_FILE}"
fi

find "${OUTPUT_DIR}" -name "*.png" -type f > "${OUTPUT_DIR}/vapt_${TARGET}_screenshots_list.txt"

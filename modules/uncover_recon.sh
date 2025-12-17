#!/bin/bash

# Advanced Reconnaissance using Uncover
# Uses search engines (Shodan, Censys, Fofa) to find exposed assets

TARGET=$1
OUTPUT_DIR=$2
mkdir -p "$OUTPUT_DIR"

OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_uncover.txt"

# Check if uncover is installed
if [ -z "$UNCOVER_PATH" ] || [ ! -x "$UNCOVER_PATH" ]; then
    echo "Uncover tool not configured. Skipping." >> "${LOG_FILE}"
    exit 0
fi

echo "Running Uncover Recon..." >> "${LOG_FILE}"

# Uncover Queries
# finding subdomains or related assets via certificate transparency and other dorks
${UNCOVER_PATH} -q "ssl:\"${TARGET}\"" -e shodan,censys,fofa ${UNCOVER_OPTIONS} -silent >> "${OUTPUT_FILE}" 2>/dev/null
${UNCOVER_PATH} -q "domain:\"${TARGET}\"" -e shodan,censys,fofa ${UNCOVER_OPTIONS} -silent >> "${OUTPUT_FILE}" 2>/dev/null

# Clean up
if [ -s "${OUTPUT_FILE}" ]; then
    sort -u -o "${OUTPUT_FILE}" "${OUTPUT_FILE}"
    echo "Uncover found $(wc -l < "${OUTPUT_FILE}") potential assets." >> "${LOG_FILE}"
else
    echo "Uncover found no assets." >> "${LOG_FILE}"
fi

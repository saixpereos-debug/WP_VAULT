#!/bin/bash

# URL/endpoint discovery module

TARGET=$1
OUTPUT_DIR=$2
SUBDOMAINS_FILE="${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

echo "Discovering URLs with Katana..." >> "${LOG_FILE}"

# Run Katana for JavaScript-based crawling
${KATANA_PATH} -u "https://${TARGET}" ${KATANA_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_urls_${TARGET}.txt" >> "${LOG_FILE}" 2>&1

# Also run on discovered subdomains if they exist
SUBDOMAINS_FILE="${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt"
if [ -f "${SUBDOMAINS_FILE}" ]; then
    while read -r subdomain; do
        ${KATANA_PATH} -u "https://${subdomain}" ${KATANA_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_urls_${subdomain}.txt" >> "${LOG_FILE}" 2>&1
    done < "${SUBDOMAINS_FILE}"
fi

# Run Feroxbuster for directory/file discovery (merged from content_discovery.sh)
echo "Running Feroxbuster for content discovery..." >> "${LOG_FILE}"
if [ -x "${FEROXBUSTER_PATH}" ]; then
    timeout 30m ${FEROXBUSTER_PATH} -u "https://${TARGET}" \
        -w tools/wordlists/raft-medium-directories.txt \
        -x php,html,txt,js,json,xml,bak,old,zip \
        -t 50 --auto-bail --quiet \
        -o "${OUTPUT_DIR}/vapt_${TARGET}_ferox.txt" >> "${LOG_FILE}" 2>&1 || true
fi

# Combine all discovered URLs
cat "${OUTPUT_DIR}"/vapt_${TARGET}_urls_*.txt "${OUTPUT_DIR}/vapt_${TARGET}_ferox.txt" 2>/dev/null | sort -u > "${OUTPUT_DIR}/vapt_${TARGET}_urls_all.txt"

URL_COUNT=$(wc -l < "${OUTPUT_DIR}/vapt_${TARGET}_urls_all.txt" 2>/dev/null || echo "0")
echo "  Total unique URLs discovered: ${URL_COUNT}" >> "${LOG_FILE}"
echo "URL_DISCOVERY=${URL_COUNT}"

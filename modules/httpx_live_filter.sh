#!/bin/bash

# Live Host Filtering Module
# Implements: subfinder → httpx (filtering) → live_hosts.txt
# This module filters discovered subdomains to identify live, interesting hosts

TARGET=$1
OUTPUT_DIR=$2
SUBDOMAINS_FILE="${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt"

mkdir -p "${OUTPUT_DIR}"

echo "Filtering live hosts from discovered subdomains..." >> "${LOG_FILE}"

# Check if subdomains file exists
if [ ! -f "${SUBDOMAINS_FILE}" ]; then
    echo "  No subdomains file found. Using target domain only." >> "${LOG_FILE}"
    echo "${TARGET}" > "${OUTPUT_DIR}/temp_targets.txt"
    SUBDOMAINS_FILE="${OUTPUT_DIR}/temp_targets.txt"
fi

# Count total subdomains
TOTAL_SUBDOMAINS=$(wc -l < "${SUBDOMAINS_FILE}")
echo "  Total subdomains to probe: ${TOTAL_SUBDOMAINS}" >> "${LOG_FILE}"

# Run httpx with filtering for live hosts
# -list: input file with URLs/domains
# -mc: match status codes (200=OK, 301/302=Redirects, 403=Forbidden but alive)
# -title: get page title
# -tech-detect: detect technologies
# -status-code: show status code
# -silent: suppress progress output
echo "  Probing hosts with HTTPX..." >> "${LOG_FILE}"

${HTTPX_PATH} -list "${SUBDOMAINS_FILE}" \
    -title \
    -tech-detect \
    -status-code \
    -mc 200,301,302,403 \
    -o "${OUTPUT_DIR}/live_hosts_detailed.txt" >> "${LOG_FILE}" 2>&1

# Extract just the URLs for clean list
if [ -f "${OUTPUT_DIR}/live_hosts_detailed.txt" ]; then
    grep -oE 'https?://[^ ]+' "${OUTPUT_DIR}/live_hosts_detailed.txt" | sort -u > "${OUTPUT_DIR}/live_hosts.txt" 2>/dev/null || true
else
    touch "${OUTPUT_DIR}/live_hosts.txt"
fi

# Create interesting URLs file (403s, admin panels, etc.)
echo "  Filtering interesting URLs..." >> "${LOG_FILE}"
grep -iE "(403|admin|api|backup|config|database|dev|old|stage|test|staging|panel|dashboard|login|wp-admin)" \
    "${OUTPUT_DIR}/live_hosts_detailed.txt" > "${OUTPUT_DIR}/interesting_urls.txt" 2>/dev/null || true

# Count results
LIVE_COUNT=$(wc -l < "${OUTPUT_DIR}/live_hosts.txt" 2>/dev/null || echo "0")
INTERESTING_COUNT=$(wc -l < "${OUTPUT_DIR}/interesting_urls.txt" 2>/dev/null || echo "0")

echo "  Live hosts found: ${LIVE_COUNT}" >> "${LOG_FILE}"
echo "  Interesting URLs: ${INTERESTING_COUNT}" >> "${LOG_FILE}"

# Print summary to stdout for main.sh to capture
echo "LIVE_HOSTS=${LIVE_COUNT}"
echo "INTERESTING_URLS=${INTERESTING_COUNT}"

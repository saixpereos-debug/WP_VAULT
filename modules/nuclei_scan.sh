#!/bin/bash

# Nuclei scanning module

TARGET=$1
OUTPUT_DIR=$2

# Try to use live hosts first, fallback to all URLs
LIVE_HOSTS_FILE="${RESULTS_DIR}/httpx/live_hosts.txt"
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

URL_LIST="${OUTPUT_DIR}/urls_to_scan.txt"
if [ -f "${LIVE_HOSTS_FILE}" ] && [ -s "${LIVE_HOSTS_FILE}" ]; then
    echo "Using live hosts for Nuclei scan..." >> "${LOG_FILE}"
    cat "${LIVE_HOSTS_FILE}" > "${URL_LIST}"
elif [ -f "${URLS_FILE}" ]; then
    echo "Live hosts not found, using all discovered URLs..." >> "${LOG_FILE}"
    cat "${URLS_FILE}" > "${URL_LIST}"
else
    echo "No URL sources found, using target domain only..." >> "${LOG_FILE}"
    echo "https://${TARGET}" > "${URL_LIST}"
fi

TARGET_COUNT=$(wc -l < "${URL_LIST}")
echo "  Scanning ${TARGET_COUNT} targets with Nuclei..." >> "${LOG_FILE}"

# Update Nuclei templates (silently)
${NUCLEI_PATH} -update-templates >/dev/null 2>&1

# Custom WordPress templates
${NUCLEI_PATH} -list "${URL_LIST}" -t templates/nuclei/ ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_custom.txt" -json >/dev/null 2>&1 || true

# Official WordPress templates
${NUCLEI_PATH} -list "${URL_LIST}" -t ${WORDPRESS_TEMPLATES} ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_official.txt" -json >/dev/null 2>&1 || true

# OWASP Top 10 
echo "Running Nuclei OWASP Top 10..." >> "${LOG_FILE}"
${NUCLEI_PATH} -list "${URL_LIST}" -tags owasp ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_owasp.txt" -json >/dev/null 2>&1 || true

# Wordfence CVEs (Tag based search if available or specific path)
# Assuming 'wordfence' tag exists or similar in default templates, or using general CVEs
echo "Running Nuclei CVEs..." >> "${LOG_FILE}"
${NUCLEI_PATH} -list "${URL_LIST}" -tags cve,wordpress -severity critical,high ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_cves.txt" -json >/dev/null 2>&1 || true

# General templates
${NUCLEI_PATH} -list "${URL_LIST}" -exclude-tags wordpress ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_general.txt" -json >/dev/null 2>&1 || true

# Parse and categorize
python3 -c "
import json
import os
from collections import defaultdict

results = defaultdict(list)

def process_file(filepath, key):
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            results[key].append(json.loads(line))
                        except: pass
        except: pass

process_file('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_custom.txt', 'wordpress_custom')
process_file('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_official.txt', 'wordpress_official')
process_file('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_general.txt', 'general')

severity_results = defaultdict(list)
for category, items in results.items():
    for item in items:
        severity = item.get('info', {}).get('severity', 'unknown')
        severity_results[severity].append(item)

with open('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_categorized.json', 'w') as f:
    json.dump({
        'by_category': dict(results),
        'by_severity': dict(severity_results)
    }, f, indent=2)
" >> "${LOG_FILE}" 2>&1

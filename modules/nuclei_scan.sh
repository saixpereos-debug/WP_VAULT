#!/bin/bash

# Nuclei scanning module - Vṛthā v2.1
# Enhanced with OWASP Top 10 template coverage

TARGET=$1
OUTPUT_DIR=$2

# Try to use live hosts first, fallback to all URLs
LIVE_HOSTS_FILE="${RESULTS_DIR}/httpx/live_hosts.txt"
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

if [ ! -s "${RESULTS_DIR}/httpx/live_hosts.txt" ]; then
    echo "  [!] No live hosts found in ${RESULTS_DIR}/httpx/live_hosts.txt. Skipping Nuclei." >> "${LOG_FILE}"
    # Use target if live hosts missing and we want to force
    echo "https://${TARGET}" > "${OUTPUT_DIR}/urls_to_scan.txt"
else
    # Use live hosts for Nuclei scan
    cp "${RESULTS_DIR}/httpx/live_hosts.txt" "${OUTPUT_DIR}/urls_to_scan.txt"
fi

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
echo "  Updating Nuclei templates..." >> "${LOG_FILE}"
${NUCLEI_PATH} -update-templates >> "${LOG_FILE}" 2>&1

# ============================================
# OWASP Top 10 Custom Templates (2021 + 2025)
# ============================================
OWASP_TEMPLATES_DIR="templates/nuclei/owasp"

if [ -d "${OWASP_TEMPLATES_DIR}" ]; then
    echo "Running custom OWASP Top 10 templates from ${OWASP_TEMPLATES_DIR}..." >> "${LOG_FILE}"
    
    # Run loop for categories
    for category in a01 a02 a03 a04 a05 a06 a07 a08 a09 a10; do
        template_path=$(find "${OWASP_TEMPLATES_DIR}" -maxdepth 1 -name "${category}*" -type d | head -n 1)
        if [ -d "$template_path" ]; then
             echo "    Scanning Category: $(basename "$template_path")" >> "${LOG_FILE}"
             ${NUCLEI_PATH} -list "${URL_LIST}" -t "${template_path}/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_${category}.txt" -j > "${OUTPUT_DIR}/nuclei_debug_${category}.log" 2>&1 || true
        else
             echo "    [!] Template category not found: ${category}*" >> "${LOG_FILE}"
        fi
    done
else
    echo "  [!] OWASP Custom Templates directory not found at ${OWASP_TEMPLATES_DIR}. Skipping OWASP scan." >> "${LOG_FILE}"
fi

# ============================================
# Official and Community Templates
# ============================================

# Custom WordPress templates (legacy)
if [ -d "templates/nuclei/" ]; then
    echo "  Running local custom templates..." >> "${LOG_FILE}"
    ${NUCLEI_PATH} -list "${URL_LIST}" -t templates/nuclei/ -exclude templates/nuclei/owasp/ ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_custom.txt" -j >> "${LOG_FILE}" 2>&1 || true
fi

# Official WordPress templates 
echo "  Running Official WordPress templates (${WORDPRESS_TEMPLATES})..." >> "${LOG_FILE}"
${NUCLEI_PATH} -list "${URL_LIST}" -t "${WORDPRESS_TEMPLATES}" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_official.txt" -j >> "${LOG_FILE}" 2>&1 || true

# ============================================
# Comprehensive Multi-Stage OWASP Assessment
# ============================================
COMPREHENSIVE_TEMPLATE="templates/nuclei/wordpress/wordpress-comprehensive-security-check.yaml"
if [ -f "${COMPREHENSIVE_TEMPLATE}" ]; then
    echo "Running comprehensive 15-stage OWASP assessment..." >> "${LOG_FILE}"
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${COMPREHENSIVE_TEMPLATE}" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_comprehensive.txt" -j >> "${LOG_FILE}" 2>&1 || true
else
    echo "  [!] Comprehensive template not found at ${COMPREHENSIVE_TEMPLATE}" >> "${LOG_FILE}"
fi

# CVE templates (critical/high only)
mkdir -p "${OUTPUT_DIR}"

if [ ! -s "${RESULTS_DIR}/httpx/live_hosts.txt" ] && [ ! -s "${URL_LIST}" ]; then
    echo "  [!] No live hosts found to scan. Skipping Nuclei." >> "${LOG_FILE}"
    exit 0
fi

echo "Running Nuclei Scans for ${TARGET}..." >> "${LOG_FILE}"
echo "Running Nuclei CVE detection..." >> "${LOG_FILE}"
${NUCLEI_PATH} -list "${URL_LIST}" -tags cve,wordpress -severity critical,high ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_cves.txt" -j >> "${LOG_FILE}" 2>&1 || true

# Parse and categorize
python3 -c "
import json
import os
from collections import defaultdict

results = defaultdict(list)
severity_results = defaultdict(list)

def process_file(filepath, key):
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            item = json.loads(line)
                            results[key].append(item)
                            severity = item.get('info', {}).get('severity', 'info')
                            severity_results[severity].append(item)
                        except: pass
        except: pass

# Process all potential output files
process_file('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_custom.txt', 'wordpress_custom')
process_file('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_official.txt', 'wordpress_official')
process_file('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_general.txt', 'general')
process_file('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_owasp.txt', 'owasp')
process_file('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_cves.txt', 'cves')

# Ensure we always have at least empty lists for expected keys if we want consistency
final_data = {
    'by_category': dict(results),
    'by_severity': dict(severity_results),
    'summary': {
        'total_findings': sum(len(v) for v in results.values()),
        'critical': len(severity_results.get('critical', [])),
        'high': len(severity_results.get('high', [])),
        'medium': len(severity_results.get('medium', [])),
        'low': len(severity_results.get('low', [])),
        'info': len(severity_results.get('info', []))
    }
}

with open('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_categorized.json', 'w') as f:
    json.dump(final_data, f, indent=2)
" >> "${LOG_FILE}" 2>&1

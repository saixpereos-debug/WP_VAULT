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

# ============================================
# OWASP Top 10 Custom Templates (2021 + 2025)
# ============================================
OWASP_TEMPLATES_DIR="templates/nuclei/owasp"

if [ -d "${OWASP_TEMPLATES_DIR}" ]; then
    echo "Running custom OWASP Top 10 templates..." >> "${LOG_FILE}"
    
    # A01: Broken Access Control
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a01-broken-access-control/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a01.txt" -json >/dev/null 2>&1 || true
    
    # A02: Cryptographic Failures
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a02-cryptographic-failures/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a02.txt" -json >/dev/null 2>&1 || true
    
    # A03: Injection
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a03-injection/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a03.txt" -json >/dev/null 2>&1 || true
    
    # A04: Insecure Design
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a04-insecure-design/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a04.txt" -json >/dev/null 2>&1 || true
    
    # A05: Security Misconfiguration
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a05-security-misconfiguration/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a05.txt" -json >/dev/null 2>&1 || true
    
    # A06: Outdated Components
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a06-outdated-components/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a06.txt" -json >/dev/null 2>&1 || true
    
    # A07: Auth Failures
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a07-auth-failures/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a07.txt" -json >/dev/null 2>&1 || true
    
    # A08: Integrity Failures
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a08-integrity-failures/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a08.txt" -json >/dev/null 2>&1 || true
    
    # A09: Logging/Monitoring
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a09-logging-monitoring/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a09.txt" -json >/dev/null 2>&1 || true
    
    # A10: SSRF
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${OWASP_TEMPLATES_DIR}/a10-ssrf/" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_a10.txt" -json >/dev/null 2>&1 || true
fi

# ============================================
# Official and Community Templates
# ============================================

# Custom WordPress templates (legacy)
${NUCLEI_PATH} -list "${URL_LIST}" -t templates/nuclei/ -exclude templates/nuclei/owasp/ ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_custom.txt" -json >/dev/null 2>&1 || true

# Official WordPress templates 
${NUCLEI_PATH} -list "${URL_LIST}" -t ${WORDPRESS_TEMPLATES} ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_official.txt" -json >/dev/null 2>&1 || true

# ============================================
# Comprehensive Multi-Stage OWASP Assessment
# ============================================
COMPREHENSIVE_TEMPLATE="templates/nuclei/wordpress/wordpress-comprehensive-security-check.yaml"
if [ -f "${COMPREHENSIVE_TEMPLATE}" ]; then
    echo "Running comprehensive 15-stage OWASP assessment..." >> "${LOG_FILE}"
    ${NUCLEI_PATH} -list "${URL_LIST}" -t "${COMPREHENSIVE_TEMPLATE}" ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_owasp_comprehensive.txt" -json >/dev/null 2>&1 || true
fi

# CVE templates (critical/high only)
echo "Running Nuclei CVE detection..." >> "${LOG_FILE}"
${NUCLEI_PATH} -list "${URL_LIST}" -tags cve,wordpress -severity critical,high ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_cves.txt" -json >/dev/null 2>&1 || true

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

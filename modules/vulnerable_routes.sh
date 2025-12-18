#!/bin/bash

# Vulnerable Route Analysis Module
# Analyzes discovered URLs for common vulnerability patterns

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt"

mkdir -p "${OUTPUT_DIR}"

echo "Analyzing URLs for vulnerable patterns..." >> "${LOG_FILE}"

# Check if master URLs file exists
if [ ! -f "${URLS_FILE}" ]; then
    echo "  No master URLs file found. Skipping route analysis." >> "${LOG_FILE}"
    exit 0
fi

URL_COUNT=$(wc -l < "${URLS_FILE}")
echo "  Analyzing ${URL_COUNT} URLs for vulnerability patterns..." >> "${LOG_FILE}"

# Run vulnerable route analyzer
python3 utils/vulnerable_routes.py "${URLS_FILE}" "${OUTPUT_DIR}/vapt_${TARGET}_vulnerable_routes.json" 2>> "${LOG_FILE}"

# Check results
if [ -f "${OUTPUT_DIR}/vapt_${TARGET}_vulnerable_routes.json" ]; then
    # Extract summary
    IDOR_COUNT=$(jq -r '.summary.by_type.IDOR // 0' "${OUTPUT_DIR}/vapt_${TARGET}_vulnerable_routes.json" 2>/dev/null || echo "0")
    SQLI_COUNT=$(jq -r '.summary.by_type."SQL Injection" // 0' "${OUTPUT_DIR}/vapt_${TARGET}_vulnerable_routes.json" 2>/dev/null || echo "0")
    PATH_TRAV_COUNT=$(jq -r '.summary.by_type."Path Traversal" // 0' "${OUTPUT_DIR}/vapt_${TARGET}_vulnerable_routes.json" 2>/dev/null || echo "0")
    SSRF_COUNT=$(jq -r '.summary.by_type.SSRF // 0' "${OUTPUT_DIR}/vapt_${TARGET}_vulnerable_routes.json" 2>/dev/null || echo "0")
    XSS_COUNT=$(jq -r '.summary.by_type.XSS // 0' "${OUTPUT_DIR}/vapt_${TARGET}_vulnerable_routes.json" 2>/dev/null || echo "0")
    
    TOTAL_VULNS=$((IDOR_COUNT + SQLI_COUNT + PATH_TRAV_COUNT + SSRF_COUNT + XSS_COUNT))
    
    echo "  Vulnerable Route Analysis Complete:" >> "${LOG_FILE}"
    echo "    IDOR: ${IDOR_COUNT}" >> "${LOG_FILE}"
    echo "    SQL Injection: ${SQLI_COUNT}" >> "${LOG_FILE}"
    echo "    Path Traversal: ${PATH_TRAV_COUNT}" >> "${LOG_FILE}"
    echo "    SSRF: ${SSRF_COUNT}" >> "${LOG_FILE}"
    echo "    XSS: ${XSS_COUNT}" >> "${LOG_FILE}"
    echo "    Total: ${TOTAL_VULNS}" >> "${LOG_FILE}"
    
    echo "VULNERABLE_ROUTES=${TOTAL_VULNS}"
else
    echo "  Route analysis failed." >> "${LOG_FILE}"
fi

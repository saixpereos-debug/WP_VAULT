#!/bin/bash

# Fuzzing & Exploitation Module (V3)
# Uses FFuf for discovery, Dalfox for XSS, SQLMap for SQLi

TARGET=$1
OUTPUT_DIR=$2
WORDLIST="${3:-tools/wordlists/raft-medium-directories.txt}"
URL_LIST=$4 # Optional: List of URLs to test for XSS/SQLi
LOG_FILE="${5:-/dev/null}"

mkdir -p "${OUTPUT_DIR}"

echo "Running Fuzzing & Exploitation for ${TARGET}..." >> "${LOG_FILE}"

# 1. Directory Fuzzing (FFUF)
if [ -x "$FFUF_PATH" ] && [ -f "$WORDLIST" ]; then
    echo "  Running FFUF Directory Fuzzing..." >> "${LOG_FILE}"
    $FFUF_PATH -u "https://${TARGET}/FUZZ" -w "$WORDLIST" $FFUF_OPTIONS \
        -o "${OUTPUT_DIR}/vapt_${TARGET}_ffuf.json" >> "${LOG_FILE}" 2>&1
else
    echo "  Skipping FFUF (Missing tool or wordlist)." >> "${LOG_FILE}"
fi

# 2. XSS Scanning (Dalfox) - Use vulnerable route analysis
if [ -x "$DALFOX_PATH" ]; then
    echo "  Running Dalfox XSS Scan on vulnerable candidates..." >> "${LOG_FILE}"
    
    # Check if vulnerable routes analysis exists
    ROUTES_FILE="${RESULTS_DIR}/route_analysis/vapt_${TARGET}_vulnerable_routes.json"
    if [ -f "${ROUTES_FILE}" ]; then
        # Extract XSS candidates from route analysis
        jq -r '.findings.XSS[]?.url // empty' "${ROUTES_FILE}" 2>/dev/null > "${OUTPUT_DIR}/xss_candidates.txt"
    else
        # Fallback: Filter URLs with parameters
        grep "?" "$URL_LIST" 2>/dev/null > "${OUTPUT_DIR}/xss_candidates.txt" || touch "${OUTPUT_DIR}/xss_candidates.txt"
    fi
    
    count=$(wc -l < "${OUTPUT_DIR}/xss_candidates.txt" 2>/dev/null || echo "0")
    
    if [ "$count" -gt 0 ]; then
        cat "${OUTPUT_DIR}/xss_candidates.txt" | head -n 20 | $DALFOX_PATH pipe $DALFOX_OPTIONS \
            -o "${OUTPUT_DIR}/vapt_${TARGET}_dalfox.txt" >> "${LOG_FILE}" 2>&1 || true
    else
        echo "  No XSS candidates found." >> "${LOG_FILE}"
    fi
    rm -f "${OUTPUT_DIR}/xss_candidates.txt"
fi

# 3. SQL Injection (SQLMap) - Use vulnerable route analysis
if [ -x "$SQLMAP_PATH" ]; then
    echo "  Running SQLMap on vulnerable candidates..." >> "${LOG_FILE}"
    
    # Check if vulnerable routes analysis exists
    ROUTES_FILE="${RESULTS_DIR}/route_analysis/vapt_${TARGET}_vulnerable_routes.json"
    if [ -f "${ROUTES_FILE}" ]; then
        # Extract SQLi candidates from route analysis
        jq -r '.findings."SQL Injection"[]?.url // empty' "${ROUTES_FILE}" 2>/dev/null | head -n 5 > "${OUTPUT_DIR}/sqli_candidates.txt"
    else
        # Fallback: Simple grep for suspicious params
        grep -E "id=|user=|page=|search=|q=" "$URL_LIST" 2>/dev/null | head -n 5 > "${OUTPUT_DIR}/sqli_candidates.txt" || touch "${OUTPUT_DIR}/sqli_candidates.txt"
    fi
    
    if [ -s "${OUTPUT_DIR}/sqli_candidates.txt" ]; then
        echo "  Testing $(wc -l < "${OUTPUT_DIR}/sqli_candidates.txt") SQLi candidates..." >> "${LOG_FILE}"
        $SQLMAP_PATH -m "${OUTPUT_DIR}/sqli_candidates.txt" --batch --smart --dbs --random-agent \
            --output-dir="${OUTPUT_DIR}/sqlmap" >> "${LOG_FILE}" 2>&1 || true
    else
        echo "  No SQLi candidates found." >> "${LOG_FILE}"
    fi
    rm -f "${OUTPUT_DIR}/sqli_candidates.txt"
fi

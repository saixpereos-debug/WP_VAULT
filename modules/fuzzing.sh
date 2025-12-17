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

# 2. XSS Scanning (Dalfox)
if [ -x "$DALFOX_PATH" ] && [ -f "$URL_LIST" ]; then
    echo "  Running Dalfox XSS Scan..." >> "${LOG_FILE}"
    # Filter URLs with parameters
    grep "?" "$URL_LIST" > "${OUTPUT_DIR}/params.txt"
    count=$(wc -l < "${OUTPUT_DIR}/params.txt")
    
    if [ "$count" -gt 0 ]; then
        cat "${OUTPUT_DIR}/params.txt" | $DALFOX_PATH pipe $DALFOX_OPTIONS \
            -o "${OUTPUT_DIR}/vapt_${TARGET}_dalfox.txt" >> "${LOG_FILE}" 2>&1
    else
        echo "  No parameters found for XSS testing." >> "${LOG_FILE}"
    fi
    rm "${OUTPUT_DIR}/params.txt" 2>/dev/null
fi

# 3. SQL Injection (SQLMap)
# We limit this to very specific suspicious params to avoid 5-day scans
if [ -x "$SQLMAP_PATH" ] && [ -f "$URL_LIST" ]; then
     echo "  Checking for SQLi candidates..." >> "${LOG_FILE}"
     # Simple grep for id=, user=, page=
     grep -E "id=|user=|page=|search=|q=" "$URL_LIST" | head -n 5 > "${OUTPUT_DIR}/sqli_candidates.txt"
     
     if [ -s "${OUTPUT_DIR}/sqli_candidates.txt" ]; then
         echo "  Running SQLMap on top 5 candidates..." >> "${LOG_FILE}"
         $SQLMAP_PATH -m "${OUTPUT_DIR}/sqli_candidates.txt" --batch --smart --dbs --random-agent \
             --output-dir="${OUTPUT_DIR}/sqlmap" >> "${LOG_FILE}" 2>&1
     fi
fi

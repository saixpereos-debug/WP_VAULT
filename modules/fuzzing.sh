#!/bin/bash

# Fuzzing & Exploitation Module (V3)
# Uses FFuf for discovery, Dalfox for XSS, SQLMap for SQLi

TARGET=$1
OUTPUT_DIR=$2
WORDLIST="${3:-tools/wordlists/raft-medium-directories.txt}"
URL_LIST=$4 # Optional: List of URLs to test for XSS/SQLi
AUTH_COOKIE=$5
LOG_FILE="${6:-/dev/null}"

mkdir -p "${OUTPUT_DIR}"

echo "Running Fuzzing & Exploitation for ${TARGET}..." >> "${LOG_FILE}"

# Intelligent Wordlist Selection
SELECTED_WORDLIST="$WORDLIST"
TECH_MAPPING="config/tech_wordlists.json"
HTTPX_RESULTS="${RESULTS_DIR}/httpx/vapt_${TARGET}_httpx_combined.json"

if [ -f "$TECH_MAPPING" ] && [ -f "$HTTPX_RESULTS" ]; then
    echo "  Optimizing wordlist based on technology detection..." >> "${LOG_FILE}"
    # Extract all technologies from httpx results (handling JSONL format)
    DETECTED_TECHS=$(jq -r '.tech[]? // .technologies[]? // empty' "$HTTPX_RESULTS" | tr '[:upper:]' '[:lower:]' | sort -u)
    
    # Check for matches in our mapping
    for tech in $DETECTED_TECHS; do
        MAPPED_LIST=$(jq -r ".[\"$tech\"] // empty" "$TECH_MAPPING")
        if [ -n "$MAPPED_LIST" ] && [ -f "$MAPPED_LIST" ]; then
            SELECTED_WORDLIST="$MAPPED_LIST"
            echo "  Match found! Using tech-specific wordlist: $tech -> $SELECTED_WORDLIST" >> "${LOG_FILE}"
            break # Use the first major match
        fi
    done
fi

WORDLIST="$SELECTED_WORDLIST"

# 1. Directory Fuzzing (FFUF)
if [ -x "$FFUF_PATH" ] && [ -f "$WORDLIST" ]; then
    echo "  Running FFUF Directory Fuzzing..." >> "${LOG_FILE}"
    FFUF_CMD="$FFUF_PATH -u \"https://${TARGET}/FUZZ\" -w \"$WORDLIST\" $FFUF_OPTIONS -o \"${OUTPUT_DIR}/vapt_${TARGET}_ffuf.json\""
    [ -n "$AUTH_COOKIE" ] && FFUF_CMD="$FFUF_CMD -H \"Cookie: $AUTH_COOKIE\""
    eval "$FFUF_CMD" >> "${LOG_FILE}" 2>&1
else
    echo "  Skipping FFUF (Missing tool or wordlist)." >> "${LOG_FILE}"
fi

# 2. XSS Scanning (Dalfox) - Use vulnerable route analysis + URL list
if [ -x "$DALFOX_PATH" ]; then
    echo "  Running Dalfox XSS Scan..." >> "${LOG_FILE}"
    
    # Aggregate XSS candidates
    ROUTES_FILE="${RESULTS_DIR}/route_analysis/vapt_${TARGET}_vulnerable_routes.json"
    if [ -f "${ROUTES_FILE}" ]; then
        jq -r '.findings.XSS[]?.url // empty' "${ROUTES_FILE}" 2>/dev/null > "${OUTPUT_DIR}/xss_candidates.txt"
    fi
    # Also add URLs with parameters from master list
    grep "?" "$URL_LIST" 2>/dev/null >> "${OUTPUT_DIR}/xss_candidates.txt"
    sort -u "${OUTPUT_DIR}/xss_candidates.txt" -o "${OUTPUT_DIR}/xss_candidates.txt"
    
    count=$(wc -l < "${OUTPUT_DIR}/xss_candidates.txt" 2>/dev/null || echo "0")
    
    if [ "$count" -gt 0 ]; then
        DALFOX_CMD="cat \"${OUTPUT_DIR}/xss_candidates.txt\" | head -n 50 | $DALFOX_PATH pipe $DALFOX_OPTIONS -o \"${OUTPUT_DIR}/vapt_${TARGET}_dalfox.txt\""
        [ -n "$AUTH_COOKIE" ] && DALFOX_CMD="$DALFOX_CMD -C \"$AUTH_COOKIE\""
        eval "$DALFOX_CMD" >> "${LOG_FILE}" 2>&1 || true
    else
        echo "  No XSS candidates found." >> "${LOG_FILE}"
    fi
    rm -f "${OUTPUT_DIR}/xss_candidates.txt"
fi

# 3. SQL Injection (SQLMap) - Use vulnerable route analysis + automated crawling
if [ -x "$SQLMAP_PATH" ]; then
    echo "  Running SQLMap for SQL Injection..." >> "${LOG_FILE}"
    
    # Extract SQLi candidates
    ROUTES_FILE="${RESULTS_DIR}/route_analysis/vapt_${TARGET}_vulnerable_routes.json"
    if [ -f "${ROUTES_FILE}" ]; then
        jq -r '.findings."SQL Injection"[]?.url // empty' "${ROUTES_FILE}" 2>/dev/null > "${OUTPUT_DIR}/sqli_candidates.txt"
    fi
    # Also grab suspicious common params
    grep -iE "id=|user=|page=|search=|q=|cat=|p=|post=|key=|token=|view=|type=" "$URL_LIST" 2>/dev/null >> "${OUTPUT_DIR}/sqli_candidates.txt"
    sort -u "${OUTPUT_DIR}/sqli_candidates.txt" -o "${OUTPUT_DIR}/sqli_candidates.txt"
    
    if [ -s "${OUTPUT_DIR}/sqli_candidates.txt" ]; then
        echo "  Testing SQLi candidates with smart crawl and forms support..." >> "${LOG_FILE}"
        SQLMAP_CMD="$SQLMAP_PATH -m \"${OUTPUT_DIR}/sqli_candidates.txt\" --batch --smart --forms --crawl=2 --random-agent --output-dir=\"${OUTPUT_DIR}/sqlmap\""
        [ -n "$AUTH_COOKIE" ] && SQLMAP_CMD="$SQLMAP_CMD --cookie=\"$AUTH_COOKIE\""
        eval "$SQLMAP_CMD" >> "${LOG_FILE}" 2>&1 || true
    else
        # If no clear candidates, try smart crawl on the main page
        echo "  No clear SQLi candidates. Running smart crawl on root..." >> "${LOG_FILE}"
        SQLMAP_CMD="$SQLMAP_PATH -u \"https://${TARGET}\" --batch --smart --forms --crawl=2 --level=2 --risk=1 --random-agent --output-dir=\"${OUTPUT_DIR}/sqlmap\""
        [ -n "$AUTH_COOKIE" ] && SQLMAP_CMD="$SQLMAP_CMD --cookie=\"$AUTH_COOKIE\""
        eval "$SQLMAP_CMD" >> "${LOG_FILE}" 2>&1 || true
    fi
    rm -f "${OUTPUT_DIR}/sqli_candidates.txt"
fi

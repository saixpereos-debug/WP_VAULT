#!/bin/bash

# Parameter and Endpoint Discovery Module for Vṛthā

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

echo "Starting Parameter and Endpoint Discovery for ${TARGET}..." >> "${LOG_FILE}"

# 1. ParamSpider (Discovery of parameters from web archives)
if command -v paramspider >/dev/null 2>&1; then
    echo "[+] Running ParamSpider..." >> "${LOG_FILE}"
    paramspider -d "${TARGET}" -o "${OUTPUT_DIR}/paramspider_results.txt" >> "${LOG_FILE}" 2>&1
fi

# 2. Arjun (Parameter Discovery)
if command -v arjun >/dev/null 2>&1; then
    echo "[+] Running Arjun on main target..." >> "${LOG_FILE}"
    arjun -u "https://${TARGET}" -oT "${OUTPUT_DIR}/arjun_results.txt" >> "${LOG_FILE}" 2>&1
    
    # Also run on a few interesting URLs from master list
    if [ -f "${URLS_FILE}" ]; then
        grep -v "\*" "${URLS_FILE}" | grep -E "^https?://" | head -n 5 | while read -r url; do
             if [ -n "$url" ]; then
                arjun -u "$url" -oT "${OUTPUT_DIR}/arjun_$(echo "$url" | md5sum | cut -d' ' -f1).txt" >> "${LOG_FILE}" 2>&1
             fi
        done
    fi
fi

# 3. FFUF for hidden files and directories discovery
if [ -f "tools/wordlists/raft-medium-directories.txt" ]; then
    echo "[+] Running FFUF for Directory Brute-forcing..." >> "${LOG_FILE}"
    ffuf -u "https://${TARGET}/FUZZ" -w "tools/wordlists/raft-medium-directories.txt" \
        -mc 200,301,302,403 -o "${OUTPUT_DIR}/ffuf_dirs.json" >> "${LOG_FILE}" 2>&1
fi

# Combine findings
cat "${OUTPUT_DIR}"/*.txt > "${OUTPUT_DIR}/vapt_${TARGET}_params_all.txt" 2>/dev/null

echo "Parameter Discovery completed." >> "${LOG_FILE}"
exit 0

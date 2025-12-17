#!/bin/bash

# HTTPx analysis module

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

# Prepare list of URLs for httpx
URL_LIST="${OUTPUT_DIR}/urls_to_scan.txt"
if [ -f "${URLS_FILE}" ]; then
    cat "${URLS_FILE}" > "${URL_LIST}"
else
    echo "https://${TARGET}" > "${URL_LIST}"
fi

# Tech Detection
# We prioritize httpx -tech-detect (which uses wappalyzer fingerprints) as it is faster and built-in.
# If wappalyzer-cli is installed, we can use it for deeper scan, but for now we rely on httpx.

echo "Running Tech Detection (HTTPX)..." >> "${LOG_FILE}"
# WhatWeb is deprecated in this workflow in favor of modern JSON-based tools
# if [ -x "$WHATWEB_PATH" ]; then ... fi  <-- REMOVED

# Run httpx with enhanced flags
# -sc: status code
# -cl: content length
# -location: redirect location
# -title: page title
# -td: tech detect
# -server: server header
${HTTPX_PATH} -l "${URL_LIST}" -sc -cl -location -title -td -server -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_tech.json" >/dev/null 2>&1

${HTTPX_PATH} -l "${URL_LIST}" -mc "${HTTPX_MATCHER_CODES}" -md "${HTTPX_MATCHER_DOMAINS}" -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_matchers.json" >/dev/null 2>&1

${HTTPX_PATH} -l "${URL_LIST}" -path "${HTTPX_PATHS_TO_PROBE}" -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_paths.json" >/dev/null 2>&1

${HTTPX_PATH} -l "${URL_LIST}" -x "${HTTPX_METHODS_TO_CHECK}" -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_methods.json" >/dev/null 2>&1

# Combine all httpx results
python3 -c "
import json
import os
import glob

# Read all JSON files
tech_data = []
matcher_data = []
path_data = []
method_data = []

def read_json_lines(filepath):
    data = []
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    try:
                        data.append(json.loads(line))
                    except: pass
        except: pass
    return data

tech_data = read_json_lines('${OUTPUT_DIR}/vapt_${TARGET}_httpx_tech.json')
matcher_data = read_json_lines('${OUTPUT_DIR}/vapt_${TARGET}_httpx_matchers.json')
path_data = read_json_lines('${OUTPUT_DIR}/vapt_${TARGET}_httpx_paths.json')
method_data = read_json_lines('${OUTPUT_DIR}/vapt_${TARGET}_httpx_methods.json')

combined_data = {
    'tech_detection': tech_data,
    'custom_matchers': matcher_data,
    'path_probing': path_data,
    'method_discovery': method_data
}

with open('${OUTPUT_DIR}/vapt_${TARGET}_httpx_combined.json', 'w') as f:
    json.dump(combined_data, f, indent=2)
" >> "${LOG_FILE}" 2>&1

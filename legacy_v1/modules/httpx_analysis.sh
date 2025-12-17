#!/bin/bash

# HTTPx analysis module for tech detection, path probing, and HTTP method discovery

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

echo "Running HTTPx analysis for ${TARGET}..." | tee -a "${LOG_FILE}"

# Prepare list of URLs for httpx
URL_LIST="${OUTPUT_DIR}/urls_to_scan.txt"
cat "${URLS_FILE}" > "${URL_LIST}"

# Run httpx for tech detection
echo "Running httpx for technology detection..." | tee -a "${LOG_FILE}"
${HTTPX_PATH} -l "${URL_LIST}" -tech-detect -status-code -title -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_tech.json" 2>&1

# Run httpx with custom matchers
echo "Running httpx with custom matchers..." | tee -a "${LOG_FILE}"
${HTTPX_PATH} -l "${URL_LIST}" -mc "${HTTPX_MATCHER_CODES}" -md "${HTTPX_MATCHER_DOMAINS}" -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_matchers.json" 2>&1

# Run httpx for path probing
echo "Running httpx for path probing..." | tee -a "${LOG_FILE}"
${HTTPX_PATH} -l "${URL_LIST}" -path "${HTTPX_PATHS_TO_PROBE}" -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_paths.json" 2>&1

# Run httpx for HTTP method discovery
echo "Running httpx for HTTP method discovery..." | tee -a "${LOG_FILE}"
${HTTPX_PATH} -l "${URL_LIST}" -x "${HTTPX_METHODS_TO_CHECK}" -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_methods.json" 2>&1

# Combine all httpx results
echo "Combining httpx results..." | tee -a "${LOG_FILE}"
python3 -c "
import json

# Read all JSON files
tech_data = []
matcher_data = []
path_data = []
method_data = []

try:
    with open('${OUTPUT_DIR}/vapt_${TARGET}_httpx_tech.json', 'r') as f:
        for line in f:
            tech_data.append(json.loads(line))
except:
    pass

try:
    with open('${OUTPUT_DIR}/vapt_${TARGET}_httpx_matchers.json', 'r') as f:
        for line in f:
            matcher_data.append(json.loads(line))
except:
    pass

try:
    with open('${OUTPUT_DIR}/vapt_${TARGET}_httpx_paths.json', 'r') as f:
        for line in f:
            path_data.append(json.loads(line))
except:
    pass

try:
    with open('${OUTPUT_DIR}/vapt_${TARGET}_httpx_methods.json', 'r') as f:
        for line in f:
            method_data.append(json.loads(line))
except:
    pass

# Combine all data
combined_data = {
    'tech_detection': tech_data,
    'custom_matchers': matcher_data,
    'path_probing': path_data,
    'method_discovery': method_data
}

# Save combined data
with open('${OUTPUT_DIR}/vapt_${TARGET}_httpx_combined.json', 'w') as f:
    json.dump(combined_data, f, indent=2)
"

echo "HTTPx analysis completed"

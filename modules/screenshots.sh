#!/bin/bash

# Screenshot capture module

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

echo "Capturing screenshots for ${TARGET}..." | tee -a "${LOG_FILE}"

# Prepare list of URLs for Gowitness
URL_LIST="${OUTPUT_DIR}/urls_to_screenshot.txt"
cat "${URLS_FILE}" | head -n 50 > "${URL_LIST}"  # Limit to first 50 URLs

# Run Gowitness
echo "Running Gowitness..." | tee -a "${LOG_FILE}"
 ${GOWITNESS_PATH} file -f "${URL_LIST}" -P "${OUTPUT_DIR}" ${GOWITNESS_OPTIONS}

# Create a list of captured screenshots
echo "Creating list of captured screenshots..." | tee -a "${LOG_FILE}"
find "${OUTPUT_DIR}" -name "*.png" -type f > "${OUTPUT_DIR}/vapt_${TARGET}_screenshots_list.txt"

echo "Screenshot capture completed. $(cat "${OUTPUT_DIR}/vapt_${TARGET}_screenshots_list.txt" | wc -l) screenshots captured."

#!/bin/bash

# Firewall detection module

TARGET=$1
OUTPUT_DIR=$2

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_firewall_detection.txt"

echo "Detecting firewall for ${TARGET}..." | tee -a "${LOG_FILE}"

# Using wafw00f
echo "=== wafw00f ===" | tee -a "${OUTPUT_FILE}"
 ${WAFW00F_PATH} ${TARGET} | tee -a "${OUTPUT_FILE}"

# Additional checks
echo -e "\n=== Additional Checks ===" | tee -a "${OUTPUT_FILE}"

# Check for Cloudflare
if curl -s -I "https://${TARGET}" | grep -i "cf-ray" > /dev/null; then
    echo "Cloudflare detected" | tee -a "${OUTPUT_FILE}"
else
    echo "Cloudflare not detected" | tee -a "${OUTPUT_FILE}"
fi

# Check for Sucuri
if curl -s "https://${TARGET}" | grep -i "sucuri" > /dev/null; then
    echo "Sucuri detected" | tee -a "${OUTPUT_FILE}"
else
    echo "Sucuri not detected" | tee -a "${OUTPUT_FILE}"
fi

echo "Firewall detection completed"

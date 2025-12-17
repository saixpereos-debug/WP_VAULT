#!/bin/bash

# Firewall detection module

TARGET=$1
OUTPUT_DIR=$2

mkdir -p "${OUTPUT_DIR}"
OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_firewall_detection.txt"

echo "=== wafw00f ===" > "${OUTPUT_FILE}"
${WAFW00F_PATH} ${TARGET} >> "${OUTPUT_FILE}" 2>&1

echo -e "\n=== Additional Checks ===" >> "${OUTPUT_FILE}"

if curl -s -I "https://${TARGET}" | grep -i "cf-ray" > /dev/null; then
    echo "Cloudflare detected" >> "${OUTPUT_FILE}"
else
    echo "Cloudflare not detected" >> "${OUTPUT_FILE}"
fi

if curl -s "https://${TARGET}" | grep -i "sucuri" > /dev/null; then
    echo "Sucuri detected" >> "${OUTPUT_FILE}"
else
    echo "Sucuri not detected" >> "${OUTPUT_FILE}"
fi

echo -e "\n=== Passive WAF Detection (Nuclei) ===" >> "${OUTPUT_FILE}"
${NUCLEI_PATH} -u "https://${TARGET}" -tags waf -headless -silent >> "${OUTPUT_FILE}" 2>&1

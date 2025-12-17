#!/bin/bash

# DNS information gathering module

TARGET=$1
OUTPUT_DIR=$2

mkdir -p "${OUTPUT_DIR}"
OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_dns_info.txt"

echo "=== nslookup ===" > "${OUTPUT_FILE}"
nslookup ${TARGET} >> "${OUTPUT_FILE}" 2>/dev/null

echo -e "\n=== dig ===" >> "${OUTPUT_FILE}"
dig ${TARGET} ANY >> "${OUTPUT_FILE}" 2>/dev/null

echo -e "\n=== host ===" >> "${OUTPUT_FILE}"
host ${TARGET} >> "${OUTPUT_FILE}" 2>/dev/null

echo -e "\n=== DNS Zone Transfer Attempt ===" >> "${OUTPUT_FILE}"
for ns in $(dig ${TARGET} NS +short); do
    dig axfr ${TARGET} @${ns} >> "${OUTPUT_FILE}" 2>/dev/null
done

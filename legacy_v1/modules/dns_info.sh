#!/bin/bash

# DNS information gathering module

TARGET=$1
OUTPUT_DIR=$2

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_dns_info.txt"

echo "Gathering DNS information for ${TARGET}..." | tee -a "${LOG_FILE}"

# Using nslookup
echo "=== nslookup ===" | tee -a "${OUTPUT_FILE}"
nslookup ${TARGET} | tee -a "${OUTPUT_FILE}"

# Using dig
echo -e "\n=== dig ===" | tee -a "${OUTPUT_FILE}"
dig ${TARGET} ANY | tee -a "${OUTPUT_FILE}"

# Using host
echo -e "\n=== host ===" | tee -a "${OUTPUT_FILE}"
host ${TARGET} | tee -a "${OUTPUT_FILE}"

# DNS zone transfer attempt
echo -e "\n=== DNS Zone Transfer Attempt ===" | tee -a "${OUTPUT_FILE}"
for ns in $(dig ${TARGET} NS +short); do
    echo "Attempting zone transfer with ${ns}..." | tee -a "${OUTPUT_FILE}"
    dig axfr ${TARGET} @${ns} | tee -a "${OUTPUT_FILE}"
done

echo "DNS information gathering completed"

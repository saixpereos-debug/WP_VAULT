#!/bin/bash

# DNS information gathering module

TARGET=$1
OUTPUT_DIR=$2

mkdir -p "${OUTPUT_DIR}"
OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_dns_info.txt"

# Optimized DNS Recon
echo "=== DNS Security Records ===" > "${OUTPUT_FILE}"

echo -e "\n[+] Nameservers (NS):" >> "${OUTPUT_FILE}"
dig +short NS ${TARGET} >> "${OUTPUT_FILE}"

echo -e "\n[+] Mail Servers (MX):" >> "${OUTPUT_FILE}"
dig +short MX ${TARGET} >> "${OUTPUT_FILE}"

echo -e "\n[+] TXT Records (SPF/DMARC/Verification):" >> "${OUTPUT_FILE}"
dig +short TXT ${TARGET} >> "${OUTPUT_FILE}"
dig +short TXT _dmarc.${TARGET} >> "${OUTPUT_FILE}"

echo -e "\n[+] A Records (IPs):" >> "${OUTPUT_FILE}"
dig +short A ${TARGET} >> "${OUTPUT_FILE}"

echo -e "\n[+] CNAME Records:" >> "${OUTPUT_FILE}"
dig +short CNAME ${TARGET} >> "${OUTPUT_FILE}"

# Zone Transfer Attempt (Quick Check)
echo -e "\n[+] Zone Transfer Check:" >> "${OUTPUT_FILE}"
for ns in $(dig +short NS ${TARGET}); do
    timeout 5 dig axfr ${TARGET} @${ns} >> "${OUTPUT_FILE}" 2>&1
done

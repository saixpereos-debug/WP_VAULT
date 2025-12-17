#!/bin/bash

# Network information gathering module

TARGET=$1
OUTPUT_DIR=$2

mkdir -p "${OUTPUT_DIR}"
OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_network_info.txt"

# Get IP address
echo "IP Address:" > "${OUTPUT_FILE}"
nslookup ${TARGET} | grep -A 1 "Name:" | tail -1 | awk '{print $2}' >> "${OUTPUT_FILE}" 2>/dev/null

# Get whois
echo -e "\nWhois Information:" >> "${OUTPUT_FILE}"
whois ${TARGET} >> "${OUTPUT_FILE}" 2>/dev/null

# Get geolocation
echo -e "\nGeolocation Information:" >> "${OUTPUT_FILE}"
IP=$(nslookup ${TARGET} | grep -A 1 "Name:" | tail -1 | awk '{print $2}')
curl -s "http://ip-api.com/json/${IP}" | jq '.' >> "${OUTPUT_FILE}" 2>/dev/null

# Check for open ports using Naabu (Fast)
echo -e "\nPort Scan (Naabu):" >> "${OUTPUT_FILE}"
${NAABU_PATH} -host ${TARGET} ${NAABU_OPTIONS} -silent >> "${OUTPUT_FILE}" 2>/dev/null

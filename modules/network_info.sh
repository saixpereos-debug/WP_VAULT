#!/bin/bash

# Network information gathering module

TARGET=$1
OUTPUT_DIR=$2

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_network_info.txt"

echo "Gathering network information for ${TARGET}..." | tee -a "${LOG_FILE}"

# Get IP address
echo "IP Address:" | tee -a "${OUTPUT_FILE}"
nslookup ${TARGET} | grep -A 1 "Name:" | tail -1 | awk '{print $2}' | tee -a "${OUTPUT_FILE}"

# Get whois information
echo -e "\nWhois Information:" | tee -a "${OUTPUT_FILE}"
whois ${TARGET} | tee -a "${OUTPUT_FILE}"

# Get geolocation information
echo -e "\nGeolocation Information:" | tee -a "${OUTPUT_FILE}"
IP=$(nslookup ${TARGET} | grep -A 1 "Name:" | tail -1 | awk '{print $2}')
curl -s "http://ip-api.com/json/${IP}" | jq '.' | tee -a "${OUTPUT_FILE}"

# Check for open ports (basic scan)
echo -e "\nBasic Port Scan (top 1000):" | tee -a "${OUTPUT_FILE}"
nmap -T4 -F ${TARGET} | tee -a "${OUTPUT_FILE}"

echo "Network information gathering completed"

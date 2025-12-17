#!/bin/bash

# Subdomain enumeration module

TARGET=$1
OUTPUT_DIR=$2
LOG_FILE=$3

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

# Function to run a subdomain enumeration tool
run_tool() {
    local tool_name=$1
    local tool_path=$2
    local tool_options=$3
    local output_file="${OUTPUT_DIR}/vapt_${TARGET}_subdomains_${tool_name}.txt"
    
    echo "Running ${tool_name}..." | tee -a "${LOG_FILE}"
    ${tool_path} -d ${TARGET} ${tool_options} | tee "${output_file}" | sort -u
}

# Run subdomain enumeration tools
run_tool "subfinder" "${SUBFINDER_PATH}" "${SUBFINDER_OPTIONS}"
run_tool "amass" "${AMASS_PATH}" "${AMASS_OPTIONS}"

# Additional method: crt.sh
echo "Running crt.sh..." | tee -a "${LOG_FILE}"
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | jq -r '.[].name_value' | sort -u > "${OUTPUT_DIR}/vapt_${TARGET}_subdomains_crtsh.txt"

# Combine all results and remove duplicates
cat "${OUTPUT_DIR}"/*.txt | sort -u > "${OUTPUT_DIR}/vapt_${TARGET}_subdomains_all.txt"

echo "Found $(cat "${OUTPUT_DIR}/vapt_${TARGET}_subdomains_all.txt" | wc -l) unique subdomains"

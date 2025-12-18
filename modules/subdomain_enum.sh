#!/bin/bash

# Subdomain enumeration module

TARGET=$1
OUTPUT_DIR=$2
# LOG_FILE is exported by main.sh

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

# Function to run a subdomain enumeration tool
run_tool() {
    local tool_name=$1
    local tool_path=$2
    local tool_options=$3
    local output_file="${OUTPUT_DIR}/vapt_${TARGET}_subdomains_${tool_name}.txt"
    
    # Run tool based on name
    if [ "$tool_name" == "subfinder" ]; then
        ${tool_path} -d ${TARGET} ${tool_options} -o "${output_file}" 2>> "${LOG_FILE}" || true
    elif [ "$tool_name" == "amass" ]; then
        ${tool_path} enum -d ${TARGET} ${tool_options} -o "${output_file}" 2>> "${LOG_FILE}" || true
    else
        ${tool_path} -d ${TARGET} ${tool_options} > "${output_file}" 2>> "${LOG_FILE}" || true
    fi
    
    # Sort and deduplicate
    if [ -f "${output_file}" ]; then
        sort -u -o "${output_file}" "${output_file}"
    fi
}

# Run subdomain enumeration tools
echo "Running Subfinder..." >> "${LOG_FILE}"
run_tool "subfinder" "${SUBFINDER_PATH}" "-silent"

echo "Running Amass..." >> "${LOG_FILE}"
run_tool "amass" "${AMASS_PATH}" "-passive"

# Additional method: crt.sh
echo "Querying crt.sh..." >> "${LOG_FILE}"
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > "${OUTPUT_DIR}/vapt_${TARGET}_subdomains_crtsh.txt"

# Combine all results and remove duplicates
cat "${OUTPUT_DIR}"/*.txt | sort -u > "${OUTPUT_DIR}/vapt_${TARGET}_subdomains_all.txt"

# Print summary
TOTAL_SUBDOMAINS=$(wc -l < "${OUTPUT_DIR}/vapt_${TARGET}_subdomains_all.txt")
echo "  Total unique subdomains discovered: ${TOTAL_SUBDOMAINS}" >> "${LOG_FILE}"
echo "SUBDOMAINS_FOUND=${TOTAL_SUBDOMAINS}"

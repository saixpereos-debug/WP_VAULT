#!/bin/bash

# WordPress scanning module

TARGET=$1
OUTPUT_DIR=$2
SUBDOMAINS_FILE="${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

# Function to scan a WordPress site
scan_wordpress() {
    local domain=$1
    local output_file="${OUTPUT_DIR}/vapt_${TARGET}_wpscan_${domain}.txt"
    
    echo "Scanning WordPress site: ${domain}" | tee -a "${LOG_FILE}"
    ${WPSCAN_PATH} --url "https://${domain}" ${WPSCAN_OPTIONS} --output "${output_file}" --format cli 2>&1
}

# Scan the main domain
scan_wordpress "${TARGET}"

# Scan subdomains that might be WordPress sites
while IFS= read -r subdomain; do
    # Quick check if it's a WordPress site
    if curl -s -I "https://${subdomain}" | grep -i "wp-content" > /dev/null; then
        scan_wordpress "${subdomain}"
    fi
done < "${SUBDOMAINS_FILE}"

# Combine all WordPress scan results
cat "${OUTPUT_DIR}"/*.txt > "${OUTPUT_DIR}/vapt_${TARGET}_wpscan_all.txt"

echo "WordPress scanning completed"

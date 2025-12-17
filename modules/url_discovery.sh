#!/bin/bash

# URL/endpoint discovery module

TARGET=$1
OUTPUT_DIR=$2
SUBDOMAINS_FILE="${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

# Function to crawl a domain for URLs
crawl_domain() {
    local domain=$1
    local output_file="${OUTPUT_DIR}/vapt_${TARGET}_urls_${domain}.txt"
    
    ${KATANA_PATH} -u "https://${domain}" ${KATANA_OPTIONS} -o "${output_file}" >> "${LOG_FILE}" 2>&1
    

}

# Crawl the main domain
crawl_domain "${TARGET}"

# Crawl subdomains if file exists
if [ -f "${SUBDOMAINS_FILE}" ]; then
    while IFS= read -r subdomain; do
        crawl_domain "${subdomain}"
    done < "${SUBDOMAINS_FILE}"
fi

# Combine all URLs and remove duplicates
cat "${OUTPUT_DIR}"/*.txt 2>/dev/null | sort -u > "${OUTPUT_DIR}/vapt_${TARGET}_urls_all.txt"

#!/bin/bash

# HTTPx analysis module - Technology detection and analysis

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

# Prepare list of URLs for httpx
URL_LIST="${OUTPUT_DIR}/urls_to_scan.txt"
if [ -f "${URLS_FILE}" ]; then
    cat "${URLS_FILE}" > "${URL_LIST}"
else
    echo "https://${TARGET}" > "${URL_LIST}"
fi

echo "Running HTTPX technology detection and analysis..." >> "${LOG_FILE}"

# Run optimized httpx with all flags in one call
${HTTPX_PATH} -list "${URL_LIST}" \
    -sc -cl -location -title -td -server \
    -mc 200,301,302,403,404,500 \
    -path "/admin,/wp-admin,/wp-login.php,/backup,/old,/test,/dev,/.env,/.git" \
    -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_combined.json" >> "${LOG_FILE}" 2>&1

# Process and extract technologies using Python
python3 << 'PYTHON_SCRIPT'
import json
import os
import sys

output_dir = os.environ.get('OUTPUT_DIR', '')
target = os.environ.get('TARGET', '')

combined_file = f"{output_dir}/vapt_{target}_httpx_combined.json"

if not os.path.exists(combined_file):
    print(f"No httpx results found at {combined_file}", file=sys.stderr)
    sys.exit(0)

technologies = set()
tech_data = []

try:
    with open(combined_file, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                tech_data.append(data)
                
                # Extract technologies
                if 'tech' in data and data['tech']:
                    for tech in data['tech']:
                        technologies.add(tech)
                
                # Also check technologies field (different httpx versions)
                if 'technologies' in data and data['technologies']:
                    for tech in data['technologies']:
                        technologies.add(tech)
                        
            except json.JSONDecodeError:
                continue
except Exception as e:
    print(f"Error processing httpx results: {e}", file=sys.stderr)

# Save extracted technologies
tech_file = f"{output_dir}/vapt_{target}_technologies.txt"
with open(tech_file, 'w') as f:
    for tech in sorted(technologies):
        f.write(f"{tech}\n")

print(f"Technologies detected: {len(technologies)}", file=sys.stderr)

PYTHON_SCRIPT

# Extract technologies for summary
if [ -f "${OUTPUT_DIR}/vapt_${TARGET}_technologies.txt" ]; then
    TECH_COUNT=$(wc -l < "${OUTPUT_DIR}/vapt_${TARGET}_technologies.txt" 2>/dev/null || echo "0")
    echo "  Technologies detected: ${TECH_COUNT}" >> "${LOG_FILE}"
    echo "TECH_DETECTED=${TECH_COUNT}"
else
    echo "  No technologies detected" >> "${LOG_FILE}"
    echo "TECH_DETECTED=0"
fi

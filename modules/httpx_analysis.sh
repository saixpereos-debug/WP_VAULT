#!/bin/bash

# HTTPx analysis module - Technology detection and analysis

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"
# Prepare list of URLs for httpx
URL_LIST="${OUTPUT_DIR}/urls_to_scan.txt"
# OPTIMIZATION: Use live_hosts.txt (roots) instead of ALL URLs for heavy tech detection
# Checking technologies on 10,000 deep URLs is redundant and slow.
LIVE_HOSTS_FILE="${RESULTS_DIR}/httpx/live_hosts.txt"

if [ -s "${LIVE_HOSTS_FILE}" ]; then
    cat "${LIVE_HOSTS_FILE}" > "${URL_LIST}"
    echo "  Using Live Hosts (Roots) for Tech Detection to save time..." >> "${LOG_FILE}"
elif [ -f "${URLS_FILE}" ]; then
    # Fallback to head 100 if no live hosts file (shouldn't happen in pipeline)
    head -n 100 "${URLS_FILE}" > "${URL_LIST}"
    echo "  Using Top 100 URLs for Tech Detection..." >> "${LOG_FILE}"
else
    echo "https://${TARGET}" > "${URL_LIST}"
fi

# Run optimized httpx for Tech Detection (Roots Only)
# Removed -path probing from THIS step to speed up tech detection
echo "  Phase 1: Detecting Technologies..." >> "${LOG_FILE}"
${HTTPX_PATH} -list "${URL_LIST}" \
    -sc -cl -location -title -td -favicon -server \
    -mc 200,301,302,403,404,500 \
    -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_tech.json" >> "${LOG_FILE}" 2>&1

# Phase 2: Probe Interesting Paths (Roots Only)
# This is much faster than running probing on ALL discovered URLs
echo "  Phase 2: Probing Interesting Paths..." >> "${LOG_FILE}"
${HTTPX_PATH} -list "${URL_LIST}" \
    -path "/admin,/wp-admin,/wp-login.php,/backup,/old,/test,/dev,/.env,/.git" \
    -mc 200,301,302,403 \
    -sc -title \
    -json -o "${OUTPUT_DIR}/vapt_${TARGET}_httpx_probes.json" >> "${LOG_FILE}" 2>&1

# Combine results for Python script compatibility
cat "${OUTPUT_DIR}/vapt_${TARGET}_httpx_tech.json" "${OUTPUT_DIR}/vapt_${TARGET}_httpx_probes.json" > "${OUTPUT_DIR}/vapt_${TARGET}_httpx_combined.json"

# Process and extract technologies using Python
# Process and extract technologies and interesting URLs using Python
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
interesting_urls = set()
tech_data = []

# Probe paths that are considered interesting
probe_paths = ["/admin", "/wp-admin", "/wp-login.php", "/backup", "/old", "/test", "/dev", "/.env", "/.git"]

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

                # Extract interesting URLs based on status code and url match
                # If the URL ends with one of the probe paths and is live (200, 301, 302, 403)
                url = data.get('url', '')
                status = data.get('status_code', 0)
                
                if status in [200, 301, 302, 403]:
                    # Check if it was one of our probes
                    for probe in probe_paths:
                        if probe in url:
                            interesting_urls.add(f"{url} [{status}]")
                            break
                        
            except json.JSONDecodeError:
                continue
except Exception as e:
    print(f"Error processing httpx results: {e}", file=sys.stderr)

# Save extracted technologies
tech_file = f"{output_dir}/vapt_{target}_technologies.txt"
with open(tech_file, 'w') as f:
    for tech in sorted(technologies):
        f.write(f"{tech}\n")

# Save interesting URLs
interesting_file = f"{output_dir}/vapt_{target}_httpx_interesting.txt"
with open(interesting_file, 'w') as f:
    for url in sorted(interesting_urls):
        f.write(f"{url}\n")
    if not interesting_urls:
         # Write "No interesting URLs found" or similar if empty? 
         # Or leave empty but valid file
         pass

print(f"Technologies detected: {len(technologies)}", file=sys.stderr)
print(f"Interesting URLs found: {len(interesting_urls)}", file=sys.stderr)

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

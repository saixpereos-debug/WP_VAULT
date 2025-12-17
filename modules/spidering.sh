#!/bin/bash

# Spidering Module using Gospider
# Focus: JS finding, Parameter Mining, Subdomain discovery via crawling

TARGET=$1
OUTPUT_DIR=$2
mkdir -p "$OUTPUT_DIR"

OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_gospider.txt"

# Check if gospider is installed
if ! command -v gospider >/dev/null; then
    echo "Gospider not found. Please run install.sh." >> "${LOG_FILE}"
    exit 1
fi

echo "Running Gospider on https://${TARGET}" >> "${LOG_FILE}"

# -c 10: Concurrent requests
# -d 2: Depth
# --other-source: Check Wayback, AlienVault, etc.
# --include-subs: specific to target subdomains
# --quiet: fewer logs

gospider \
    -s "https://${TARGET}" \
    -o "$OUTPUT_DIR" \
    -c 10 -d 2 \
    --other-source \
    --include-subs \
    --quiet \
    >> "${LOG_FILE}" 2>&1

# Move/Rename output for consistency
# Gospider creates a folder named after the site
# We want to aggregate findings

FINDINGS_DIR="$OUTPUT_DIR/${TARGET}"
if [ -d "$FINDINGS_DIR" ]; then
    # Combine all results
    cat "$FINDINGS_DIR"/* > "${OUTPUT_FILE}" 2>/dev/null
    # Clean up raw directory if desired, or keep it
    # rm -rf "$FINDINGS_DIR"
fi

# Extract JS files for AI Analysis
grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*\.js" "${OUTPUT_FILE}" | sort -u > "${OUTPUT_DIR}/vapt_${TARGET}_js_files.txt"

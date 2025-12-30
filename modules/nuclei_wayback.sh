#!/bin/bash

# Nuclei WayBack Scanning Module for Vṛthā

TARGET=$1
OUTPUT_DIR=$2
TEMPLATES=${3:-$WORDPRESS_TEMPLATES}

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

echo "Starting Advanced Nuclei-Wayback Scan for ${TARGET}..." >> "${LOG_FILE}"

# Build output file path
OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wayback.json"

# Execute Python automation script
# We pass the domain and templates defined in config
python3 utils/nuclei_wayback.py \
    -d "${TARGET}" \
    -t "${TEMPLATES}" \
    -o "${OUTPUT_FILE}" \
    -m 500 \
    -r 150 \
    -c 25 \
    >> "${LOG_FILE}" 2>&1

if [ -s "${OUTPUT_FILE}" ]; then
    echo "  Nuclei-Wayback scan completed. Results saved to ${OUTPUT_FILE}" >> "${LOG_FILE}"
    
    # Categorize results using existing logic from nuclei_scan.sh or similar
    # (Optional: we can expand categorization later)
else
    echo "  Nuclei-Wayback scan yielded no findings or failed." >> "${LOG_FILE}"
fi

exit 0

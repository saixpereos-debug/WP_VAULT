#!/bin/bash

# Historical URL Discovery Module (V3)
# Uses GAU and Waybackurls to find archived endpoints

# Source config if variables not set
if [ -z "$GAU_PATH" ]; then
    source config/config.sh 2>/dev/null || true
fi

TARGET=$1
OUTPUT_DIR=$2
LOG_FILE="${3:-/dev/null}"

mkdir -p "${OUTPUT_DIR}"

echo "Running Historical Discovery for ${TARGET}..." >> "${LOG_FILE}"

# Temporary files
GAU_OUT="${OUTPUT_DIR}/vapt_${TARGET}_gau.txt"
WAYBACK_OUT="${OUTPUT_DIR}/vapt_${TARGET}_wayback.txt"
COMBINED_OUT="${OUTPUT_DIR}/vapt_${TARGET}_historical_all.txt"

# Run GAU
if [ -x "$GAU_PATH" ]; then
    echo "  Running GAU..." >> "${LOG_FILE}"
    $GAU_PATH $GAU_OPTIONS "$TARGET" >> "$GAU_OUT" 2>>"${LOG_FILE}"
fi

# Run Waybackurls
if [ -x "$WAYBACKURLS_PATH" ]; then
    echo "  Running Waybackurls..." >> "${LOG_FILE}"
    echo "$TARGET" | $WAYBACKURLS_PATH >> "$WAYBACK_OUT" 2>>"${LOG_FILE}"
fi

# Combine and unique
cat "$GAU_OUT" "$WAYBACK_OUT" 2>/dev/null | sort -u > "$COMBINED_OUT"

# Filter noise (images, fonts, etc.)
# We want potential endpoints: php, asp, jsp, html, or no extension
# We exclude typical assets
grep -vivE "\.(jpg|jpeg|png|gif|svg|css|js|ico|woff|woff2|ttf|eot)$" "$COMBINED_OUT" > "${OUTPUT_DIR}/vapt_${TARGET}_historical_filtered.txt"

COUNT=$(wc -l < "${OUTPUT_DIR}/vapt_${TARGET}_historical_filtered.txt")
echo "  Found $COUNT unique historical endpoints (filtered)." >> "${LOG_FILE}"

# Cleanup
rm "$GAU_OUT" "$WAYBACK_OUT" 2>/dev/null

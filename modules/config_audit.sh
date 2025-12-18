#!/bin/bash

# Configuration Audit Module
# Checks for directory indexing, version exposure, and hardening issues from 2025 checklist

TARGET=$1
OUTPUT_DIR=$2
LOG_FILE="${3:-/dev/null}"

mkdir -p "${OUTPUT_DIR}"
EXTRA_OUT="${OUTPUT_DIR}/vapt_${TARGET}_config_audit.txt"

echo "Running Configuration Audit for ${TARGET}..." >> "${LOG_FILE}"

# 1. Directory Indexing Checks
echo "  Checking for directory indexing..." >> "${LOG_FILE}"
paths=("/wp-content/uploads/" "/wp-includes/" "/wp-content/plugins/" "/wp-content/themes/")
for path in "${paths[@]}"; do
    if curl -s -k "https://${TARGET}${path}" | grep -qiE "Index of|Parent Directory"; then
        echo "[!] Directory Indexing Enabled: https://${TARGET}${path}" >> "$EXTRA_OUT"
    fi
done

# 2. Version Exposure Checks
echo "  Checking for version exposure..." >> "${LOG_FILE}"
# Meta generator tag
if curl -s -k "https://${TARGET}/" | grep -qi "generator\" content=\"WordPress"; then
    echo "[!] WordPress Version Exposed in Meta Generator Tag" >> "$EXTRA_OUT"
fi

# Query strings in scripts/styles
if curl -s -k "https://${TARGET}/" | grep -q "?ver="; then
    echo "[!] WordPress/Plugin Versions Exposed via Query Strings (?ver=)" >> "$EXTRA_OUT"
fi

# 3. Security Header Audit (via Python utility)
HTTPX_JSON="${RESULTS_DIR}/httpx/vapt_${TARGET}_httpx_analysis.json"
if [ -f "$HTTPX_JSON" ]; then
    echo "  Auditing Security Headers..." >> "${LOG_FILE}"
    python3 utils/header_auditor.py "$HTTPX_JSON" "${OUTPUT_DIR}/vapt_${TARGET}_header_audit.json" >> "${LOG_FILE}" 2>&1
fi

# 4. Misc Hardening
# Check for readme.html exposure (often contains version)
if curl -s -k -I "https://${TARGET}/readme.html" | grep -q "HTTP/.* 200"; then
    echo "[!] Exposed readme.html: https://${TARGET}/readme.html" >> "$EXTRA_OUT"
fi

echo "Configuration Audit completed." >> "${LOG_FILE}"

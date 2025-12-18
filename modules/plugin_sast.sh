#!/bin/bash

# Plugin SAST Module
# Identifies plugins and performs static analysis on public source code if available

TARGET=$1
OUTPUT_DIR=$2
LOG_FILE="${3:-/dev/null}"

mkdir -p "${OUTPUT_DIR}/source"

echo "Running Plugin Static Analysis for ${TARGET}..." >> "${LOG_FILE}"

# 1. Identify plugins from previous results (WPScan or HTTPX)
WPSCAN_RESULTS="${RESULTS_DIR}/wordpress/vapt_${TARGET}_wpscan_all.txt"
PLUGINS=""

if [ -f "$WPSCAN_RESULTS" ]; then
    PLUGINS=$(grep -Po "\[\+\] \K[a-z0-9-]+" "$WPSCAN_RESULTS" | sort -u)
fi

if [ -z "$PLUGINS" ]; then
    echo "  No plugins identified for static analysis." >> "${LOG_FILE}"
    exit 0
fi

for plugin in $PLUGINS; do
    echo "  Analyzing plugin: ${plugin}" >> "${LOG_FILE}"
    
    # 2. Attempt to fetch public source from WordPress.org (if not already local)
    # This is a basic implementation; in production, we'd check versions too.
    if [ ! -d "${OUTPUT_DIR}/source/${plugin}" ]; then
        echo "    Fetching source for ${plugin} from wordpress.org..." >> "${LOG_FILE}"
        wget -q "https://downloads.wordpress.org/plugin/${plugin}.zip" -O "${OUTPUT_DIR}/source/${plugin}.zip"
        if [ -f "${OUTPUT_DIR}/source/${plugin}.zip" ]; then
            unzip -q "${OUTPUT_DIR}/source/${plugin}.zip" -d "${OUTPUT_DIR}/source/" >> "${LOG_FILE}" 2>&1
            rm "${OUTPUT_DIR}/source/${plugin}.zip"
        else
            echo "    Failed to fetch source for ${plugin}. Might be a private or repository-only plugin." >> "${LOG_FILE}"
            continue
        fi
    fi
    
    # 3. Run the custom SAST analyzer
    if [ -d "${OUTPUT_DIR}/source/${plugin}" ]; then
        echo "    Running Vṛthā SAST on ${plugin}..." >> "${LOG_FILE}"
        python3 utils/plugin_analyzer.py "${OUTPUT_DIR}/source/${plugin}" --output "${OUTPUT_DIR}/sast_${plugin}.json" >> "${LOG_FILE}" 2>&1
    fi
done

echo "Plugin SAST completed." >> "${LOG_FILE}"

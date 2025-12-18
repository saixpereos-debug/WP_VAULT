#!/bin/bash

# Advanced Reconnaissance using Uncover
# Uses search engines (Shodan, Censys, Fofa) to find exposed assets

TARGET=$1
OUTPUT_DIR=$2
mkdir -p "$OUTPUT_DIR"

OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_uncover.txt"

# Check if uncover is installed
if [ -z "$UNCOVER_PATH" ] || [ ! -x "$UNCOVER_PATH" ]; then
    echo "Uncover tool not configured. Skipping." >> "${LOG_FILE}"
    exit 0
fi

# Export API keys for Uncover
if [ -n "$SHODAN_API_KEY" ]; then
    export SHODAN_API_KEY="$SHODAN_API_KEY"
fi

# Check for Uncover configuration (API keys)
# Uncover uses ~/.config/uncover/provider-config.yaml
UNCOVER_CONFIG="$HOME/.config/uncover/provider-config.yaml"

if [ ! -f "$UNCOVER_CONFIG" ]; then
    echo -e "${YELLOW}[!] Uncover provider config not found at $UNCOVER_CONFIG${NC}"
    echo -e "${YELLOW}    Deep cloud reconnaissance (Shodan/Censys) will likely fail or return limited results.${NC}"
    echo -e "${YELLOW}    To fix: Create the config file or export API keys (SHODAN_API_KEY, etc.)${NC}"
    echo "Uncover config missing. Proceeding with limited/public search..." >> "${LOG_FILE}"
    # We do not exit, we just warn and proceed as requested ("option to ignore")
else
    echo "Uncover config found. Proceeding with authenticated search..." >> "${LOG_FILE}"
fi

echo "Running Uncover Recon..." >> "${LOG_FILE}"

# Uncover Queries
# finding subdomains or related assets via certificate transparency and other dorks
${UNCOVER_PATH} -q "ssl:\"${TARGET}\"" -e shodan,censys,fofa ${UNCOVER_OPTIONS} -silent >> "${OUTPUT_FILE}" 2>/dev/null
${UNCOVER_PATH} -q "domain:\"${TARGET}\"" -e shodan,censys,fofa ${UNCOVER_OPTIONS} -silent >> "${OUTPUT_FILE}" 2>/dev/null

# Clean up
if [ -s "${OUTPUT_FILE}" ]; then
    sort -u -o "${OUTPUT_FILE}" "${OUTPUT_FILE}"
    echo "Uncover found $(wc -l < "${OUTPUT_FILE}") potential assets." >> "${LOG_FILE}"
else
    echo "Uncover found no assets." >> "${LOG_FILE}"
fi

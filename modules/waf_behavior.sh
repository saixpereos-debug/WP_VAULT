#!/bin/bash

# WAF Behavior and Identification Module for Vṛthā

TARGET=$1
OUTPUT_DIR=$2

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

echo "Starting WAF Behavior Detection for ${TARGET}..." >> "${LOG_FILE}"

# 1. Standard WAF Identification (wafw00f)
if command -v wafw00f >/dev/null 2>&1; then
    echo "[+] Running wafw00f..." >> "${LOG_FILE}"
    wafw00f "https://${TARGET}" -a -o "${OUTPUT_DIR}/wafw00f_results.json" >> "${LOG_FILE}" 2>&1
fi

# 2. Custom WAF Probing (Behavioral)
echo "[+] Probing WAF behavior with custom payloads..." >> "${LOG_FILE}"
payloads=(
    "' OR 1=1--" 
    "<script>alert(1)</script>" 
    "../../../../etc/passwd"
    "() { :; }; echo VULNERABLE"
)

for payload in "${payloads[@]}"; do
    echo "  Testing payload: $payload" >> "${LOG_FILE}"
    status_code=$(curl -s -o /dev/null -w "%{http_code}" -k "https://${TARGET}/?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")")
    echo "  Status Code for '$payload': $status_code" >> "${OUTPUT_DIR}/waf_behavior_probes.log"
    
    if [ "$status_code" == "403" ] || [ "$status_code" == "406" ] || [ "$status_code" == "501" ]; then
        echo "  [!] Payload '$payload' was likely BLOCKED (Status: $status_code)" >> "${LOG_FILE}"
    elif [ "$status_code" == "200" ]; then
        echo "  [?] Payload '$payload' was ACCEPTED (Status: $status_code)" >> "${LOG_FILE}"
    fi
done

echo "WAF Behavior analysis completed." >> "${LOG_FILE}"
exit 0

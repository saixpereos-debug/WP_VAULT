#!/bin/bash

# Enhanced Nuclei scanning module with custom WordPress templates

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

echo "Running enhanced Nuclei scan for ${TARGET}..." | tee -a "${LOG_FILE}"

# Prepare list of URLs for Nuclei
URL_LIST="${OUTPUT_DIR}/urls_to_scan.txt"
cat "${URLS_FILE}" > "${URL_LIST}"

# Update Nuclei templates
echo "Updating Nuclei templates..." | tee -a "${LOG_FILE}"
${NUCLEI_PATH} -update-templates 2>&1

# Run Nuclei with custom WordPress templates
echo "Running Nuclei with custom WordPress templates..." | tee -a "${LOG_FILE}"
${NUCLEI_PATH} -l "${URL_LIST}" -t templates/nuclei/ ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_custom.txt" -json 2>&1

# Run Nuclei with WordPress-specific templates from the official repository
echo "Running Nuclei with official WordPress templates..." | tee -a "${LOG_FILE}"
${NUCLEI_PATH} -l "${URL_LIST}" -t ${WORDPRESS_TEMPLATES} ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_official.txt" -json 2>&1

# Run Nuclei with all templates (excluding WordPress)
echo "Running Nuclei with all templates (excluding WordPress)..." | tee -a "${LOG_FILE}"
${NUCLEI_PATH} -l "${URL_LIST}" -exclude-tags wordpress ${NUCLEI_OPTIONS} -o "${OUTPUT_DIR}/vapt_${TARGET}_nuclei_general.txt" -json 2>&1

# Parse and categorize Nuclei results
echo "Parsing and categorizing Nuclei results..." | tee -a "${LOG_FILE}"
python3 -c "
import json
from collections import defaultdict

# Read all JSON files
results = defaultdict(list)

# Process custom WordPress templates
try:
    with open('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_custom.txt', 'r') as f:
        for line in f:
            if line.strip():
                results['wordpress_custom'].append(json.loads(line))
except:
    pass

# Process official WordPress templates
try:
    with open('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_wordpress_official.txt', 'r') as f:
        for line in f:
            if line.strip():
                results['wordpress_official'].append(json.loads(line))
except:
    pass

# Process general templates
try:
    with open('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_general.txt', 'r') as f:
        for line in f:
            if line.strip():
                results['general'].append(json.loads(line))
except:
    pass

# Categorize by severity
severity_results = defaultdict(list)
for category, items in results.items():
    for item in items:
        severity = item.get('info', {}).get('severity', 'unknown')
        severity_results[severity].append(item)

# Save categorized results
with open('${OUTPUT_DIR}/vapt_${TARGET}_nuclei_categorized.json', 'w') as f:
    json.dump({
        'by_category': dict(results),
        'by_severity': dict(severity_results)
    }, f, indent=2)

# Print summary
print(f'Nuclei scan completed with {sum(len(items) for items in results.values())} total findings')
for severity, items in severity_results.items():
    print(f'  {severity}: {len(items)} findings')
"

echo "Enhanced Nuclei scanning completed"

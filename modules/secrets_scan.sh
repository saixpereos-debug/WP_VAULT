#!/bin/bash

# Secrets & Identity Extraction Module (V4)
# Replaced TruffleHog with specialized extraction for Emails, Phones, and Identities
# Aggregates data from scraped content and WPScan results

TARGET=$1
OUTPUT_DIR=$2
URL_FILE=$3 # Optional input file with URLs
LOG_FILE="${4:-/dev/null}"

mkdir -p "${OUTPUT_DIR}"
TEMP_CONTENT="${OUTPUT_DIR}/temp_content"
mkdir -p "$TEMP_CONTENT"

echo "Running Secrets & Identity Extraction for ${TARGET}..." >> "${LOG_FILE}"

# Step 1: Download content to scan (Limited to JS and Configs if possible)
echo "  Downloading content for analysis..." >> "${LOG_FILE}"
if [ -f "$URL_FILE" ]; then
    # Filter for JS/PHP/Config files or just fetch to 100 interesting ones
    grep -E "\.js$|\.json$|\.xml$|\.env$" "$URL_FILE" | head -n 50 > "${TEMP_CONTENT}/urls_to_fetch.txt"
    # Also fetch main page
    echo "https://${TARGET}/" >> "${TEMP_CONTENT}/urls_to_fetch.txt"
    
    # Download with wget using common User-Agent
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    wget --user-agent="$ua" -i "${TEMP_CONTENT}/urls_to_fetch.txt" -P "$TEMP_CONTENT" -q --timeout=10 --tries=2
else
    # Just fetch the main page if no list provided
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
     wget --user-agent="$ua" "https://${TARGET}/" -P "$TEMP_CONTENT" -q
fi

# Step 2: Run Enhanced Regex Scraper (Emails, Phones, Keys, Identities)
echo "  Running Regex Scraper on discovered URLs..." >> "${LOG_FILE}"
if [ -f "$URL_FILE" ]; then
    # Filter URLs to only scan relevant file types
    echo "  Filtering URLs for scannable content..." >> "${LOG_FILE}"
    grep -E "\.(js|json|xml|env|config|yml|yaml)(\?|$)" "${URL_FILE}" 2>/dev/null | \
        grep -vE "\.(css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico)(\?|$)" | \
        head -n 500 > "${OUTPUT_DIR}/scannable_urls.txt"

    SCANNABLE_COUNT=$(wc -l < "${OUTPUT_DIR}/scannable_urls.txt" 2>/dev/null || echo "0")
    echo "  Scannable URLs: ${SCANNABLE_COUNT}" >> "${LOG_FILE}"

    if [ "${SCANNABLE_COUNT}" -eq 0 ]; then
        echo "  No scannable URLs found. Scanning main page only." >> "${LOG_FILE}"
        echo "https://${TARGET}/" > "${OUTPUT_DIR}/scannable_urls.txt"
    fi

    echo "  Starting regex extraction..." >> "${LOG_FILE}"
    # Run enhanced regex scraper with HTML/JSON/XML parsing
    python3 utils/regex_scraper.py "${OUTPUT_DIR}/scannable_urls.txt" \
        --threads 20 \
        --parse-html \
        --parse-json \
        --parse-xml \
        > "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt" 2>> "${LOG_FILE}" || true

    rm -f "${OUTPUT_DIR}/scannable_urls.txt"
else
    # Fallback to just main page
    echo "https://${TARGET}/" > "${OUTPUT_DIR}/single_url.txt"
    python3 utils/regex_scraper.py "${OUTPUT_DIR}/single_url.txt" \
        --parse-html \
        --parse-json \
        --parse-xml \
        > "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt" 2>>"${LOG_FILE}" || true
fi

# Step 3: Extract & Consolidate Identities from WPScan (if available)
WPSCAN_RESULTS="${RESULTS_DIR}/wordpress/vapt_${TARGET}_wpscan_all.txt"
IDENTITY_REPORT="${OUTPUT_DIR}/vapt_${TARGET}_identity_report.txt"
touch "$IDENTITY_REPORT"

echo "=== Extracted Identities & Contacts ===" > "$IDENTITY_REPORT"

# Extract Emails
echo -e "\n[EMAILS]" >> "$IDENTITY_REPORT"
grep "\[EMAIL\]" "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt" | awk '{print $2}' | sort -u >> "$IDENTITY_REPORT"

# Extract Phone Numbers
echo -e "\n[PHONE NUMBERS]" >> "$IDENTITY_REPORT"
grep "Phone Number" "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt" | awk -F': ' '{print $2}' | awk -F' |' '{print $1}' | sort -u >> "$IDENTITY_REPORT"

# Extract WordPress Users (from Scraper & WPScan)
echo -e "\n[WORDPRESS USERS / AUTHORS]" >> "$IDENTITY_REPORT"
# From Scraper
grep -E "WordPress Author|Person Name|Username Pattern" "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt" | awk -F': ' '{print $2}' | awk -F' |' '{print $1}' | sort -u >> "$IDENTITY_REPORT"

# From WPScan Results
if [ -f "$WPSCAN_RESULTS" ]; then
    echo "  Parsing WPScan for users..." >> "${LOG_FILE}"
    # WPScan standard user output format parsing
    grep -E "\[\+\] [a-zA-Z0-9_-]+" "$WPSCAN_RESULTS" | grep -i "User" >> "$IDENTITY_REPORT"
    # Try finding "Found X users:" sections
    sed -n '/\[i\] User(s) Identified:/,/\([+]\|[!]\|[i]\)/p' "$WPSCAN_RESULTS" | grep "\[+\]" | awk '{print $2}' >> "$IDENTITY_REPORT"
fi

# Cleanup
# Remove duplicates in place
sort -u "$IDENTITY_REPORT" -o "$IDENTITY_REPORT"

SECRETS_COUNT=$(grep -c "\[SECRET\]" "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt")
EMAILS_COUNT=$(grep -c "@" "$IDENTITY_REPORT")
echo "  Found $SECRETS_COUNT potential secrets and $EMAILS_COUNT identities." >> "${LOG_FILE}"

# Cleanup content to save space, but keep report
rm -rf "$TEMP_CONTENT"
exit 0

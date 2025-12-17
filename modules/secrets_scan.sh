#!/bin/bash

# Secrets Scanning Module (V3)
# Uses Trufflehog to find secrets in discovered content

TARGET=$1
OUTPUT_DIR=$2
URL_FILE=$3 # Optional input file with URLs
LOG_FILE="${4:-/dev/null}"

mkdir -p "${OUTPUT_DIR}"
TEMP_CONTENT="${OUTPUT_DIR}/temp_content"
mkdir -p "$TEMP_CONTENT"

echo "Running Secrets Scan for ${TARGET}..." >> "${LOG_FILE}"

if [ ! -x "$TRUFFLEHOG_PATH" ]; then
    echo "  TruffleHog not found at $TRUFFLEHOG_PATH. Skipping." >> "${LOG_FILE}"
    exit 1
fi

# Step 1: Download content to scan (Limited to JS and Configs if possible)
echo "  Downloading content for analysis..." >> "${LOG_FILE}"
if [ -f "$URL_FILE" ]; then
    # Filter for JS/PHP/Config files or just fetch top 100 interesting ones
    # For efficiency we might just grab JS files
    grep -E "\.js$|\.json$|\.xml$|\.env$" "$URL_FILE" | head -n 50 > "${TEMP_CONTENT}/urls_to_fetch.txt"
    
    # Also fetch main page
    echo "https://${TARGET}/" >> "${TEMP_CONTENT}/urls_to_fetch.txt"
    
    # Download with wget
    wget -i "${TEMP_CONTENT}/urls_to_fetch.txt" -P "$TEMP_CONTENT" -q --timeout=5 --tries=1
else
    # Just fetch the main page if no list provided
     wget "https://${TARGET}/" -P "$TEMP_CONTENT" -q
fi

# Step 2: Run TruffleHog
echo "  Executing TruffleHog filesystem scan..." >> "${LOG_FILE}"
$TRUFFLEHOG_PATH filesystem "$TEMP_CONTENT" --json > "${OUTPUT_DIR}/vapt_${TARGET}_trufflehog.json" 2>>"${LOG_FILE}"

# Step 3: Run Deep Regex Scraper (Emails & Keys in Response Body)
echo "  Running Deep Regex Scraper on discovered URLs..." >> "${LOG_FILE}"
if [ -f "$URL_FILE" ]; then
    python3 utils/regex_scraper.py "$URL_FILE" --threads 20 > "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt" 2>>"${LOG_FILE}"
else
    # Fallback to just main page if no URL file
    echo "https://${TARGET}/" > "${OUTPUT_DIR}/single_url.txt"
    python3 utils/regex_scraper.py "${OUTPUT_DIR}/single_url.txt" > "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt" 2>>"${LOG_FILE}"
fi

# Step 4: Parse Report (Basic)
SECRETS_COUNT=$(grep -c "Detector" "${OUTPUT_DIR}/vapt_${TARGET}_trufflehog.json")
SCRAPED_COUNT=$(wc -l < "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt")
echo "  Found $SECRETS_COUNT potential secrets (TruffleHog) and $SCRAPED_COUNT (Regex Scraper)." >> "${LOG_FILE}"

# Cleanup content to save space, but keep report
rm -rf "$TEMP_CONTENT"

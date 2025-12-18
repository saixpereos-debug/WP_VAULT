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

# Step 3: Run Enhanced Deep Regex Scraper (Emails & Keys in Response Body)
echo "  Running Enhanced Regex Scraper on discovered URLs..." >> "${LOG_FILE}"
if [ -f "$URL_FILE" ]; then
    echo "Scanning for secrets using enhanced regex patterns..." >> "${LOG_FILE}"

    # Filter URLs to only scan relevant file types
    echo "  Filtering URLs for scannable content..." >> "${LOG_FILE}"
    grep -E "\.(js|json|xml|env|config|yml|yaml)(\?|$)" "${URL_FILE}" 2>/dev/null | \
        grep -vE "\.(css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico)(\?|$)" | \
        head -n 500 > "${OUTPUT_DIR}/scannable_urls.txt"

    SCANNABLE_COUNT=$(wc -l < "${OUTPUT_DIR}/scannable_urls.txt" 2>/dev/null || echo "0")
    echo "  Scannable URLs: ${SCANNABLE_COUNT}" >> "${LOG_FILE}"

    if [ "${SCANNABLE_COUNT}" -eq 0 ]; then
        echo "  No scannable URLs found. Skipping regex scraper." >> "${LOG_FILE}"
        touch "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt"
    else
        # Run enhanced regex scraper with HTML/JSON/XML parsing
        python3 utils/regex_scraper.py "${OUTPUT_DIR}/scannable_urls.txt" \
            --threads 20 \
            --parse-html \
            --parse-json \
            --parse-xml \
            > "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt" 2>> "${LOG_FILE}" || true
    fi

    rm -f "${OUTPUT_DIR}/scannable_urls.txt"
else
    # Fallback to just main page if no URL file
    echo "https://${TARGET}/" > "${OUTPUT_DIR}/single_url.txt"
    python3 utils/regex_scraper.py "${OUTPUT_DIR}/single_url.txt" \
        --parse-html \
        --parse-json \
        --parse-xml \
        > "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt" 2>>"${LOG_FILE}" || true
fi

# Step 4: Parse Report (Basic)
SECRETS_COUNT=$(grep -c "Detector" "${OUTPUT_DIR}/vapt_${TARGET}_trufflehog.json")
SCRAPED_COUNT=$(wc -l < "${OUTPUT_DIR}/vapt_${TARGET}_scraped_secrets.txt")
echo "  Found $SECRETS_COUNT potential secrets (TruffleHog) and $SCRAPED_COUNT (Regex Scraper)." >> "${LOG_FILE}"

# Cleanup content to save space, but keep report
rm -rf "$TEMP_CONTENT"

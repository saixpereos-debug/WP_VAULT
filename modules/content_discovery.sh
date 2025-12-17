#!/bin/bash

# Content Discovery Module using Feroxbuster
# Features: Smart wordlist selection, Auto-tuning, Recursion

TARGET=$1
OUTPUT_DIR=$2
WORDLIST_DIR="tools/wordlists"
mkdir -p "$WORDLIST_DIR"
mkdir -p "$OUTPUT_DIR"

# Default Wordlist (Assetnote Best of lists are great, utilizing a smaller "automated" one for speed by default)
# If user wants full assetnote, they can replace this.
DEFAULT_WORDLIST="$WORDLIST_DIR/raft-medium-directories.txt"
DEFAULT_WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"

# Ensure wordlist exists
if [ ! -f "$DEFAULT_WORDLIST" ]; then
    echo "Downloading default wordlist..." >> "${LOG_FILE}"
    wget -q "$DEFAULT_WORDLIST_URL" -O "$DEFAULT_WORDLIST"
fi

# Determine Extensions based on Tech Detection
# We read the tech json from httpx if available
EXTENSIONS="txt,html,php"
TECH_FILE="${RESULTS_DIR}/httpx/vapt_${TARGET}_httpx_tech.json"
WHATWEB_FILE="${RESULTS_DIR}/httpx/vapt_${TARGET}_whatweb.json"

# Function to check tech in files
check_tech() {
    local keyword=$1
    if [ -f "$TECH_FILE" ] && grep -iq "$keyword" "$TECH_FILE"; then return 0; fi
    if [ -f "$WHATWEB_FILE" ] && grep -iq "$keyword" "$WHATWEB_FILE"; then return 0; fi
    return 1
}

# Check Techs
if check_tech "ASP.NET"; then
    EXTENSIONS="aspx,ashx,asp,svc,$EXTENSIONS"
fi
if check_tech "Java" || check_tech "JSP"; then
    EXTENSIONS="jsp,jspx,do,action,$EXTENSIONS"
fi
if check_tech "Python" || check_tech "Django" || check_tech "Flask"; then
    EXTENSIONS="py,inc,$EXTENSIONS"
fi

# Run Feroxbuster
# --auto-tune: Automatically filters out false positives by size/word count
# --depth 2: Limited recursion to avoid infinite loops
# --scan-limit 2: Parallel scans limit
# --time-limit 10m: Safety cap per directory
# --silent: We handle logging
# --json: For easier parsing later (optional, but feroxbuster creates its own files)

OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_feroxbuster.txt"

# Check if feroxbuster is installed
if ! command -v feroxbuster >/dev/null; then
    echo "Feroxbuster not found. Please run install.sh." >> "${LOG_FILE}"
    exit 1
fi

echo "Running Feroxbuster with extensions: $EXTENSIONS" >> "${LOG_FILE}"

feroxbuster \
    --url "https://${TARGET}" \
    --wordlist "$DEFAULT_WORDLIST" \
    --extensions "$EXTENSIONS" \
    --depth 2 \
    --auto-tune \
    --scan-limit 2 \
    --time-limit 10m \
    --silent \
    --no-state \
    --output "${OUTPUT_FILE}" \
    >> "${LOG_FILE}" 2>&1

# Sort and clean output
if [ -f "${OUTPUT_FILE}" ]; then
    sort -u -o "${OUTPUT_FILE}" "${OUTPUT_FILE}"
fi

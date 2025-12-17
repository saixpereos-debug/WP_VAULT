#!/bin/bash

# WordPress scanning module

TARGET=$1
OUTPUT_DIR=$2
SUBDOMAINS_FILE="${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

scan_wordpress() {
    local domain=$1
    local output_file="${OUTPUT_DIR}/vapt_${TARGET}_wpscan_${domain}.txt"
    
    # Build command
    local cmd="${WPSCAN_PATH} --url \"https://${domain}\" ${WPSCAN_OPTIONS} --output \"${output_file}\" --format cli"
    
    # Add API token if present
    if [ -n "$WPSCAN_API_TOKEN" ]; then
        cmd="$cmd --api-token $WPSCAN_API_TOKEN"
    fi
    
    # Run wpscan
    # Redirect stdout to the specific output file (handled by --output flag)
    # Redirect stderr to a debug log
    echo "Running WPScan for $domain..." >> "${LOG_FILE}"
    eval "$cmd" >> "${OUTPUT_DIR}/wpscan_debug.log" 2>&1

    # --- Extra Blog-Inspired Checks ---
    echo "Running Extra Checks for $domain..." >> "${LOG_FILE}"
    local EXTRA_OUT="${OUTPUT_DIR}/vapt_${TARGET}_extra_checks.txt"
    
    # 1. User Enumeration (Author Archives)
    # Check ?author=1,2,3
    for i in {1..5}; do
        auth_url="https://${domain}/?author=$i"
        if curl -s -I -L "$auth_url" | grep -q "wp-includes"; then
             # If it redirects to /author/username/ it's vulnerable or exposes user
             final_url=$(curl -Ls -o /dev/null -w %{url_effective} "$auth_url")
             echo "[!] Possible User Enumeration: $auth_url -> $final_url" >> "$EXTRA_OUT"
        fi
    done

    # 2. Open Redirect (wp-login.php)
    # Ref: https://bitninja.com/blog/understanding-the-open-redirection-vulnerability-in-wordpresss-wp-login-plugin/
    redirect_url="https://${domain}/wp-login.php?redirect_to=http://google.com"
    if curl -s -I "$redirect_url" | grep -q "Location: http://google.com"; then
         echo "[CRITICAL] Open Redirect found at $redirect_url" >> "$EXTRA_OUT"
    fi

    # 3. Sensitive Files (JetTricks, debug.log, backup configs)
    # Ref: https://patchstack.com/database/wordpress/plugin/jet-tricks/vulnerability/wordpress-jettricks-1-5-4-1-sensitive-data-exposure-vulnerability
    # Ref: https://markazgasimov.medium.com/5-minutes-3-sites-1-wordpress-vulnerability-my-bug-bounty-win-9d4d90042833
    files=("debug.log" "wp-config.php.bak" "wp-config.php.old" "wp-config.php.save" ".env" "xmlrpc.php")
    for file in "${files[@]}"; do
        status=$(curl -o /dev/null -s -w "%{http_code}" "https://${domain}/$file")
        if [ "$status" == "200" ]; then
             echo "[!] Exposed Sensitive File: https://${domain}/$file (HTTP 200)" >> "$EXTRA_OUT"
        fi
    done
}

# Scan main domain
scan_wordpress "${TARGET}"

# Scan subdomains
if [ -f "${SUBDOMAINS_FILE}" ]; then
    while IFS= read -r subdomain; do
        # Quick check if it's WP
        if curl -s -I "https://${subdomain}" | grep -i "wp-content" >/dev/null 2>&1; then
            scan_wordpress "${subdomain}"
        fi
    done < "${SUBDOMAINS_FILE}"
fi

cat "${OUTPUT_DIR}"/*.txt > "${OUTPUT_DIR}/vapt_${TARGET}_wpscan_all.txt" 2>/dev/null

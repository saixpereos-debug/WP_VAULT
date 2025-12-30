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
    
    echo "Scanning WordPress site: $domain..." >> "${LOG_FILE}"
    
    # Use a standard GET request with a common UA to check accessibility, as some WAFs block HEAD.
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    if ! curl -s -L --max-time 15 -k -H "User-Agent: $ua" "https://${domain}" > /dev/null 2>&1; then
        # Try HTTP if HTTPS fails
        if ! curl -s -L --max-time 15 -H "User-Agent: $ua" "http://${domain}" > /dev/null 2>&1; then
            echo "  Target $domain is not reachable (Checked with GET). Skipping." >> "${LOG_FILE}"
            return 1
        fi
        # Use HTTP if HTTPS failed
        local protocol="http"
    else
        local protocol="https"
    fi
    
    # Build aggressive 2025-standard command
    local cmd="${WPSCAN_PATH} --url \"${protocol}://${domain}\" --enumerate u,ap,at,tt --plugins-detection aggressive --max-threads 20 --stealthy --force --detection-mode mixed --disable-tls-checks --ignore-main-redirect --output \"${output_file}\" --format cli"
    
    # Add API token if present
    if [ -n "$WPSCAN_API_TOKEN" ]; then
        cmd="$cmd --api-token $WPSCAN_API_TOKEN"
    fi
    
    # Run wpscan with error handling
    echo "  Running Aggressive WPScan on ${protocol}://${domain}..." >> "${LOG_FILE}"
    
    # Execute with a timeout and capture errors
    timeout 600 bash -c "$cmd" >> "${OUTPUT_DIR}/wpscan_debug.log" 2>&1
    
    local exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "  WPScan timed out for $domain" >> "${LOG_FILE}"
        echo "[!] WPScan Timeout for $domain after 10 minutes." > "${output_file}"
    elif [ $exit_code -ne 0 ]; then
        echo "  WPScan failed for $domain (exit code: $exit_code). Check wpscan_debug.log" >> "${LOG_FILE}"
        echo "[!] WPScan Failed for $domain (Exit Code: $exit_code)" > "${output_file}"
        tail -n 20 "${OUTPUT_DIR}/wpscan_debug.log" >> "${output_file}"
    else
        echo "  WPScan completed for $domain" >> "${LOG_FILE}"
        if [ ! -s "${output_file}" ]; then
            echo "[!] WPScan completed but output file is empty. Check debug.log" >> "${LOG_FILE}"
            echo "[!] WPScan returned no results for $domain" > "${output_file}"
            cat "${OUTPUT_DIR}/wpscan_debug.log" >> "${output_file}"
        fi
    fi

    # --- 2025 Checklist: Advanced Discovery Phase (Rules 1-3) ---
    echo "Running 2025 Checklist Advanced Rule Automation for $domain..." >> "${LOG_FILE}"
    local EXTRA_OUT="${OUTPUT_DIR}/vapt_${TARGET}_extra_checks.txt"
    
    # Rule 2: User Enumeration (WP-ENUM-001)
    echo "  [Rule 2] Checking User Enumeration (REST API & Author ID)..." >> "${LOG_FILE}"
    
    # Check 1: REST API
    rest_users=$(curl -s -k -H "User-Agent: $ua" "${protocol}://${domain}/wp-json/wp/v2/users")
    if echo "$rest_users" | jq -e '. | type == "array" and length > 0' >/dev/null 2>&1; then
        user_list=$(echo "$rest_users" | jq -r '.[].slug' | tr '\n' ',' | sed 's/,$//')
        echo "[!] WP-ENUM-001: REST API User Exposure: ${user_list}" >> "$EXTRA_OUT"
    fi

    # Check 2: Author ID Brute Force (Simple check for ID 1-5)
    for id in {1..5}; do
        author_url="${protocol}://${domain}/?author=${id}"
        # Follow redirects to see where it leads
        author_resp=$(curl -s -I -L -k -H "User-Agent: $ua" "$author_url")
        if echo "$author_resp" | grep -qi "Location: .*/author/"; then
            author_name=$(echo "$author_resp" | grep -i "Location:" | grep -oE "/author/[^/]+" | cut -d'/' -f3)
            if [ -n "$author_name" ]; then
                echo "[!] WP-ENUM-001: Author ID Enumeration: Found user '$author_name' at $author_url" >> "$EXTRA_OUT"
            fi
        fi
    done

    # Rule 1: Sensitive Configuration File Exposure (WP-MISCONFIG-001)
    echo "  [Rule 1] Scanning for exposed backups and config variants..." >> "${LOG_FILE}"
    # Expanded list based on user rules
    config_paths=(
        "wp-config.php" "wp-config.php.bak" "wp-config.txt" "wp-config.zip" 
        "wp-config.php_orig" "wp-config.save" "wp-config.md" "wp-config.php.old"
        "wp-config.php.save" "wp-config.php.swp" ".env" "php.ini" "database.sql"
    )

    for path in "${config_paths[@]}"; do
        # Ignore main wp-config.php unless it returns 200 AND text content (it should normally be executed by PHP)
        status=$(curl -o /dev/null -s -w "%{http_code}" -k -H "User-Agent: $ua" "${protocol}://${domain}/$path")
        if [ "$status" == "200" ]; then
             content=$(curl -s -k -H "User-Agent: $ua" --max-time 5 "${protocol}://${domain}/$path")
             # Verify it's a real config leak by searching for DB constants
             if echo "$content" | grep -qiE "DB_PASSWORD|DB_NAME|DB_USER|AUTH_KEY|SECURE_AUTH_KEY" >/dev/null 2>&1; then
                echo "[CRITICAL] WP-MISCONFIG-001: Sensitive Configuration File Exposed: ${protocol}://${domain}/$path" >> "$EXTRA_OUT"
             elif [ "$path" != "wp-config.php" ]; then
                # Potential copy, even if not leaking full DB constants (could be a partial save)
                echo "[!] Potential Sensitive File Found: ${protocol}://${domain}/$path (HTTP 200)" >> "$EXTRA_OUT"
             fi
        fi
    done

    # Rule 3: XML-RPC API Abuse (WP-API-001)
    echo "  [Rule 3] Auditing XML-RPC API for brute-force and SSRF..." >> "${LOG_FILE}"
    xmlrpc_url="${protocol}://${domain}/xmlrpc.php"
    
    # Step 1: Confirm Presence
    xmlrpc_resp=$(curl -s -k -H "User-Agent: $ua" "$xmlrpc_url")
    if echo "$xmlrpc_resp" | grep -q "XML-RPC server accepts POST requests only."; then
        echo "[!] WP-API-001: XML-RPC is ACTIVE at ${xmlrpc_url}" >> "$EXTRA_OUT"
        
        # Step 2: List Methods to detect Brute-Force and SSRF
        method_list=$(curl -s -k -H "User-Agent: $ua" -X POST -d '<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' "$xmlrpc_url")
        
        # Detect Brute-Force
        if echo "$method_list" | grep -qiE "wp.getUsersBlogs|metaWeblog.getUsersBlogs|wp.getUserBlogs"; then
            echo "[!] WP-API-001: XML-RPC vulnerable to Brute-Force (wp.getUsersBlogs found)" >> "$EXTRA_OUT"
        fi
        
        # Detect SSRF (Pingback)
        if echo "$method_list" | grep -qi "pingback.ping"; then
            echo "[!] WP-API-001: XML-RPC vulnerable to SSRF (pingback.ping found)" >> "$EXTRA_OUT"
        fi
    fi

    # Author Sitemap User Enum (Bonus check)
    if curl -s -I -k -H "User-Agent: $ua" "${protocol}://${domain}/author-sitemap.xml" | grep -q "HTTP/.* 200"; then
        echo "[!] User Exposure: Author Sitemap Exposed: ${protocol}://${domain}/author-sitemap.xml" >> "$EXTRA_OUT"
    fi

    # 4. Supply Chain Risk: Abandoned Plugins
    echo "  Checking for abandoned/unmaintained plugins..." >> "${LOG_FILE}"
    # Extract plugins from wpscan file
    if [ -f "$output_file" ]; then
        plugins=$(grep -Po "\[\+\] \K[a-z0-9-]+" "$output_file" | sort -u | tr '\n' ' ')
        if [ -n "$plugins" ]; then
            python3 utils/wp_repo_check.py $plugins > "${OUTPUT_DIR}/vapt_${TARGET}_abandoned_plugins.json" 2>/dev/null
        fi
    fi
}

# Scan main domain
scan_wordpress "${TARGET}" || true

# Scan subdomains
if [ -f "${SUBDOMAINS_FILE}" ]; then
    while IFS= read -r subdomain; do
        [ -z "$subdomain" ] && continue
        # Quick check for WordPress fingerprints before full scan
        if curl -s -L -k --max-time 5 "https://${subdomain}" 2>/dev/null | grep -qiE "wp-content|wp-includes|wp-json" >/dev/null 2>&1; then
            scan_wordpress "${subdomain}" || true
        fi
    done < "${SUBDOMAINS_FILE}"
fi

# Combine findings
cat "${OUTPUT_DIR}"/vapt_${TARGET}_wpscan_*.txt > "${OUTPUT_DIR}/vapt_${TARGET}_wpscan_all.txt" 2>/dev/null || touch "${OUTPUT_DIR}/vapt_${TARGET}_wpscan_all.txt"

exit 0

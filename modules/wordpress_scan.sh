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
    
    # Validate target is reachable
    echo "  Validating target accessibility..." >> "${LOG_FILE}"
    if ! curl -s -I --max-time 10 -k "https://${domain}" > /dev/null 2>&1; then
        # Try HTTP if HTTPS fails
        if ! curl -s -I --max-time 10 "http://${domain}" > /dev/null 2>&1; then
            echo "  Target $domain is not reachable. Skipping." >> "${LOG_FILE}"
            return 1
        fi
        # Use HTTP if HTTPS failed
        local protocol="http"
    else
        local protocol="https"
    fi
    
    # Build aggressive 2025-standard command
    # Flags based on user checklist: --enumerate u,ap,at,tt --plugins-detection aggressive --max-threads 20 --stealthy --force --detection-mode mixed
    local cmd="${WPSCAN_PATH} --url \"${protocol}://${domain}\" --enumerate u,ap,at,tt --plugins-detection aggressive --max-threads 20 --stealthy --force --detection-mode mixed --disable-tls-checks --ignore-main-redirect --output \"${output_file}\" --format cli"
    
    # Add API token if present
    if [ -n "$WPSCAN_API_TOKEN" ]; then
        cmd="$cmd --api-token $WPSCAN_API_TOKEN"
    fi
    
    # Run wpscan with error handling
    echo "  Running Aggressive WPScan on ${protocol}://${domain}..." >> "${LOG_FILE}"
    eval "$cmd" >> "${OUTPUT_DIR}/wpscan_debug.log" 2>&1
    
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo "  WPScan failed for $domain (exit code: $exit_code). Check wpscan_debug.log" >> "${LOG_FILE}"
        tail -n 5 "${OUTPUT_DIR}/wpscan_debug.log" >> "${LOG_FILE}" 2>&1
    else
        echo "  WPScan completed for $domain" >> "${LOG_FILE}"
    fi

    # --- 2025 Checklist: Extra Discovery Phase ---
    echo "Running 2025 Checklist Extra Discovery for $domain..." >> "${LOG_FILE}"
    local EXTRA_OUT="${OUTPUT_DIR}/vapt_${TARGET}_extra_checks.txt"
    
    # 1. Advanced User Enumeration (REST API & Sitemaps)
    # Check REST API
    echo "  Checking REST API User Enumeration..." >> "${LOG_FILE}"
    rest_users=$(curl -s -k "https://${domain}/wp-json/wp/v2/users")
    if echo "$rest_users" | jq -e '. | type == "array" and length > 0' >/dev/null 2>&1; then
        user_list=$(echo "$rest_users" | jq -r '.[].slug' | tr '\n' ',' | sed 's/,$//')
        echo "[!] REST API User Exposure: ${user_list}" >> "$EXTRA_OUT"
    fi

    # Check Author Sitemap
    if curl -s -I -k "https://${domain}/author-sitemap.xml" | grep -q "HTTP/.* 200"; then
        echo "[!] Author Sitemap Exposed: https://${domain}/author-sitemap.xml" >> "$EXTRA_OUT"
    fi

    # 2. Greedy Sensitive File Discovery (Backups, VCS, Configs)
    # Ref: 2025 Checklist Items
    echo "  Scanning for exposed backups and config leaks..." >> "${LOG_FILE}"
    
    # Common sensitive paths and backups
    paths=(
        ".git/config" ".env" "php.ini" "error_log" "debug.log" "wp-config.php.bak" 
        "wp-config.php.old" "wp-config.php.save" "wp-config.php.txt" "wp-config.php~"
        "wp-config.php.swp" ".htaccess.bak" ".htaccess.old" "database.sql" 
        "dump.sql" "backup.zip" "site.zip" "wp-content/debug.log"
    )

    for path in "${paths[@]}"; do
        status=$(curl -o /dev/null -s -w "%{http_code}" -k "https://${domain}/$path")
        if [ "$status" == "200" ]; then
             # Verify it's not a false positive (e.g. 200 with 404 text)
             if curl -s -k "https://${domain}/$path" | grep -qiE "DB_PASSWORD|DB_NAME|git|env" >/dev/null 2>&1; then
                echo "[CRITICAL] Sensitive File Exposed: https://${domain}/$path" >> "$EXTRA_OUT"
             else
                echo "[!] Potential Sensitive File: https://${domain}/$path (HTTP 200)" >> "$EXTRA_OUT"
             fi
        fi
    done

    # 3. Security Hardening Checks
    # Check for XML-RPC
    if curl -s -k "https://${domain}/xmlrpc.php" | grep -q "XML-RPC server accepts POST requests only."; then
        echo "[!] XML-RPC is Enabled at https://${domain}/xmlrpc.php" >> "$EXTRA_OUT"
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
scan_wordpress "${TARGET}"

# Scan subdomains
if [ -f "${SUBDOMAINS_FILE}" ]; then
    while IFS= read -r subdomain; do
        if [ -n "$subdomain" ]; then
            if curl -s -I -k "https://${subdomain}" --max-time 5 | grep -i "wp-content" >/dev/null 2>&1; then
                scan_wordpress "${subdomain}"
            fi
        fi
    done < "${SUBDOMAINS_FILE}"
fi

cat "${OUTPUT_DIR}"/*.txt > "${OUTPUT_DIR}/vapt_${TARGET}_wpscan_all.txt" 2>/dev/null

#!/bin/bash

# Configuration variables for Enhanced WordPress VAPT v2.0

# OpenRouter API
OPENROUTER_API_KEY="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"
OPENROUTER_MODEL="qwen/qwen-2.5-coder-32b-instruct"
# Resolve path relative to this config file
SEC_AI_PATH="$(dirname "${BASH_SOURCE[0]}")/../sec_ai/main.py"

# Tool paths (adjust as needed)
SUBFINDER_PATH="/opt/tools/go/bin/subfinder"
AMASS_PATH="/usr/bin/amass"
KATANA_PATH="/opt/tools/go/bin/katana"
HTTPX_PATH="/usr/bin/httpx"
WAFW00F_PATH="/usr/bin/wafw00f"
GOWITNESS_PATH="/opt/tools/go/bin/gowitness"
WPSCAN_PATH="/usr/local/bin/wpscan"
NUCLEI_PATH="/opt/tools/go/bin/nuclei"
NAABU_PATH="/opt/tools/go/bin/naabu"
UNCOVER_PATH="/opt/tools/go/bin/uncover"
WHATWEB_PATH="/usr/bin/whatweb"

# V3 Tools
GAU_PATH="/opt/tools/go/bin/gau"
WAYBACKURLS_PATH="/opt/tools/go/bin/waybackurls"
TRUFFLEHOG_PATH="/usr/local/bin/trufflehog"
FFUF_PATH="/usr/bin/ffuf"
DALFOX_PATH="/opt/tools/go/bin/dalfox"
SQLMAP_PATH="/usr/bin/sqlmap"

# Tool options
SUBFINDER_OPTIONS=""
AMASS_OPTIONS="-passive"
KATANA_OPTIONS="-depth 2 -js-crawl"
HTTPX_OPTIONS="-status-code -title -tech-detect -content-length -silent"
HTTPX_MATCHER_CODES="200,301,302,403"
HTTPX_MATCHER_DOMAINS="admin,api,backup,config,database,dev,old,stage,test"
HTTPX_PATHS_TO_PROBE="/admin,/wp-admin,/wp-login.php,/wp-config.php,/backup,/old,/test,/dev"
HTTPX_METHODS_TO_CHECK="GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD"
WAFW00F_OPTIONS="-a"
GOWITNESS_OPTIONS="--delay 2 --timeout 15 --threads 5 --resolution 1920x1080"
NAABU_OPTIONS="-top-ports 1000"
UNCOVER_OPTIONS="-l 20"
WPSCAN_OPTIONS="--random-user-agent --detection-mode aggressive --disable-tls-checks --ignore-main-redirect"
# Note: --url is handled dynamically by the module script
WPSCAN_API_TOKEN="bqMrmBBahqQQa15bTTSSu623B6zl94V8akuxhWQiqCI"
NUCLEI_OPTIONS="-c 50 -bs 25 -retries 2 -no-mhe"

# V3 Options
GAU_OPTIONS="--threads 5"
TRUFFLEHOG_OPTIONS="filesystem"
FFUF_OPTIONS="-t 50 -mc 200,301,302,403"
DALFOX_OPTIONS="-b hahwul.xss.ht"
FEROXBUSTER_OPTIONS="--auto-tune --depth 2"
GOSPIDER_OPTIONS="-d 2 --no-redirect -t 20"

# WordPress-specific Nuclei templates
WORDPRESS_TEMPLATES="cves/wordpress/,vulnerabilities/wordpress/,misconfiguration/wordpress/"
CUSTOM_WORDPRESS_TEMPLATES="templates/nuclei/"

# Sensitive routes detection context for OpenRouter
SENSITIVE_ROUTES_PROMPT="Analyze the following URLs and identify potentially sensitive endpoints or routes that might expose sensitive information, admin panels, or configuration files. For each identified endpoint, explain why it might be sensitive and what security implications it could have."

#!/bin/bash

# Configuration variables for WordPress VAPT

# OpenRouter API
OPENROUTER_API_KEY="your_openrouter_api_key_here"
OPENROUTER_MODEL="gpt-4"  # or your preferred model

# Tool paths (adjust as needed)
SUBFINDER_PATH="/opt/tools/go/bin/subfinder"
AMASS_PATH="/usr/bin/amass"
KATANA_PATH="/opt/tools/go/bin/katana"
HACKCRAWLER_PATH="/opt/tools/go/bin/hakrawler"  # Changed from hackcrawler to hakrawler
WAFW00F_PATH="/usr/bin/wafw00f"
GOWITNESS_PATH="/opt/tools/go/bin/gowitness"
WPSCAN_PATH="/usr/local/bin/wpscan"
NUCLEI_PATH="/opt/tools/go/bin/nuclei"

# Tool options
SUBFINDER_OPTIONS="-v"
AMASS_OPTIONS="-passive"
KATANA_OPTIONS="-depth 2 -js-crawl"
HACKCRAWLER_OPTIONS="-depth 2"
GOWITNESS_OPTIONS="-screenshot-size 1920,1080"
WPSCAN_OPTIONS="--url-template {target} --follow-redirects --random-user-agent"
NUCLEI_OPTIONS="-severity critical,high,medium,low,info -rl 50"
HTTPX_OPTIONS="-status-code -title -tech-detect -content-length -silent"
HTTPX_MATCHER_CODES="200,301,302,403"
HTTPX_MATCHER_DOMAINS="admin,api,backup,config,database,dev,old,stage,test"
HTTPX_PATHS_TO_PROBE="/admin,/wp-admin,/wp-login.php,/wp-config.php,/backup,/old,/test,/dev"
HTTPX_METHODS_TO_CHECK="GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD"


# WordPress-specific Nuclei templates (can be expanded)
WORDPRESS_TEMPLATES="cves/wordpress/,vulnerabilities/wordpress/,misconfiguration/wordpress/"
CUSTOM_WORDPRESS_TEMPLATES="templates/nuclei/"

# Sensitive routes detection context for OpenRouter
SENSITIVE_ROUTES_PROMPT="Analyze the following URLs and identify potentially sensitive endpoints or routes that might expose sensitive information, admin panels, or configuration files. For each identified endpoint, explain why it might be sensitive and what security implications it could have."

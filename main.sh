#!/bin/bash

# Configuration for colors (before sourcing to ensure usage check is pretty)
RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'
BLUE=$'\e[0;34m'
NC=$'\e[0m' # No Color

# Check if target domain is provided (Top priority)
if [ $# -eq 0 ] || [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    echo -e "${RED}Usage: $0 <target_domain> [--cookie \"session=...\"]${NC}"
    exit 1
fi

TARGET=$1
shift

# Default values
COOKIE=""

# Parse additional arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --cookie) COOKIE="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Load configuration and UI logger
set -a
# Ensure config exists
if [ ! -f "config/config.sh" ]; then
    if [ -f "config/config.sh.template" ]; then
        echo "Creating config.sh from template..."
        cp config/config.sh.template config/config.sh
    else
        echo -e "${RED}[!] Critical Error: config.sh.template not found!${NC}"
        exit 1
    fi
fi
source config/config.sh
# Ensure logger is sourced for UI functions (print_banner, run_with_spinner, etc.)
source utils/logger.sh
# Run Dependency Check
source utils/check_deps.sh

# Initialize AI status (1 = failed/disabled, 0 = success)
export AI_CHECK_STATUS=1

# Interactive API Key Check with Connectivity Test
check_api_keys() {
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        local config_updated=false
        
        # 1. Check/Prompt for OpenRouter API Key
        if [ -z "$OPENROUTER_API_KEY" ] || [ "$OPENROUTER_API_KEY" == "your_openrouter_api_key_here" ]; then
            echo -e "${YELLOW}[!] OpenRouter API Key is missing or default.${NC}"
            read -p "   Please enter your OpenRouter API Key: " input_key
            if [ -n "$input_key" ]; then
                OPENROUTER_API_KEY="$input_key"
                # Use | as delimiter to avoid issues with / in keys
                sed -i "s|OPENROUTER_API_KEY=\".*\"|OPENROUTER_API_KEY=\"$input_key\"|" config/config.sh
                config_updated=true
            else
                echo -e "${RED}[!] Key is required for AI features. Disabling AI for this session.${NC}"
                OPENROUTER_API_KEY=""
                return 0
            fi
        fi

        # 2. Verify Connectivity
        if [ -n "$OPENROUTER_API_KEY" ]; then
            echo -e "[-] Verifying OpenRouter API Access for model: ${BLUE}${OPENROUTER_MODEL}${NC}"
            export OPENROUTER_API_KEY
            export OPENROUTER_MODEL
            
            python3 "$SEC_AI_PATH" check > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[+] API Connection Successful.${NC}"
                AI_CHECK_STATUS=0
                return 0
            else
                echo -e "${RED}[!] API Connectivity Check Failed (Possible 401 Unauthorized or Network Error).${NC}"
                read -p "   Would you like to re-enter your OpenRouter API Key? (y/N): " re_enter
                if [[ "$re_enter" =~ ^[Yy]$ ]]; then
                    OPENROUTER_API_KEY=""
                    retry_count=$((retry_count + 1))
                else
                    echo -e "${YELLOW}[-] Proceeding without AI features.${NC}"
                    OPENROUTER_API_KEY=""
                    return 0
                fi
            fi
        fi
    done
}

# Check WPScan API Token (Non-critical, no connectivity test needed here)
check_wpscan_token() {
    if [ -z "$WPSCAN_API_TOKEN" ] || [ "$WPSCAN_API_TOKEN" == "your_wpscan_api_token_here" ]; then
        echo -e "${YELLOW}[!] WPScan API Token is missing.${NC}"
        echo -e "   You can get a free token from https://wpscan.com/api"
        read -p "   Please enter your WPScan API Token (or press Enter to skip): " input_token
        if [ -n "$input_token" ]; then
            WPSCAN_API_TOKEN="$input_token"
            sed -i "s|WPSCAN_API_TOKEN=\".*\"|WPSCAN_API_TOKEN=\"$input_token\"|" config/config.sh
            export WPSCAN_API_TOKEN
        fi
    fi
}

check_api_keys
check_wpscan_token

# Export dynamic variables for modules
export TARGET
export COOKIE
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
RESULTS_DIR="results/${TARGET}_${DATE}"

# Export dynamic variables for modules
export TARGET
export RESULTS_DIR

# Create results directory structure
mkdir -p "${RESULTS_DIR}"/{subdomains,urls,httpx,network,dns,firewall,nuclei,screenshots,wordpress,context,final_report,route_analysis}

# Log file
LOG_FILE="${RESULTS_DIR}/vapt_${TARGET}_log.txt"
export LOG_FILE

# Start Scan
clear
python3 utils/banner.py

echo "Target: $TARGET"
[ -n "$COOKIE" ] && echo "Authentication: Enabled (Cookie Provided)"
echo "Started: $(date)"
echo -e "${NC}"
echo "------------------------------------------------"

echo "Full execution log: ${LOG_FILE}"

# Function to execute a module with UI
execute_module() {
    local task_name=$1
    local module_script=$2
    local output_dir=$3
    shift 3
    
    run_with_spinner "${task_name}" bash modules/${module_script} "${TARGET}" "${output_dir}" "$@"
    
    # After module finishes, check results and print finding summary
    case $module_script in
        "subdomain_enum.sh")
            count=$(cat "${output_dir}/vapt_${TARGET}_subdomains_all.txt" 2>/dev/null | wc -l)
            log_finding "$count" "Subdomains"
            ;;
        "httpx_live_filter.sh")
            if [ ! -s "${output_dir}/live_hosts.txt" ]; then
                 echo -e "   ${RED}✖ Critical Failure: live_hosts.txt is empty. Stopping pipeline.${NC}"
                 exit 1
            fi
            count=$(cat "${output_dir}/live_hosts.txt" 2>/dev/null | wc -l)
            log_finding "$count" "Live Hosts"
            ;;
        "url_discovery.sh")
            count=$(cat "${output_dir}/vapt_${TARGET}_urls_all.txt" 2>/dev/null | wc -l)
            log_finding "$count" "URLs"
            ;;
        "nuclei_scan.sh"|"nuclei_wayback.sh")
            # Check for non-empty results logic or ensure folder creation
            if [ ! -d "${output_dir}" ]; then mkdir -p "${output_dir}"; fi
            count=$(jq '.summary.total_findings // 0' "${output_dir}"/*.json 2>/dev/null | head -n 1)
            log_finding "${count:-0}" "Vulnerabilities Identified"
            ;;
        "zap_daemon.sh")
            if [ ! -s "${output_dir}/zap_report.html" ]; then
                 echo -e "   ${RED}✖ ZAP Report generation failed.${NC}"
            fi
            ;;

        "wordpress_scan.sh")
            if [ -s "${output_dir}/vapt_${TARGET}_wpscan_all.txt" ]; then
                log_finding 1 "WordPress Scan Complete"
            fi
            ;;
        *)
            ;;
    esac
}

# Execute all modules
print_banner "Reconnaissance Phase"
execute_module "Scanning Subdomains" "subdomain_enum.sh" "${RESULTS_DIR}/subdomains"
execute_module "Discovering URLs" "url_discovery.sh" "${RESULTS_DIR}/urls"

print_banner "Live Host Discovery & Filtering"
execute_module "Filtering Live Hosts (HTTPX)" "httpx_live_filter.sh" "${RESULTS_DIR}/httpx"

print_banner "Analysis Phase"
execute_module "Analyzing Technologies" "httpx_analysis.sh" "${RESULTS_DIR}/httpx"
execute_module "Detecting WAF Behavior" "waf_behavior.sh" "${RESULTS_DIR}/firewall"
execute_module "Gathering Network Info" "network_info.sh" "${RESULTS_DIR}/network"
execute_module "Querying DNS Records" "dns_info.sh" "${RESULTS_DIR}/dns"
execute_module "Detecting Firewalls" "firewall_detection.sh" "${RESULTS_DIR}/firewall"
execute_module "Auditing Configuration & Hardening" "config_audit.sh" "${RESULTS_DIR}/context"

print_banner "Deep Discovery Phase"
execute_module "Historical Reconnaissance (Wayback/GAU)" "historical_scan.sh" "${RESULTS_DIR}/urls"
execute_module "Spidering (GoSpider)" "spidering.sh" "${RESULTS_DIR}/spidering"

# Combine all URL sources for advanced scanning
cat "${RESULTS_DIR}/urls/"*.txt "${RESULTS_DIR}/spidering/"*.txt 2>/dev/null | sort -u > "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt"

execute_module "Discovering Parameters & Endpoints" "param_discovery.sh" "${RESULTS_DIR}/urls"
execute_module "Analyzing Vulnerable Routes (IDOR/SQLi/SSRF/XSS)" "vulnerable_routes.sh" "${RESULTS_DIR}/route_analysis"

# AI-Driven Target Selection for Deep Phases
if [ "$AI_CHECK_STATUS" -eq 0 ]; then
    echo -ne "${BLUE}[*] AI selecting interesting targets for Screenshots & Fuzzing...${NC}"
    mkdir -p "${RESULTS_DIR}/screenshots" "${RESULTS_DIR}/fuzzing"
    python3 utils/target_selector.py --input "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt" --mode screenshots --output "${RESULTS_DIR}/screenshots/urls_to_screenshot.txt" >> "${LOG_FILE}" 2>&1
    python3 utils/target_selector.py --input "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt" --mode fuzzing --output "${RESULTS_DIR}/fuzzing/urls_to_fuzz.txt" >> "${LOG_FILE}" 2>&1
    echo -e "${GREEN} Done.${NC}"
fi

print_banner "Active Vulnerability Phase"
execute_module "Extracting Identity & Secrets" "secrets_scan.sh" "${RESULTS_DIR}/secrets" "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt"
execute_module "Advanced Fuzzing & Exploitation (FFUF/Dalfox/SQLMap)" "fuzzing.sh" "${RESULTS_DIR}/fuzzing" "tools/wordlists/raft-medium-directories.txt" "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt" "$COOKIE"
execute_module "Running Nuclei Scans (Standard)" "nuclei_scan.sh" "${RESULTS_DIR}/nuclei"
execute_module "Running Nuclei Scans (Wayback-Enhanced)" "nuclei_wayback.sh" "${RESULTS_DIR}/nuclei"
execute_module "OWASP ZAP Baseline & Active Scan" "zap_daemon.sh" "${RESULTS_DIR}/zap" "$COOKIE"

execute_module "Analyzing WordPress Core" "wordpress_scan.sh" "${RESULTS_DIR}/wordpress"
execute_module "Static Analysis of Plugins (SAST)" "plugin_sast.sh" "${RESULTS_DIR}/wordpress"
execute_module "Capturing Evidence (Screenshots)" "screenshots.sh" "${RESULTS_DIR}/screenshots"

print_banner "Reporting Phase"
run_with_spinner "Building Context" python3 utils/context_builder.py "${TARGET}" "${RESULTS_DIR}"

if [ -n "$OPENROUTER_API_KEY" ] && [ "$OPENROUTER_API_KEY" != "your_openrouter_api_key_here" ] && [ "$AI_CHECK_STATUS" -eq 0 ]; then
    echo -e "${BLUE}[*] Starting AI Analysis (Red Team Persona - Vṛthā v2.1)...${NC}"
    
    # Define output report path
    FINAL_REPORT="${RESULTS_DIR}/final_report/vapt_${TARGET}_ai_report.md"
    
    # Execute AI Analysis
    run_with_spinner "AI Vulnerability Analysis & PDF Generation" python3 "$SEC_AI_PATH" analyze --input "${RESULTS_DIR}" --output "${FINAL_REPORT}" --format pdf
    
    echo -e "${GREEN}[+] AI Report Generated: ${FINAL_REPORT}${NC}"
else
    echo -e "${YELLOW}Skipping AI Analysis (No API Key or Check Failed).${NC}"
    echo "Basic report structure available in ${RESULTS_DIR}/context/"
fi

# Generate HTML Report
echo -e "${BLUE}[*] Generating Final HTML Report...${NC}"
python3 utils/report_generator.py "${TARGET}" "${RESULTS_DIR}" 2>>"${LOG_FILE}" || echo -e "${YELLOW}HTML report generation error${NC}"

echo -e "\n${GREEN}${BOLD}Vṛthā VAPT Scan Completed Successfully!${NC}"
echo -e "Results Directory: ${BLUE}${RESULTS_DIR}${NC}"
if [ -f "${RESULTS_DIR}/final_report/vapt_${TARGET}_report.html" ]; then
    echo -e "HTML Report: ${BLUE}${RESULTS_DIR}/final_report/vapt_${TARGET}_report.html${NC}"
fi
if [ -f "${RESULTS_DIR}/final_report/vapt_${TARGET}_ai_report.md" ]; then
    echo -e "AI Report (Markdown): ${BLUE}${RESULTS_DIR}/final_report/vapt_${TARGET}_ai_report.md${NC}"
fi
if [ -f "${RESULTS_DIR}/final_report/vapt_${TARGET}_ai_report.pdf" ]; then
    echo -e "Professional PDF: ${BLUE}${RESULTS_DIR}/final_report/vapt_${TARGET}_ai_report.pdf${NC}"
fi

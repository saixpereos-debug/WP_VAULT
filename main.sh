#!/bin/bash

# Enhanced Vṛthā - WordPress VAPT Automation Framework v2.0
# Main execution script

# Load configuration and UI logger
set -a
source config/config.sh
# Run Dependency Check
source utils/check_deps.sh

# Interactive API Key Check
check_api_keys() {
    local config_updated=false
    
    # Check OpenRouter API Key
    if [ -z "$OPENROUTER_API_KEY" ] || [ "$OPENROUTER_API_KEY" == "your_openrouter_api_key_here" ]; then
        echo -e "${YELLOW}[!] OpenRouter API Key is missing or default.${NC}"
        echo -e "   This key is required for AI-powered report generation."
        read -p "   Please enter your OpenRouter API Key (or press Enter to skip): " input_key
        if [ -n "$input_key" ]; then
            OPENROUTER_API_KEY="$input_key"
            # Update config file
            if [[ "$OSTYPE" == "darwin"* ]]; then
                sed -i '' "s/OPENROUTER_API_KEY=\".*\"/OPENROUTER_API_KEY=\"$input_key\"/" config/config.sh
            else
                sed -i "s/OPENROUTER_API_KEY=\".*\"/OPENROUTER_API_KEY=\"$input_key\"/" config/config.sh
            fi
            config_updated=true
            echo -e "${GREEN}   Saved to config/config.sh${NC}"
        fi
    fi

    # Check WPScan API Token
    if [ -z "$WPSCAN_API_TOKEN" ]; then
        echo -e "${YELLOW}[!] WPScan API Token is missing.${NC}"
        echo -e "   This token is required for the most up-to-date vulnerability database."
        echo -e "   You can get a free token from https://wpscan.com/api"
        read -p "   Please enter your WPScan API Token (or press Enter to skip): " input_token
        if [ -n "$input_token" ]; then
            WPSCAN_API_TOKEN="$input_token"
            # Update config file
            if [[ "$OSTYPE" == "darwin"* ]]; then
                 sed -i '' "s/WPSCAN_API_TOKEN=\".*\"/WPSCAN_API_TOKEN=\"$input_token\"/" config/config.sh
            else
                 sed -i "s/WPSCAN_API_TOKEN=\".*\"/WPSCAN_API_TOKEN=\"$input_token\"/" config/config.sh
            fi
            config_updated=true
            echo -e "${GREEN}   Saved to config/config.sh${NC}"
        fi
    fi
    
    # Re-export if updated
    if [ "$config_updated" = true ]; then
        export OPENROUTER_API_KEY
        export WPSCAN_API_TOKEN
    fi
}

check_api_keys
 
# Check OpenRouter API Connectivity if key is present
if [ -n "$OPENROUTER_API_KEY" ] && [ "$OPENROUTER_API_KEY" != "your_openrouter_api_key_here" ]; then
    echo -e "[-] Verifying OpenRouter API Access for model: ${BLUE}${OPENROUTER_MODEL}${NC}"
    if [ -f "$SEC_AI_PATH" ]; then
        python3 "$SEC_AI_PATH" check
        AI_CHECK_STATUS=$?
        if [ $AI_CHECK_STATUS -ne 0 ]; then
             echo -e "${RED}[!] AI Connectivity Check Failed. AI features will be disabled for this session.${NC}"
             OPENROUTER_API_KEY=""
        else
             echo -e "${GREEN}[+] AI Model Connected Successfully.${NC}"
        fi
    else
        echo -e "${RED}[!] sec_ai module not found at $SEC_AI_PATH${NC}"
    fi
fi

# Check if target domain is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Usage: $0 <target_domain>${NC}"
    exit 1
fi

TARGET=$1
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
RESULTS_DIR="results/${TARGET}_${DATE}"

# Export dynamic variables for modules
export TARGET
export RESULTS_DIR

# Create results directory structure
mkdir -p "${RESULTS_DIR}"/{subdomains,urls,httpx,network,dns,firewall,nuclei,screenshots,wordpress,context,final_report}

# Log file
LOG_FILE="${RESULTS_DIR}/vapt_${TARGET}_log.txt"
export LOG_FILE

# Start Scan
clear
python3 utils/banner.py

echo "Target: $TARGET"
echo "Started: $(date)"
echo -e "${NC}"
echo "------------------------------------------------"

echo "Full execution log: ${LOG_FILE}"

# Function to execute a module with UI
execute_module() {
    local task_name=$1
    local module_script=$2
    local output_dir=$3
    
    # We use run_with_spinner to execute the module
    # The module itself usually produces output files, so we don't need to capture stdout
    # The module might print 'log_finding' lines, but since run_with_spinner redirects everything to LOG_FILE,
    # we need a way to extract the summary finding or let the module write a summary file we can read.
    
    # NEW STRATEGY: 
    # The module is executed via run_with_spinner. 
    # Output goes to LOG_FILE.
    # To show "findings" in the UI, we check the output files OR regex the log for a special marker if needed.
    # For simplicity, we just show the spinner validation.
    # Ideally, modules should print summary stats to a specific temporary file or variable?
    # Let's keep it simple: run module, check if files exist, print rough stats based on file line counts.
    
    run_with_spinner "${task_name}" bash modules/${module_script} "${TARGET}" "${output_dir}"
    
    # After module finishes, check results and print finding summary
    case $module_script in
        "subdomain_enum.sh")
            count=$(cat "${output_dir}/vapt_${TARGET}_subdomains_all.txt" 2>/dev/null | wc -l)
            log_finding "$count" "Subdomains"
            ;;
        "url_discovery.sh")
            count=$(cat "${output_dir}/vapt_${TARGET}_urls_all.txt" 2>/dev/null | wc -l)
            log_finding "$count" "URLs"
            ;;
        "nuclei_scan.sh")
            # This is trickier, let's count vulnerabilities from json
            count=$(jq '.by_category | map(length) | add' "${output_dir}/vapt_${TARGET}_nuclei_categorized.json" 2>/dev/null)
            log_finding "${count:-0}" "Vulnerabilities (Nuclei)"
            ;;
        "wordpress_scan.sh")
            # Parsing wpscan output is hard without parsing proper JSON
            # We can check line count of vuln block or file size
            # Let's just say "Scan Completed"
            if [ -s "${output_dir}/vapt_${TARGET}_wpscan_all.txt" ]; then
                log_finding 1 "WordPress Scan Results Generated"
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

print_banner "Analysis Phase"
execute_module "Analyzing Technologies" "httpx_analysis.sh" "${RESULTS_DIR}/httpx"
execute_module "Gathering Network Info" "network_info.sh" "${RESULTS_DIR}/network"
execute_module "Querying DNS Records" "dns_info.sh" "${RESULTS_DIR}/dns"
execute_module "Detecting Firewalls" "firewall_detection.sh" "${RESULTS_DIR}/firewall"

print_banner "Deep Discovery Phase (V3 Enterprise)"
execute_module "Historical Recon (GAU/Wayback)" "historical_scan.sh" "${RESULTS_DIR}/urls"
execute_module "Advanced Recon (Uncover)" "uncover_recon.sh" "${RESULTS_DIR}/uncover"
execute_module "Fuzzing Content (Feroxbuster)" "content_discovery.sh" "${RESULTS_DIR}/content"
execute_module "Spidering & Parameter Mining (Gospider)" "spidering.sh" "${RESULTS_DIR}/spidering"

# Combine all URL sources for advanced scanning
cat "${RESULTS_DIR}/urls/"*.txt "${RESULTS_DIR}/spidering/"*.txt "${RESULTS_DIR}/content/"*.txt 2>/dev/null | sort -u > "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt"

print_banner "Active Vulnerability Phase"
execute_module "Secrets Scanning (TruffleHog)" "secrets_scan.sh" "${RESULTS_DIR}/secrets" "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt"
execute_module "Advanced Fuzzing & Exploitation (FFUF/Dalfox/SQLMap)" "fuzzing.sh" "${RESULTS_DIR}/fuzzing" "tools/wordlists/raft-medium-directories.txt" "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt"
execute_module "Running Nuclei Scans" "nuclei_scan.sh" "${RESULTS_DIR}/nuclei"

execute_module "Specifying WordPress Issues" "wordpress_scan.sh" "${RESULTS_DIR}/wordpress"
execute_module "Capturing Evidence" "screenshots.sh" "${RESULTS_DIR}/screenshots"

print_banner "Reporting Phase"
run_with_spinner "Building Context" python3 utils/context_builder.py "${TARGET}" "${RESULTS_DIR}"

if [ -n "$OPENROUTER_API_KEY" ] && [ "$OPENROUTER_API_KEY" != "your_openrouter_api_key_here" ] && [ "$AI_CHECK_STATUS" -eq 0 ]; then
    echo -e "${BLUE}[*] Starting AI Analysis (Red Team Persona)...${NC}"
    
    # Define output report path
    FINAL_REPORT="${RESULTS_DIR}/final_report/vapt_${TARGET}_ai_report.md"
    
    # Execute AI Analysis
    run_with_spinner "AI Vulnerability Analysis" python3 "$SEC_AI_PATH" analyze --input "${RESULTS_DIR}" --output "${FINAL_REPORT}"
    
    echo -e "${GREEN}[+] AI Report Generated: ${FINAL_REPORT}${NC}"
else
    echo -e "${YELLOW}Skipping AI Analysis (No API Key or Check Failed).${NC}"
    echo "Basic report structure available in ${RESULTS_DIR}/context/"
fi

echo -e "\n${GREEN}${BOLD}Scan Completed Successfully!${NC}"
echo -e "Report: ${BLUE}${RESULTS_DIR}/final_report/vapt_${TARGET}_report.html${NC}"

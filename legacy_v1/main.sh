#!/bin/bash

# Enhanced WordPress VAPT Automation Framework v2.0
# Main execution script

# Load configuration
source config/config.sh

# Check if target domain is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_domain>"
    exit 1
fi

TARGET=$1
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
RESULTS_DIR="results/${TARGET}_${DATE}"

# Create results directory structure
mkdir -p "${RESULTS_DIR}"/{subdomains,urls,httpx,network,dns,firewall,nuclei,screenshots,wordpress,context,final_report}

# Log file
LOG_FILE="${RESULTS_DIR}/vapt_${TARGET}_log.txt"
echo "Enhanced WordPress VAPT for ${TARGET} started at ${DATE}" | tee -a "${LOG_FILE}"

# Function to execute a module and log results
execute_module() {
    local module_name=$1
    local module_script=$2
    local output_dir=$3
    
    echo "Executing ${module_name}..." | tee -a "${LOG_FILE}"
    
    # Execute the module and capture output
    bash modules/${module_script} "${TARGET}" "${output_dir}" 2>&1 | tee -a "${LOG_FILE}"
    
    if [ $? -eq 0 ]; then
        echo "${module_name} completed successfully" | tee -a "${LOG_FILE}"
    else
        echo "Error in ${module_name}" | tee -a "${LOG_FILE}"
    fi
}

# Execute all modules in sequence
execute_module "Subdomain Enumeration" "subdomain_enum.sh" "${RESULTS_DIR}/subdomains"
execute_module "URL Discovery" "url_discovery.sh" "${RESULTS_DIR}/urls"
execute_module "HTTPx Analysis" "httpx_analysis.sh" "${RESULTS_DIR}/httpx"
execute_module "Network Information" "network_info.sh" "${RESULTS_DIR}/network"
execute_module "DNS Information" "dns_info.sh" "${RESULTS_DIR}/dns"
execute_module "Firewall Detection" "firewall_detection.sh" "${RESULTS_DIR}/firewall"
execute_module "Nuclei Scanning" "nuclei_scan.sh" "${RESULTS_DIR}/nuclei"
execute_module "Screenshot Capture" "screenshots.sh" "${RESULTS_DIR}/screenshots"
execute_module "WordPress Scanning" "wordpress_scan.sh" "${RESULTS_DIR}/wordpress"

# Build optimized context for OpenRouter
echo "Building optimized context for OpenRouter..." | tee -a "${LOG_FILE}"
python3 utils/context_builder.py "${TARGET}" "${RESULTS_DIR}"

# Generate final report using OpenRouter API
echo "Generating final report..." | tee -a "${LOG_FILE}"
python3 utils/report_generator.py "${TARGET}" "${RESULTS_DIR}" "${OPENROUTER_API_KEY}"

echo "Enhanced WordPress VAPT for ${TARGET} completed. Results saved in ${RESULTS_DIR}" | tee -a "${LOG_FILE}"

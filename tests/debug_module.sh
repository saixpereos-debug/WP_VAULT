#!/bin/bash

# Quick Debug Script - Test Individual Modules
# Usage: bash tests/debug_module.sh <module_name> <target>

MODULE=$1
TARGET=${2:-"example.com"}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Load config
source config/config.sh

# Setup test environment
TEST_DIR="/tmp/vapt_debug_$$"
export RESULTS_DIR="${TEST_DIR}/results"
export LOG_FILE="${TEST_DIR}/debug.log"
mkdir -p "${RESULTS_DIR}"/{subdomains,urls,httpx,nuclei}

echo "=========================================="
echo "Module Debug - ${MODULE}"
echo "Target: ${TARGET}"
echo "=========================================="
echo ""

case "${MODULE}" in
    "subdomain_enum")
        echo "Testing subdomain enumeration..."
        bash modules/subdomain_enum.sh "${TARGET}" "${RESULTS_DIR}/subdomains"
        echo ""
        echo "Results:"
        ls -lh "${RESULTS_DIR}/subdomains/"
        echo ""
        echo "Sample output:"
        head -10 "${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt" 2>/dev/null || echo "No results"
        ;;
        
    "httpx_live_filter")
        echo "Testing HTTPX live host filtering..."
        # Create test subdomains
        cat > "${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt" << EOF
${TARGET}
www.${TARGET}
mail.${TARGET}
test.${TARGET}
EOF
        echo "Input subdomains:"
        cat "${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt"
        echo ""
        echo "Running httpx..."
        bash modules/httpx_live_filter.sh "${TARGET}" "${RESULTS_DIR}/httpx"
        echo ""
        echo "Results:"
        ls -lh "${RESULTS_DIR}/httpx/"
        echo ""
        echo "Live hosts found:"
        cat "${RESULTS_DIR}/httpx/live_hosts.txt" 2>/dev/null || echo "No live hosts"
        echo ""
        echo "Detailed output:"
        cat "${RESULTS_DIR}/httpx/live_hosts_detailed.txt" 2>/dev/null | head -10 || echo "No detailed output"
        ;;
        
    "vulnerable_routes")
        echo "Testing vulnerable route analysis..."
        # Create test URLs
        cat > "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt" << EOF
https://api.${TARGET}/v1/users/123/profile
https://${TARGET}/download?file=report.pdf
https://${TARGET}/search?q=test
https://${TARGET}/admin/users?id=456
https://${TARGET}/api/data?user_id=789
EOF
        echo "Input URLs:"
        cat "${RESULTS_DIR}/vapt_${TARGET}_master_urls.txt"
        echo ""
        echo "Running analysis..."
        mkdir -p "${RESULTS_DIR}/route_analysis"
        bash modules/vulnerable_routes.sh "${TARGET}" "${RESULTS_DIR}/route_analysis"
        echo ""
        echo "Results:"
        ls -lh "${RESULTS_DIR}/route_analysis/"
        echo ""
        echo "Findings summary:"
        jq '.summary' "${RESULTS_DIR}/route_analysis/vapt_${TARGET}_vulnerable_routes.json" 2>/dev/null || echo "No JSON output"
        ;;
        
    "httpx_analysis")
        echo "Testing HTTPX technology detection..."
        # Create test URLs
        cat > "${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt" << EOF
https://${TARGET}
https://www.${TARGET}
EOF
        echo "Input URLs:"
        cat "${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"
        echo ""
        echo "Running httpx analysis..."
        bash modules/httpx_analysis.sh "${TARGET}" "${RESULTS_DIR}/httpx"
        echo ""
        echo "Results:"
        ls -lh "${RESULTS_DIR}/httpx/"
        echo ""
        echo "Technologies found:"
        cat "${RESULTS_DIR}/httpx/vapt_${TARGET}_technologies.txt" 2>/dev/null || echo "No technologies detected"
        echo ""
        echo "Sample JSON:"
        head -5 "${RESULTS_DIR}/httpx/vapt_${TARGET}_httpx_combined.json" 2>/dev/null || echo "No JSON output"
        ;;
        
    "context_builder")
        echo "Testing context builder..."
        # Create minimal test data
        mkdir -p "${RESULTS_DIR}"/{subdomains,urls,httpx}
        echo "${TARGET}" > "${RESULTS_DIR}/subdomains/vapt_${TARGET}_subdomains_all.txt"
        echo "https://${TARGET}" > "${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"
        cat > "${RESULTS_DIR}/httpx/vapt_${TARGET}_technologies.txt" << EOF
WordPress
PHP
MySQL
EOF
        cat > "${RESULTS_DIR}/httpx/vapt_${TARGET}_httpx_combined.json" << EOF
{"url":"https://${TARGET}","status_code":200,"tech":["WordPress","PHP"]}
EOF
        echo "Running context builder..."
        python3 utils/context_builder.py "${TARGET}" "${RESULTS_DIR}"
        echo ""
        echo "Results:"
        ls -lh "${RESULTS_DIR}/context/"
        echo ""
        echo "Technologies in context:"
        jq '.summary.technologies' "${RESULTS_DIR}/context/vapt_${TARGET}_optimized_context.json" 2>/dev/null || echo "No context generated"
        ;;
        
    *)
        echo -e "${RED}Unknown module: ${MODULE}${NC}"
        echo ""
        echo "Available modules:"
        echo "  - subdomain_enum"
        echo "  - httpx_live_filter"
        echo "  - vulnerable_routes"
        echo "  - httpx_analysis"
        echo "  - context_builder"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "Debug log:"
echo "=========================================="
cat "${LOG_FILE}" 2>/dev/null || echo "No log file"

echo ""
echo "Test directory: ${TEST_DIR}"
echo "To inspect: ls -R ${TEST_DIR}"

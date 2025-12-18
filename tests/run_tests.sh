#!/bin/bash

# Automated Test Suite for WordPress VAPT Framework
# Tests every module with expected outputs and validates logic flow

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Test directory
TEST_DIR="/tmp/vapt_tests_$(date +%s)"
mkdir -p "${TEST_DIR}"

# Load config
source config/config.sh
export RESULTS_DIR="${TEST_DIR}/results"
export LOG_FILE="${TEST_DIR}/test.log"
mkdir -p "${RESULTS_DIR}"

echo "=========================================="
echo "WordPress VAPT Framework - Test Suite"
echo "=========================================="
echo ""

# Helper functions
pass_test() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((TESTS_PASSED++))
    ((TESTS_TOTAL++))
}

fail_test() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    echo "  Reason: $2"
    ((TESTS_FAILED++))
    ((TESTS_TOTAL++))
}

test_file_exists() {
    local file=$1
    local desc=$2
    if [ -f "$file" ]; then
        pass_test "$desc - File exists: $file"
        return 0
    else
        fail_test "$desc - File missing: $file" "Expected file was not created"
        return 1
    fi
}

test_file_not_empty() {
    local file=$1
    local desc=$2
    if [ -s "$file" ]; then
        local lines=$(wc -l < "$file")
        pass_test "$desc - File has content: $lines lines"
        return 0
    else
        fail_test "$desc - File is empty: $file" "Expected content but file is empty"
        return 1
    fi
}

test_command_exists() {
    local cmd=$1
    local desc=$2
    if command -v "$cmd" &> /dev/null; then
        pass_test "$desc - Command available: $cmd"
        return 0
    else
        fail_test "$desc - Command missing: $cmd" "Required tool not installed"
        return 1
    fi
}

# ==========================================
# TEST 1: Dependency Checks
# ==========================================
echo ""
echo "TEST SUITE 1: Dependency Validation"
echo "=========================================="

test_command_exists "subfinder" "Subdomain Enumeration"
test_command_exists "httpx" "HTTP Probing"
test_command_exists "nuclei" "Vulnerability Scanning"
test_command_exists "katana" "URL Discovery"
test_command_exists "gospider" "Web Spidering"
test_command_exists "wpscan" "WordPress Scanning"
test_command_exists "python3" "Python Runtime"
test_command_exists "jq" "JSON Processing"

# ==========================================
# TEST 2: Subdomain Enumeration
# ==========================================
echo ""
echo "TEST SUITE 2: Subdomain Enumeration"
echo "=========================================="

# Create test data
TEST_TARGET="example.com"
TEST_SUBDOMAINS_DIR="${RESULTS_DIR}/subdomains"
mkdir -p "${TEST_SUBDOMAINS_DIR}"

# Test subfinder syntax
echo "Testing subfinder command syntax..."
if subfinder -d example.com -silent -o "${TEST_DIR}/subfinder_test.txt" 2>&1 | grep -q "error\|Error"; then
    fail_test "Subfinder Syntax" "Command produced errors"
else
    pass_test "Subfinder Syntax" 
fi

# Test amass syntax
echo "Testing amass command syntax..."
if timeout 5 amass enum -d example.com -passive -o "${TEST_DIR}/amass_test.txt" 2>&1 | grep -q "flag provided but not defined"; then
    fail_test "Amass Syntax" "Invalid flags detected"
else
    pass_test "Amass Syntax"
fi

# ==========================================
# TEST 3: HTTPX Live Host Filtering
# ==========================================
echo ""
echo "TEST SUITE 3: HTTPX Live Host Filtering"
echo "=========================================="

# Create test subdomain list
cat > "${TEST_DIR}/test_subdomains.txt" << EOF
example.com
www.example.com
test.example.com
nonexistent.example.com
EOF

# Test httpx -list flag
echo "Testing httpx -list flag..."
if httpx -list "${TEST_DIR}/test_subdomains.txt" -silent -mc 200,301,302,403 -o "${TEST_DIR}/httpx_test.txt" 2>&1 | grep -q "No such option: -l"; then
    fail_test "HTTPX -list Flag" "Using wrong flag (-l instead of -list)"
else
    pass_test "HTTPX -list Flag"
fi

# Test live host extraction
if [ -f "${TEST_DIR}/httpx_test.txt" ] && [ -s "${TEST_DIR}/httpx_test.txt" ]; then
    if grep -qE "https?://" "${TEST_DIR}/httpx_test.txt"; then
        pass_test "HTTPX Output Format" 
    else
        fail_test "HTTPX Output Format" "No URLs found in output"
    fi
fi

# ==========================================
# TEST 4: Nuclei Scanning
# ==========================================
echo ""
echo "TEST SUITE 4: Nuclei Vulnerability Scanning"
echo "=========================================="

# Create test URL list
cat > "${TEST_DIR}/test_urls.txt" << EOF
https://example.com
https://www.example.com
EOF

# Test nuclei -list flag
echo "Testing nuclei -list flag..."
if timeout 10 nuclei -list "${TEST_DIR}/test_urls.txt" -silent -severity info -o "${TEST_DIR}/nuclei_test.txt" 2>&1 | grep -q "No such option: -l"; then
    fail_test "Nuclei -list Flag" "Using wrong flag (-l instead of -list)"
else
    pass_test "Nuclei -list Flag"
fi

# ==========================================
# TEST 5: Vulnerable Routes Analysis
# ==========================================
echo ""
echo "TEST SUITE 5: Vulnerable Routes Detection"
echo "=========================================="

# Create test URLs with known patterns
cat > "${TEST_DIR}/vulnerable_test_urls.txt" << EOF
https://api.example.com/v1/users/123/profile
https://example.com/download?file=report.pdf
https://example.com/search?q=test
https://example.com/proxy?url=http://external.com
https://blog.example.com/posts?id=456
EOF

# Run vulnerable routes analyzer
python3 utils/vulnerable_routes.py "${TEST_DIR}/vulnerable_test_urls.txt" "${TEST_DIR}/vuln_routes.json" 2>&1

if test_file_exists "${TEST_DIR}/vuln_routes.json" "Vulnerable Routes - JSON Output"; then
    # Check for IDOR detection
    if jq -e '.findings.IDOR | length > 0' "${TEST_DIR}/vuln_routes.json" > /dev/null 2>&1; then
        pass_test "IDOR Detection - Found numeric IDs"
    else
        fail_test "IDOR Detection" "Should detect /users/123 as IDOR"
    fi
    
    # Check for Path Traversal detection
    if jq -e '.findings."Path Traversal" | length > 0' "${TEST_DIR}/vuln_routes.json" > /dev/null 2>&1; then
        pass_test "Path Traversal Detection - Found file parameter"
    else
        fail_test "Path Traversal Detection" "Should detect ?file= parameter"
    fi
    
    # Check for SQLi detection
    if jq -e '.findings."SQL Injection" | length > 0' "${TEST_DIR}/vuln_routes.json" > /dev/null 2>&1; then
        pass_test "SQL Injection Detection - Found id parameter"
    else
        fail_test "SQL Injection Detection" "Should detect ?id= parameter"
    fi
    
    # Check for SSRF detection
    if jq -e '.findings.SSRF | length > 0' "${TEST_DIR}/vuln_routes.json" > /dev/null 2>&1; then
        pass_test "SSRF Detection - Found url parameter"
    else
        fail_test "SSRF Detection" "Should detect ?url= parameter"
    fi
fi

# ==========================================
# TEST 6: Secret Scanning
# ==========================================
echo ""
echo "TEST SUITE 6: Secret Scanning"
echo "=========================================="

# Create test HTML with secrets
cat > "${TEST_DIR}/test_page.html" << 'EOF'
<html>
<script>
const API_KEY = "sk-1234567890abcdef";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const email = "admin@example.com";
</script>
</html>
EOF

# Create test URL list for scraping
cat > "${TEST_DIR}/secret_test_urls.txt" << EOF
file://${TEST_DIR}/test_page.html
EOF

# Test regex scraper
python3 utils/regex_scraper.py "${TEST_DIR}/secret_test_urls.txt" --parse-html > "${TEST_DIR}/secrets_found.txt" 2>&1 || true

if [ -f "${TEST_DIR}/secrets_found.txt" ]; then
    if grep -q "API" "${TEST_DIR}/secrets_found.txt" || grep -q "admin@example.com" "${TEST_DIR}/secrets_found.txt"; then
        pass_test "Secret Detection - Found API keys/emails"
    else
        fail_test "Secret Detection" "Should detect API keys and emails in HTML"
    fi
fi

# ==========================================
# TEST 7: Context Builder
# ==========================================
echo ""
echo "TEST SUITE 7: Context Building"
echo "=========================================="

# Create minimal test structure
mkdir -p "${TEST_DIR}/context_test"/{subdomains,urls,httpx,nuclei}

# Create test data
echo "example.com" > "${TEST_DIR}/context_test/subdomains/vapt_example.com_subdomains_all.txt"
echo "https://example.com" > "${TEST_DIR}/context_test/urls/vapt_example.com_urls_all.txt"

# Create test httpx data with technologies
cat > "${TEST_DIR}/context_test/httpx/vapt_example.com_httpx_combined.json" << 'EOF'
{"url":"https://example.com","status_code":200,"tech":["WordPress","PHP","MySQL"]}
EOF

# Create technologies file
cat > "${TEST_DIR}/context_test/httpx/vapt_example.com_technologies.txt" << 'EOF'
WordPress
PHP
MySQL
EOF

# Run context builder
python3 utils/context_builder.py "example.com" "${TEST_DIR}/context_test" 2>&1

if test_file_exists "${TEST_DIR}/context_test/context/vapt_example.com_optimized_context.json" "Context Builder - Output File"; then
    # Check technologies count
    TECH_COUNT=$(jq -r '.summary.technologies.count' "${TEST_DIR}/context_test/context/vapt_example.com_optimized_context.json" 2>/dev/null || echo "0")
    if [ "$TECH_COUNT" -gt 0 ]; then
        pass_test "Context Builder - Technologies Extracted ($TECH_COUNT found)"
    else
        fail_test "Context Builder - Technologies" "Expected >0 technologies, got $TECH_COUNT"
    fi
    
    # Check structure
    if jq -e '.summary.subdomains' "${TEST_DIR}/context_test/context/vapt_example.com_optimized_context.json" > /dev/null 2>&1; then
        pass_test "Context Builder - JSON Structure Valid"
    else
        fail_test "Context Builder - JSON Structure" "Missing expected fields"
    fi
fi

# ==========================================
# TEST 8: Module Integration
# ==========================================
echo ""
echo "TEST SUITE 8: Module Integration Tests"
echo "=========================================="

# Test httpx_live_filter.sh logic
TEST_HTTPX_DIR="${TEST_DIR}/httpx_integration"
mkdir -p "${TEST_HTTPX_DIR}"

# Create test subdomain list
cat > "${TEST_HTTPX_DIR}/test_subs.txt" << EOF
example.com
www.example.com
EOF

# Simulate running httpx_live_filter
export OUTPUT_DIR="${TEST_HTTPX_DIR}"
export TARGET="example.com"

# Test if module creates required files
bash modules/httpx_live_filter.sh "example.com" "${TEST_HTTPX_DIR}" 2>&1 || true

# Check if live_hosts.txt was created (even if empty due to test data)
if [ -f "${TEST_HTTPX_DIR}/live_hosts.txt" ]; then
    pass_test "HTTPX Live Filter - Creates live_hosts.txt"
else
    fail_test "HTTPX Live Filter - File Creation" "live_hosts.txt not created"
fi

# ==========================================
# TEST 9: Report Generation
# ==========================================
echo ""
echo "TEST SUITE 9: Report Generation"
echo "=========================================="

# Test report generator with minimal context
TEST_REPORT_DIR="${TEST_DIR}/report_test"
mkdir -p "${TEST_REPORT_DIR}/context"

# Create minimal context
cat > "${TEST_REPORT_DIR}/context/vapt_test.com_optimized_context.json" << 'EOF'
{
  "target": "test.com",
  "summary": {
    "subdomains": {"count": 5},
    "urls": {"count": 100},
    "technologies": {"count": 3, "items": ["WordPress", "PHP", "MySQL"]},
    "vulnerabilities": {"critical": 1, "high": 2, "medium": 5, "low": 10, "info": 20}
  },
  "detailed_findings": []
}
EOF

# Run report generator
python3 utils/report_generator.py "test.com" "${TEST_REPORT_DIR}" 2>&1 || true

if [ -f "${TEST_REPORT_DIR}/final_report/vapt_test.com_report.html" ]; then
    pass_test "Report Generator - HTML Report Created"
    
    # Check if report contains key sections
    if grep -q "WordPress" "${TEST_REPORT_DIR}/final_report/vapt_test.com_report.html"; then
        pass_test "Report Generator - Contains Technology Data"
    else
        fail_test "Report Generator - Content" "Missing technology information"
    fi
else
    fail_test "Report Generator - Output" "HTML report not generated"
fi

# ==========================================
# TEST 10: End-to-End Workflow
# ==========================================
echo ""
echo "TEST SUITE 10: End-to-End Workflow Validation"
echo "=========================================="

# Test main.sh workflow logic (without actually running full scan)
if grep -q "execute_module" main.sh; then
    pass_test "Main Workflow - Uses execute_module function"
else
    fail_test "Main Workflow - Structure" "Missing execute_module calls"
fi

# Check workflow order
if grep -n "subdomain_enum\|httpx_live_filter\|nuclei_scan" main.sh | sort -t: -k1 -n | head -3 | grep -q "subdomain_enum.*httpx_live_filter.*nuclei_scan"; then
    pass_test "Main Workflow - Correct Module Order"
else
    echo -e "${YELLOW}⚠ WARNING${NC}: Module execution order may be suboptimal"
fi

# ==========================================
# SUMMARY
# ==========================================
echo ""
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo "Total Tests: $TESTS_TOTAL"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "Review the failures above and fix the issues."
    exit 1
fi

# Cleanup
rm -rf "${TEST_DIR}"

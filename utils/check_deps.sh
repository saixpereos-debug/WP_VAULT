#!/bin/bash

# Dependency Checker
# Verifies that all tools defined in config.sh are installed and actionable

failed=0

# Ensure logger is sourced if this script is run standalone
if [ -z "$BLUE" ]; then
    source utils/logger.sh 2>/dev/null || true
fi

print_banner "Pre-flight Check: Verifying Dependencies"

check_tool() {
    local name=$1
    local path=$2
    
    # If path is empty, it's missing from config
    if [ -z "$path" ]; then
        echo -e "   ${RED}✖${NC} ${name}: Variable not set in config"
        failed=1
        return
    fi


    # If it's a full path, check existance
    if [[ "$path" == /* ]] || [[ "$path" == ./* ]]; then
        if [ -x "$path" ]; then
            echo -e "   ${GREEN}✔${NC} ${name}: Found at $path"
        else
            # Try command -v in case it's in PATH despite being absolute (weird edge case)
            if command -v "$path" >/dev/null 2>&1; then
                 echo -e "   ${GREEN}✔${NC} ${name}: Found (executable)"
            else
                echo -e "   ${RED}✖${NC} ${name}: NOT found at $path"
                failed=1
            fi
        fi
    else
        # Just a command name
        if command -v "$path" >/dev/null 2>&1; then
             echo -e "   ${GREEN}✔${NC} ${name}: Found in PATH"
        else
             echo -e "   ${RED}✖${NC} ${name}: Not found in system PATH"
             failed=1
        fi
    fi
}

check_command() {
    local name=$1
    local cmd=$2
    
    if command -v "$cmd" >/dev/null 2>&1; then
        echo -e "   ${GREEN}✔${NC} ${name}: Installed"
    else
        echo -e "   ${RED}✖${NC} ${name}: Not installed (Command '$cmd' missing)"
        failed=1
    fi
}

# Check Configured Tools
check_tool "Subfinder" "$SUBFINDER_PATH"
check_tool "Amass" "$AMASS_PATH"
check_tool "Katana" "$KATANA_PATH"
check_tool "HTTPX" "$HTTPX_PATH"
check_tool "Nuclei" "$NUCLEI_PATH"
check_tool "WPScan" "$WPSCAN_PATH"
check_tool "Gowitness" "$GOWITNESS_PATH"
check_tool "Naabu" "$NAABU_PATH"
check_tool "Uncover" "$UNCOVER_PATH"
check_tool "WhatWeb" "$WHATWEB_PATH"

# Check New Tools (Added in install.sh, but might not be in config yet)
check_command "Feroxbuster" "feroxbuster"
check_command "Gospider" "gospider"

if [ $failed -eq 1 ]; then
    echo -e "\n${RED}[!] Missing Critical Dependencies${NC}"
    echo -e "    Some tools are missing or not configured correctly."
    echo -e "    Run ${BOLD}./install.sh${NC} to install them."
    echo -e "    Run ${BOLD}./setup.sh${NC} to update configuration paths."
    exit 1
fi

echo -e "   ${GREEN}All dependencies verified.${NC}\n"

#!/bin/bash

# Configuration Setup Script for Vṛthā Framework v2.0
# This script detects installed tools and updates config/config.sh

CONFIG_FILE="config/config.sh"
BACKUP_FILE="config/config.sh.bak"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Vṛthā Environment Setup...${NC}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: $CONFIG_FILE not found!${NC}"
    exit 1
fi

# Backup existing config
cp "$CONFIG_FILE" "$BACKUP_FILE"
echo -e "Created backup of config file at $BACKUP_FILE"

# Function to check and update tool path
update_tool_path() {
    local var_name=$1
    local tool_names=$2 # Space separated possibilities, e.g., "tool tool.py"
    local found_path=""

    echo -n "Checking for $var_name... "
    
    # Check system PATH
    for tool in $tool_names; do
        if command -v "$tool" >/dev/null 2>&1; then
            found_path=$(command -v "$tool")
            break
        fi
    done

    # If not found in PATH, check local tools directory
    if [ -z "$found_path" ]; then
        for tool in $tool_names; do
            if [ -f "tools/$tool" ]; then
                found_path="$(pwd)/tools/$tool"
                break
            fi
        done
    fi

    if [ -n "$found_path" ]; then
        echo -e "${GREEN}Found at $found_path${NC}"
        # Escape slashes for sed
        local escaped_path=$(echo "$found_path" | sed 's/\//\\\//g')
        # Update config file, handling potential quotes in the original file
        # Matches VAR_NAME="value" or VAR_NAME=value
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS sed requires empty extension for -i
            sed -i '' "s/^${var_name}=.*/${var_name}=\"${escaped_path}\"/" "$CONFIG_FILE"
        else
            sed -i "s/^${var_name}=.*/${var_name}=\"${escaped_path}\"/" "$CONFIG_FILE"
        fi
    else
        echo -e "${RED}Not found!${NC}"
        echo -e "${YELLOW}  Please install one of: [ $tool_names ]${NC}"
    fi
}

echo "------------------------------------------------"

# Detect tools
update_tool_path "SUBFINDER_PATH" "subfinder"
update_tool_path "AMASS_PATH" "amass"
update_tool_path "KATANA_PATH" "katana"

update_tool_path "HTTPX_PATH" "httpx"
update_tool_path "WAFW00F_PATH" "wafw00f wafw00f.py"
update_tool_path "GOWITNESS_PATH" "gowitness"
update_tool_path "WPSCAN_PATH" "wpscan"
update_tool_path "NUCLEI_PATH" "nuclei"

echo "------------------------------------------------"
echo -e "${YELLOW}Checking critical dependencies...${NC}"

# Check for jq
if command -v jq >/dev/null 2>&1; then
    echo -e "jq: ${GREEN}Installed${NC}"
else
    echo -e "jq: ${RED}Not installed (Required for JSON processing)${NC}"
fi

# Check for python3
if command -v python3 >/dev/null 2>&1; then
    echo -e "python3: ${GREEN}Installed${NC}"
else
    echo -e "python3: ${RED}Not installed (Required for scripts)${NC}"
fi

# Check for pip packages
echo -n "Checking Python libraries (requests)... "
if python3 -c "import requests" >/dev/null 2>&1; then
    echo -e "${GREEN}Installed${NC}"
else
    echo -e "${RED}Missing 'requests'${NC}"
fi

echo "------------------------------------------------"
echo -e "${GREEN}Setup complete! Configuration updated in $CONFIG_FILE${NC}"
echo -e "Review the warnings above if any tools were missing."

#!/bin/bash

# Vṛthā Installer Script
# Installs dependencies and tools for the Vṛthā - Advanced WordPress VAPT Framework
# 
# Description:
# This script automates the setup of the Vṛthā framework. It handles:
# 1. System updates and base dependency installation (git, python, ruby, etc.)
# 2. Golang environment setup
# 3. Installation of security tools:
#    - Subfinder, Amass, Katana (Recon)
#    - HTTPX, Naabu, Uncover (Analysis)
#    - Nuclei, WPScan, Feroxbuster, Gospider, Gowitness (Scanning)
#    - Wafw00f, WhatWeb (Fingerprinting)
# 4. Auto-configuration of tool paths.
#
# Usage: sudo ./install.sh

# Exit on error
set -e
set -o pipefail

# Error Handling
INSTALL_LOG="install_log.txt"
trap 'error_handler' ERR

error_handler() {
    echo -e "\n${RED}[!] Installation Failed!${NC}"
    echo -e "${RED}[!] Error occurred on line $BASH_LINENO${NC}"
    echo -e "${YELLOW}[!] Checking last 20 lines of install log ($INSTALL_LOG):${NC}\n"
    tail -n 20 "$INSTALL_LOG"
    echo -e "\n${RED}[!] Please fix the error and try again.${NC}"
    exit 1
}

# Redirect output to log file as well
# exec > >(tee -a "$INSTALL_LOG") 2>&1

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Clear log
echo "Vṛthā Installer Log - $(date)" > "$INSTALL_LOG"

# Display Banner using Python script if available
if [ -f "utils/banner.py" ]; then
    python3 utils/banner.py
else
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${BLUE}        Vṛthā - Easy Installer                ${NC}"
    echo -e "${BLUE}=================================================${NC}"
fi

echo -e "${YELLOW}Logs are being saved to ${INSTALL_LOG}${NC}"

# Check for root permissions (required for apt/yum)
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}[!] This script performs system updates. It is recommended to run as root or with sudo.${NC}"
  # We won't exit, but commands might fail if not sudo
fi

log_msg() {
    echo -e "$1"
    echo -e "$1" >> "$INSTALL_LOG"
}

# 1. System Updates & Base Dependencies
log_msg "\n${YELLOW}[+] Updating system package lists...${NC}"
if command -v apt-get >/dev/null; then
    sudo apt-get update >> "$INSTALL_LOG" 2>&1
    
    log_msg "${YELLOW}[+] Installing basic tools (git, curl, wget, jq, python3)...${NC}"
    sudo apt-get install -y git curl wget jq python3 python3-pip python3-venv >> "$INSTALL_LOG" 2>&1
    
    log_msg "${YELLOW}[+] Installing build dependencies (ruby, gcc, libs)...${NC}"
    # We remove -qq to ensure errors are verbose in the log
    sudo apt-get install -y ruby-full build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev >> "$INSTALL_LOG" 2>&1
    
elif command -v yum >/dev/null; then
    sudo yum update -y -q >> "$INSTALL_LOG" 2>&1
    sudo yum install -y -q git curl wget jq ruby ruby-devel gcc python3 python3-pip >> "$INSTALL_LOG" 2>&1
elif command -v pacman >/dev/null; then
    sudo pacman -Syu --noconfirm git curl wget jq ruby gcc python python-pip >> "$INSTALL_LOG" 2>&1
else
    log_msg "${RED}[!] Unsupported package manager. Please install git, curl, wget, jq, ruby, python3 manually.${NC}"
fi

# 2. Check & Install Go (Golang)
log_msg "\n${YELLOW}[+] Checking for Go environment...${NC}"
if ! command -v go >/dev/null; then
    log_msg "${RED}[!] Go is not installed.${NC}"
    log_msg "${YELLOW}[+] Attempting to install Go...${NC}"
    
    # Download and install specific version of Go (linux-amd64)
    GO_VER="1.21.0"
    wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" >> "$INSTALL_LOG" 2>&1
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "go${GO_VER}.linux-amd64.tar.gz" >> "$INSTALL_LOG" 2>&1
    rm "go${GO_VER}.linux-amd64.tar.gz"
    
    # Add to path temporarily for this session
    export PATH=$PATH:/usr/local/go/bin
    log_msg "${GREEN}[+] Go installed. Please add 'export PATH=\$PATH:/usr/local/go/bin' to your ~/.bashrc or ~/.zshrc${NC}"
else
    log_msg "${GREEN}[+] Go is already installed: $(go version)${NC}"
fi

# Ensure GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
export PATH=$PATH:$HOME/go/bin

# 3. Install Security Tools (Go)
log_msg "\n${YELLOW}[+] Installing Security Tools via Go...${NC}"

install_go_tool() {
    local tool_name=$1
    local repo=$2
    if ! command -v "$tool_name" >/dev/null; then
        log_msg "${BLUE}  -> Installing $tool_name...${NC}"
        go install -v "$repo@latest" >> "$INSTALL_LOG" 2>&1
        if [ $? -eq 0 ]; then
             log_msg "${GREEN}    Successfully installed $tool_name${NC}"
        else
             log_msg "${RED}    Failed to install $tool_name${NC}"
             # We don't exit here, might refer to manual install
             return 1
        fi
    else
        log_msg "${GREEN}  -> $tool_name is already installed${NC}"
    fi
}

install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "amass" "github.com/OWASP/Amass/v3/..."
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
install_go_tool "gowitness" "github.com/sensepost/gowitness"
install_go_tool "gospider" "github.com/jaeles-project/gospider"
install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install_go_tool "uncover" "github.com/projectdiscovery/uncover/cmd/uncover"

# Install Feroxbuster (Rust tool, installing binary)
log_msg "\n${YELLOW}[+] Installing Feroxbuster...${NC}"
if ! command -v feroxbuster >/dev/null; then
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash >> "$INSTALL_LOG" 2>&1
    sudo mv feroxbuster /usr/local/bin/ >> "$INSTALL_LOG" 2>&1
else
    log_msg "${GREEN}  -> feroxbuster is already installed${NC}"
fi

# 4. Install WAFW00F (Python)
log_msg "\n${YELLOW}[+] Installing Python Tools...${NC}"
if ! command -v wafw00f >/dev/null; then
    log_msg "${BLUE}  -> Installing wafw00f...${NC}"
    pip3 install wafw00f --break-system-packages >> "$INSTALL_LOG" 2>&1 || pip3 install wafw00f >> "$INSTALL_LOG" 2>&1
else
    log_msg "${GREEN}  -> wafw00f is already installed${NC}"
fi

# Install Python dependencies for the script
log_msg "${BLUE}  -> Installing script dependencies (requests, markdown)...${NC}"
pip3 install requests markdown --break-system-packages >> "$INSTALL_LOG" 2>&1 || pip3 install requests markdown >> "$INSTALL_LOG" 2>&1

# 5. Install WPScan (Ruby)
log_msg "\n${YELLOW}[+] Installing Ruby Tools...${NC}"
if ! command -v wpscan >/dev/null; then
    log_msg "${BLUE}  -> Installing wpscan...${NC}"
    sudo gem install wpscan >> "$INSTALL_LOG" 2>&1
else
    log_msg "${GREEN}  -> wpscan is already installed${NC}"
fi

# 6. Install WhatWeb (Ruby)
log_msg "\n${YELLOW}[+] Installing WhatWeb...${NC}"
if ! command -v whatweb >/dev/null; then
    log_msg "${BLUE}  -> Installing WhatWeb...${NC}"
    sudo gem install whatweb >> "$INSTALL_LOG" 2>&1
else
    log_msg "${GREEN}  -> WhatWeb is already installed${NC}"
fi

# 7. Run Configuration
log_msg "\n${YELLOW}[+] Running Auto-Configuration (setup.sh)...${NC}"
chmod +x setup.sh
./setup.sh >> "$INSTALL_LOG" 2>&1

log_msg "\n${GREEN}=================================================${NC}"
log_msg "${GREEN}      Installation & Setup Complete!             ${NC}"
log_msg "${GREEN}=================================================${NC}"
log_msg "You can now run the tool using:"
log_msg "${BLUE}  ./main.sh target.com${NC}"

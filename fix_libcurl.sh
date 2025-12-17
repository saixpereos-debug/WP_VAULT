#!/bin/bash

# Fix Libcurl Version Conflict (Debian 12 Bookworm)
# Implements the "SAFE FIX" to resolve Backports vs Stable conflicts.
# Goal: Downgrade libcurl to stable to allow dev headers to install.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Checking for Libcurl Version Conflict...${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./fix_libcurl.sh)${NC}"
  exit 1
fi

# 1. Identify Stable Version
# We assume the user is on Debian 12. 
# We look for the version available in the main/stable repo (typically priority 500 or 990)
# This is a heuristic: finding the version string that starts with 7.88.1 (standard for Bookworm)
TARGET_VER=$(apt-cache policy libcurl4 | grep "7.88.1-" | awk '{print $1}' | head -n 1)

if [ -z "$TARGET_VER" ]; then
    echo -e "${RED}[!] Could not detect a stable '7.88.1-*' version for libcurl4.${NC}"
    echo "    This script is designed for Debian 12 Bookworm."
    exit 1
fi

CURRENT_VER=$(dpkg-query -W -f='${Version}' libcurl4 2>/dev/null)

echo -e "    Current Version: ${RED}$CURRENT_VER${NC}"
echo -e "    Target Stable:   ${GREEN}$TARGET_VER${NC}"

if [ "$CURRENT_VER" == "$TARGET_VER" ]; then
    echo -e "${GREEN}[✔] System is already on the stable version. No downgrade needed.${NC}"
    echo -e "    Attempting to install headers..."
    apt-get install -y libcurl4-openssl-dev
    exit 0
fi

# 2. Downgrade Packages
echo -e "\n${YELLOW}[!] Backports detected. Downgrading to stable...${NC}"
echo "    Packages: libcurl4, curl, libcurl3-gnutls -> $TARGET_VER"

apt-get install -y --allow-downgrades \
    libcurl4="$TARGET_VER" \
    curl="$TARGET_VER" \
    libcurl3-gnutls="$TARGET_VER"

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Downgrade failed. Please check apt logs.${NC}"
    exit 1
fi

# 3. Hold Packages
echo -e "\n${BLUE}[*] Holding packages to prevent auto-upgrade...${NC}"
apt-mark hold libcurl4 curl libcurl3-gnutls

# 4. Fix Broken Installs
echo -e "\n${BLUE}[*] Fixing any broken dependencies...${NC}"
apt-get install --fix-broken -y

# 5. Install Dev Headers
echo -e "\n${GREEN}[*] Installing libcurl4-openssl-dev...${NC}"
apt-get install -y libcurl4-openssl-dev

echo -e "\n${GREEN}[✔] Dependency conflict resolved.${NC}"
echo "    You can now proceed with ./install.sh"

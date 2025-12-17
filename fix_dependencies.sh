#!/bin/bash

# Fix Broken Dependencies Script
# Helps resolve "held broken packages" errors in apt

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Attempting to fix broken packages...${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./fix_dependencies.sh)${NC}"
  exit 1
fi

# 1. Update lists
echo -e "\n${BLUE}[1/5] Updating package lists...${NC}"
apt-get update

# 2. Fix broken installs
echo -e "\n${BLUE}[2/5] Running --fix-broken install...${NC}"
apt-get install --fix-broken -y

# 3. Configure pending packages
echo -e "\n${BLUE}[3/5] Configuring pending packages...${NC}"
dpkg --configure -a

# 4. Clean cache
echo -e "\n${BLUE}[4/5] Cleaning apt cache...${NC}"
apt-get autoclean
apt-get clean

# 5. Safe upgrade (optional, keeps back packages if needed but fixes dependency tree)
echo -e "\n${BLUE}[5/5] Attempting safe upgrade...${NC}"
apt-get upgrade -y

echo -e "\n${GREEN}[✔] Repairs attempted. Please try running ./install.sh again.${NC}"

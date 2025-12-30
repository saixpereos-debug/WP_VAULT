#!/usr/bin/env python3
import sys

# Professional Vṛthā Banner
# Vṛthā - WordPress VAPT Automation Framework

RED = '\033[0;31m'
GREEN = '\033[0;32m'
BLUE = '\033[0;34m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
BOLD = '\033[1m'
NC = '\033[0m' # No Color

BANNER = f"""{BLUE}{BOLD}
██╗   ██╗██████╗ ████████╗██╗  ██╗ █████╗ 
██║   ██║██╔══██╗╚══██╔══╝██║  ██║██╔══██╗
██║   ██║██████╔╝   ██║   ███████║███████║
╚██╗ ██╔╝██╔══██╗   ██║   ██╔══██║██╔══██║
 ╚████╔╝ ██║  ██║   ██║   ██║  ██║██║  ██║
  ╚═══╝  ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ {NC}{CYAN}
   Advanced Vṛthā VAPT Framework v2.0
{NC}{YELLOW}   "Offensive Excellence for Defensive Strength"
{NC}------------------------------------------------"""

def print_banner():
    print(BANNER)

if __name__ == "__main__":
    print_banner()

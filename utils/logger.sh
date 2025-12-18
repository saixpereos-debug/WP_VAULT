#!/bin/bash

# UI Logger Utility for Vṛthā Framework
# Provides clean, tool-agnostic output with spinners and status updates

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Save cursor position
save_cursor() {
    echo -ne "\033[s"
}

# Restore cursor position
restore_cursor() {
    echo -ne "\033[u"
}

# Clear line
clear_line() {
    echo -ne "\033[K"
}

# Info message (Blue)
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Success message (Green)
log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Warning message (Yellow)
log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Error message (Red)
log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Finding message (Cyan with indentation)
log_finding() {
    local count=$1
    local type=$2
    
    # Handle 'null' or non-numeric values
    if [[ "$count" == "null" ]] || [[ -z "$count" ]] || [[ ! "$count" =~ ^[0-9]+$ ]]; then
        count=0
    fi

    if [ "$count" -gt 0 ]; then
        echo -e "   ${CYAN}└── Found ${BOLD}${count}${NC}${CYAN} ${type}${NC}"
    else
        echo -e "   ${YELLOW}└── No ${type} found${NC}"
    fi
}

# Section header
print_banner() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"
}

# Running animation function
# Usage: run_with_spinner "Task description" command arg1 arg2 ...
run_with_spinner() {
    local task_name="$1"
    shift
    local cmd="$@"
    
    # Hide cursor
    tput civis
    
    # Start the command in background, redirecting stdout/stderr to log file
    # We rely on LOG_FILE being exported
    eval "$cmd" >> "${LOG_FILE}" 2>&1 &
    local pid=$!
    
    local delay=0.1
    local spinstr='|/-\'
    
    echo -ne "   ${YELLOW}⟳${NC} ${task_name}..."
    
    while ps -p $pid > /dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    
    # Check exit status
    wait $pid
    local exit_status=$?
    
    # Clear spinner chars
    printf "      \b\b\b\b\b\b"
    
    if [ $exit_status -eq 0 ]; then
        echo -e "\r   ${GREEN}✔${NC} ${task_name} ${GREEN}Completed${NC}    "
    else
        echo -e "\r   ${RED}✖${NC} ${task_name} ${RED}Failed${NC}       "
    fi
    
    # Show cursor
    tput cnorm
    
    return $exit_status
}

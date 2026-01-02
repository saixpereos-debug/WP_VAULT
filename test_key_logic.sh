#!/bin/bash
RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'
BLUE=$'\e[0;34m'
NC=$'\e[0m'

source config/config.sh
SEC_AI_PATH="sec_ai/main.py"
echo "Loaded Key: ${OPENROUTER_API_KEY:0:10}..."

echo "Running Python Check..."
python3 "$SEC_AI_PATH" check > /dev/null 2>&1
EXIT_CODE=$?
echo "Python Exit Code: $EXIT_CODE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "Logic: Success (AI Enabled)"
else
    echo "Logic: Failure (Enter Error Block)"
    # Replicating the exact block I wrote
    echo -e "${RED}[!] API Connectivity Check Failed: 401 Unauthorized / Invalid Key.${NC}"
    echo -e "    The key stored in config/config.sh appears to be invalid or expired."
    # We won't prompt in this test, just show we reached here
    echo "[DEBUG] Script would prompt user here."
fi

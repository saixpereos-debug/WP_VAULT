#!/bin/bash

# Sensitive routes detection module using OpenRouter API

TARGET=$1
OUTPUT_DIR=$2
URLS_FILE="${RESULTS_DIR}/urls/vapt_${TARGET}_urls_all.txt"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

OUTPUT_FILE="${OUTPUT_DIR}/vapt_${TARGET}_sensitive_routes.txt"

echo "Detecting sensitive routes for ${TARGET} using OpenRouter..." | tee -a "${LOG_FILE}"

# Prepare the prompt for OpenRouter
PROMPT_FILE="config/openrouter-prompts.txt"
PROMPT=$(grep -A 10 "SENSITIVE_ROUTES_PROMPT" "${PROMPT_FILE}" | tail -n +2)

# Read URLs and prepare the request
URLS=$(cat "${URLS_FILE}" | head -n 100)  # Limit to first 100 URLs to avoid token limits

# Create JSON payload for OpenRouter API
PAYLOAD=$(cat <<EOF
{
  "model": "${OPENROUTER_MODEL}",
  "messages": [
    {
      "role": "system",
      "content": "${PROMPT}"
    },
    {
      "role": "user",
      "content": "Analyze these URLs for sensitive endpoints:\n\n${URLS}"
    }
  ]
}
EOF
)

# Send request to OpenRouter API
echo "Sending request to OpenRouter API..." | tee -a "${LOG_FILE}"
RESPONSE=$(curl -s -X POST "https://openrouter.ai/api/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -d "${PAYLOAD}")

# Extract and save the response
echo "${RESPONSE}" | jq -r '.choices[0].message.content' > "${OUTPUT_FILE}"

echo "Sensitive routes detection completed"

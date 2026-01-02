#!/usr/bin/env python3
import os
import sys
import json
import argparse
import requests
import re

def select_targets(urls, mode, api_key, model):
    """
    Asks the AI to identify interesting URLs from a list for specific security testing phases.
    """
    if not api_key:
        return urls[:20]  # Fallback to heuristic

    prompt = f"""
You are a Red Team Expert specializing in WordPress VAPT. 
I have a list of {len(urls)} discovered URLs from a target.
Identify the top 15 most "interesting" URLs for the following mode: {mode.upper()}

Modes:
- SCREENSHOTS: Focus on login pages, admin panels, dashboards, unique directories, and sensitive file disclosures.
- FUZZING: Focus on URLs with parameters (?id=, ?p=), search forms, login portals, and REST API endpoints.

Return ONLY a flat list of the selected URLs, one per line. No commentary.

URLs:
{chr(10).join(urls[:200])} 
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/vapt-automation/vrtha",
        "X-Title": "Vrtha V2.3 Target Selector"
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a specialized security target selector. Output ONLY URLs."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3
    }

    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=30)
        if response.status_code == 200:
            content = response.json()['choices'][0]['message']['content']
            # Robust URL extraction: find all strings starting with http/https
            selected = re.findall(r'https?://[^\s\'"\]\)]+', content)
            
            # De-duplicate while preserving order
            unique_selected = []
            seen = set()
            for url in selected:
                clean_url = url.strip()
                if clean_url and clean_url not in seen:
                    unique_selected.append(clean_url)
                    seen.add(clean_url)
            
            return unique_selected if unique_selected else urls[:15]
        else:
            return urls[:15]
    except Exception:
        return urls[:15]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Driven Target Selector")
    parser.add_argument("--input", required=True, help="Input file with URLs")
    parser.add_argument("--mode", required=True, choices=["screenshots", "fuzzing"], help="Selection mode")
    parser.add_argument("--output", required=True, help="Output file for selected URLs")
    
    args = parser.parse_args()
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    model = os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-exp:free")

    if not os.path.exists(args.input):
        sys.exit(0)

    with open(args.input, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        sys.exit(0)

    selected_urls = select_targets(urls, args.mode, api_key, model)

    # Ensure output directory exists
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(args.output, 'w') as f:
        for url in selected_urls:
            f.write(f"{url}\n")

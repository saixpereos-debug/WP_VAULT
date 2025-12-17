
import json
import os
import glob
import re

def parse_nuclei_results(results_dir):
    """Parses Nuclei JSON output."""
    findings = []
    nuclei_file = os.path.join(results_dir, "nuclei", "*_nuclei.json")
    files = glob.glob(nuclei_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                # Nuclei often outputs one JSON object per line
                for line in f:
                    try:
                        data = json.loads(line)
                        findings.append({
                            "tool": "nuclei",
                            "name": data.get("info", {}).get("name", "Unknown"),
                            "severity": data.get("info", {}).get("severity", "info"),
                            "description": data.get("info", {}).get("description", ""),
                            "matched_at": data.get("matched-at", ""),
                            "curl_command": data.get("curl-command", "")
                        })
                    except: pass
        except Exception as e:
            print(f"Error reading nuclei file {fpath}: {e}")
    return findings

def parse_httpx_results(results_dir):
    """Parses HTTPX/Tech Detection results."""
    tech_stack = {}
    httpx_file = os.path.join(results_dir, "httpx", "*_httpx_tech.json")
    files = glob.glob(httpx_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        url = data.get("url")
                        tech = data.get("tech", [])
                        if url and tech:
                            tech_stack[url] = tech
                    except: pass
        except: pass
    return tech_stack

def parse_secrets_results(results_dir):
    """Parses Secrets scan results."""
    secrets = []
    secrets_file = os.path.join(results_dir, "secrets", "*_trufflehog.json")
    files = glob.glob(secrets_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                data = json.load(f)
                # Helper to recursive search? Or just simple parse if structure is known
                # Trufflehog V3 structure varies, assuming simple list or specific format
                # For now, let's just grab basic info if possible or raw count
                secrets.append(str(data)[:1000]) # Truncate for now
        except: pass
    return secrets

def get_scan_context(results_dir):
    """Aggregates all results into a text context."""
    nuclei_data = parse_nuclei_results(results_dir)
    tech_data = parse_httpx_results(results_dir)
    secrets_data = parse_secrets_results(results_dir)
    
    context = f"## Technology Stack\n"
    for url, tech in tech_data.items():
        context += f"- {url}: {', '.join(tech)}\n"
        
    context += f"\n## Vulnerabilities (Nuclei)\n"
    if not nuclei_data:
        context += "No vulnerabilities found by Nuclei.\n"
    for v in nuclei_data:
        context += f"- [{v['severity'].upper()}] {v['name']} at {v['matched_at']}\n"
        
    context += f"\n## Potential Secrets\n"
    if not secrets_data:
         context += "No secrets detected.\n"
    else:
        context += f"Found {len(secrets_data)} potential secret groups.\n"

    return context

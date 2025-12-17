#!/usr/bin/env python3

import sys
import os
import json
import requests

def analyze_architecture(target, results_dir, api_key):
    """
    Analyzes the gathered data to answer 'Big Questions' about the application architecture.
    """
    
    context_dir = os.path.join(results_dir, "context")
    os.makedirs(context_dir, exist_ok=True)
    
    # 1. Gather Context
    # Tech Stack
    tech_data = ""
    tech_file = os.path.join(results_dir, "httpx", f"vapt_{target}_httpx_tech.json")
    if os.path.exists(tech_file):
        try:
            with open(tech_file, 'r') as f:
                # Read first few lines of tech
                lines = f.readlines()[:20] 
                tech_data = "".join(lines)
        except: pass

    # JS Files (from Gospider)
    js_files = []
    js_file_path = os.path.join(results_dir, "spidering", f"vapt_{target}_js_files.txt")
    if os.path.exists(js_file_path):
        try:
            with open(js_file_path, 'r') as f:
                js_files = [x.strip() for x in f.readlines()][:30] # Limit to 30
        except: pass
        
    # Discovered Endpoints (Feroxbuster)
    endpoints = []
    ferox_file = os.path.join(results_dir, "content", f"vapt_{target}_feroxbuster.txt")
    if os.path.exists(ferox_file):
        try:
            with open(ferox_file, 'r') as f:
                endpoints = [x.strip() for x in f.readlines()][:50]
        except: pass

    # 2. Construct Prompt
    prompt = f"""
    You are a Senior Application Security Architect. Analyze the following reconnaissance data for the target: {target}
    
    Recon Data:
    - Tech Stack Snippets: {tech_data}
    - Identified JS Files: {', '.join(js_files)}
    - Sample Endpoints: {', '.join(endpoints)}
    
    Please answer the following "Big Questions" to help build a threat model:
    
    1. **Data Passing Analysis**: Based on the tech stack and endpoints (e.g., .php, .jsp, API routes), how does the app likely pass data? (UIDs, Emails, UUIDs, Cookies, Authorization Headers?)
    2. **User & Tenant Model**: 
       - Does the site likely have multi-tenancy?
       - What user levels appear to exist? (Admin, Tenant Admin, User, Unauthenticated Viewer?)
    3. **Threat Model Identification**:
       - Does this site have a unique threat model?
       - How might it handle XSS or Code Injection based on the tech (e.g., React vs PHP)?
       - How is CSRF likely handled?
    
    Provide a concise, markdown-formatted architectural assessment.
    """
    
    # 3. Call OpenRouter
    if not api_key or "your_" in api_key:
        print("Skipping AI analysis: API Key missing.")
        return

    print("Sending architectural context to OpenRouter...")
    content = None
    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/vrtha", 
            },
            json={
                "model": "openai/gpt-4o", # Using GPT-4o typically available
                "messages": [
                    {"role": "system", "content": "You are a senior Application Security Architect specializing in WordPress."},
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=60
        )
        
            
    except Exception as e:
        print(f"Error during AI analysis: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 analyze_architecture.py <target> <results_dir> <api_key>")
        sys.exit(1)
        
    target = sys.argv[1]
    results_dir = sys.argv[2]
    api_key = sys.argv[3] if len(sys.argv) > 3 else ""
    
    analyze_architecture(target, results_dir, api_key)

#!/usr/bin/env python3

import os
import sys
import json
import requests
from datetime import datetime

def generate_report(target, results_dir, api_key):
    """Generate a comprehensive VAPT report using OpenRouter API"""
    
    # Create final report directory
    final_report_dir = os.path.join(results_dir, "final_report")
    os.makedirs(final_report_dir, exist_ok=True)
    
    # Initialize report data
    report_data = {
        "target": target,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings": {}
    }
    
    # Read all scan results
    scan_results = {}
    for root, dirs, files in os.walk(results_dir):
        for file in files:
            if file.startswith(f"vapt_{target}_") and file.endswith(".txt"):
                scan_name = file.split(f"vapt_{target}_")[1].split(".txt")[0]
                file_path = os.path.join(root, file)
                
                with open(file_path, 'r') as f:
                    scan_results[scan_name] = f.read()
    
    # Prepare prompt for OpenRouter
    with open("config/openrouter-prompts.txt", 'r') as f:
        prompts = f.read()
    
    report_prompt = prompts.split("REPORT_GENERATION_PROMPT")[1].strip() if "REPORT_GENERATION_PROMPT" in prompts else """
    Analyze the following WordPress VAPT scan results and generate a comprehensive security report.
    The report should include:
    1. Executive Summary
    2. Critical Findings
    3. Detailed Vulnerability Analysis
    4. Risk Assessment
    5. Remediation Recommendations
    
    Format the report in Markdown with clear sections and subsections.
    """
    
    # Combine all scan results
    combined_results = ""
    for scan_name, result in scan_results.items():
        combined_results += f"\n\n=== {scan_name.upper()} ===\n{result}"
    
    # Create JSON payload for OpenRouter API
    payload = {
        "model": "gpt-4",  # or your preferred model
        "messages": [
            {
                "role": "system",
                "content": report_prompt
            },
            {
                "role": "user",
                "content": f"Target: {target}\n\nScan Results:\n{combined_results}"
            }
        ]
    }
    
    # Send request to OpenRouter API
    print("Sending scan results to OpenRouter for analysis...")
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        json=payload
    )
    
    if response.status_code == 200:
        # Extract and save the report
        report_content = response.json()["choices"][0]["message"]["content"]
        
        # Save as Markdown
        with open(os.path.join(final_report_dir, f"vapt_{target}_report.md"), 'w') as f:
            f.write(report_content)
        
        # Convert to HTML
        html_report = markdown_to_html(report_content)
        with open(os.path.join(final_report_dir, f"vapt_{target}_report.html"), 'w') as f:
            f.write(html_report)
        
        print(f"Report generated successfully and saved in {final_report_dir}")
    else:
        print(f"Error generating report: {response.status_code} - {response.text}")
        
        # Save raw scan results as a fallback
        with open(os.path.join(final_report_dir, f"vapt_{target}_raw_results.txt"), 'w') as f:
            f.write(combined_results)
        
        print("Raw scan results saved as a fallback.")

def markdown_to_html(markdown_text):
    """Convert Markdown to HTML with basic styling"""
    html = markdown_text
    
    # Basic Markdown to HTML conversion
    html = html.replace('# ', '<h1>')
    html = html.replace('## ', '<h2>')
    html = html.replace('### ', '<h3>')
    html = html.replace('#### ', '<h4>')
    html = html.replace('\n\n', '</p><p>')
    html = '<p>' + html + '</p>'
    
    # Add CSS styling
    styled_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VAPT Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            h2 {{ color: #3498db; }}
            h3 {{ color: #2980b9; }}
            .critical {{ color: #e74c3c; font-weight: bold; }}
            .high {{ color: #e67e22; font-weight: bold; }}
            .medium {{ color: #f39c12; font-weight: bold; }}
            .low {{ color: #27ae60; font-weight: bold; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        {html}
    </body>
    </html>
    """
    
    return styled_html

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 generate_report.py <target> <results_dir> <api_key>")
        sys.exit(1)
    
    target = sys.argv[1]
    results_dir = sys.argv[2]
    api_key = sys.argv[3]
    
    generate_report(target, results_dir, api_key)

#!/usr/bin/env python3
import json
import sys
import os

def audit_headers(httpx_json_file):
    """Audits security headers from httpx JSON output."""
    if not os.path.exists(httpx_json_file):
        return {"error": f"File not found: {httpx_json_file}"}

    findings = []
    try:
        with open(httpx_json_file, 'r') as f:
            data = json.load(f)
            
        for entry in data:
            url = entry.get("url", "unknown")
            headers = entry.get("header", {})
            
            # Map of header to recommended state
            security_headers = {
                "Content-Security-Policy": "Missing Content-Security-Policy (CSP) header. (High Risk of XSS)",
                "X-Frame-Options": "Missing X-Frame-Options header. (Risk of Clickjacking)",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header. (Risk of MIME sniffing)",
                "Strict-Transport-Security": "Missing HSTS header. (Risk of SSL stripping)",
                "Referrer-Policy": "Missing Referrer-Policy header.",
                "Permissions-Policy": "Missing Permissions-Policy header."
            }
            
            # Normalize header keys to lowercase for matching
            lower_headers = {k.lower(): v for k, v in headers.items()}
            
            site_findings = []
            for header, message in security_headers.items():
                if header.lower() not in lower_headers:
                    site_findings.append({
                        "header": header,
                        "status": "Missing",
                        "impact": message
                    })
                else:
                    val = lower_headers[header.lower()]
                    # Basic strength checks
                    if header == "X-Frame-Options" and "deny" not in val.lower() and "sameorigin" not in val.lower():
                        site_findings.append({
                            "header": header,
                            "status": "Weak",
                            "value": val,
                            "impact": "X-Frame-Options is present but weak."
                        })
            
            if site_findings:
                findings.append({
                    "url": url,
                    "issues": site_findings
                })
                
    except Exception as e:
        return {"error": f"Error parsing JSON: {str(e)}"}
        
    return findings

def main():
    if len(sys.argv) < 3:
        print("Usage: header_auditor.py <httpx_json> <output_json>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    results = audit_headers(input_file)
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Header audit complete. Results saved to {output_file}")

if __name__ == "__main__":
    main()

import re
import sys
import requests
import argparse
from concurrent.futures import ThreadPoolExecutor

# Regex Patterns
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@(?!example\.com)(?!.*\.(png|jpg|jpeg|gif|css|js)$)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
# Basic key patterns (can be expanded)
KEY_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Generic API Key": r"(?i)(?:api_key|apikey|secret_key|access_token)[\s=:\"']{1,5}([a-zA-Z0-9\-_]{20,})",
    "Private Key Block": r"-----BEGIN PRIVATE KEY-----"
}

def fetch_and_scan(url, timeout=5):
    findings = []
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        content = response.text
        
        # Scan for Emails
        emails = set(re.findall(EMAIL_REGEX, content))
        if emails:
            for email in emails:
                findings.append(f"[EMAIL] {email} found at {url}")
                
        # Scan for Keys
        for key_name, pattern in KEY_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                # Basic false positive filter for generic key (too short or just 'variable_name')
                if len(match) > 8:
                     findings.append(f"[SECRET] {key_name}: {match[:10]}... found at {url}")

    except Exception as e:
        pass # frequent errors expected in bulk scanning
        
    return findings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url_file", help="File containing URLs to scan")
    parser.add_argument("--threads", type=int, default=10)
    args = parser.parse_args()
    
    urls = []
    with open(args.url_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip().startswith("http")]
        
    print(f"[-] Scanning {len(urls)} URLs for secrets and emails with {args.threads} threads...")
    
    all_findings = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(fetch_and_scan, url): url for url in urls}
        for future in future_to_url:
            result = future.result()
            if result:
                for item in result:
                    print(item) # Print to stdout for capture
                    all_findings.append(item)
                    
    if not all_findings:
        print("[-] No obvious secrets or emails found in crawled content.")

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()

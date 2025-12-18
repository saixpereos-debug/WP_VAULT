#!/usr/bin/env python3
import re
import sys
import requests
import argparse
import json
from concurrent.futures import ThreadPoolExecutor

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

import xml.etree.ElementTree as ET

# Enhanced Regex Patterns
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@(?!example\.com)(?!.*\.(png|jpg|jpeg|gif|css|js)$)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

# Comprehensive secret patterns
KEY_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "GitHub Token": r"gh[pousr]_[0-9a-zA-Z]{36}",
    "Generic API Key": r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)[\s=:\"\'\`]{1,5}([a-zA-Z0-9\-_]{20,})",
    "Private Key Block": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Slack Token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Firebase URL": r"[a-z0-9-]+\.firebaseio\.com",
    "Database URL": r"(?i)(mysql|postgres|mongodb|redis)://[^\s\"'<>]+",
    "S3 Bucket": r"[a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com",
    "Twilio Account SID": r"AC[a-f0-9]{32}",
    "Twilio Auth Token": r"(?i)twilio.*['\"][a-f0-9]{32}['\"]",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": r"key-[0-9a-f]{32}",
    "Heroku API Key": r"(?i)heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "PayPal Braintree Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Internal IP": r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}",
    "Potential Endpoint": r"(['\"])/(?:api|v1|v2|v3|admin|config|debug|setup|upload|download)/[a-zA-Z0-9\-_/.]{3,50}(?:['\"])",
    "WP Config leak": r"define\(['\"]DB_(?:NAME|USER|PASSWORD|HOST)['\"]",
    "WordPress Salt/Key": r"define\(['\"](?:AUTH|SECURE_AUTH|LOGGED_IN|NONCE)_(?:KEY|SALT)['\"]",
    "WordPress Author Name": r"(?i)author_name[\"']?\s*:\s*[\"']([^\"']+)[\"']",
    "WordPress REST User": r"/wp-json/wp/v2/users/\d+",
    "Session Cookie": r"(?i)(?:PHP|WP|JSESS|SESSION)ID=[a-zA-Z0-9\-_]{16,}",
    "DOM XSS Sink: innerHTML": r"\.innerHTML\s*=",
    "DOM XSS Sink: document.write": r"document\.write\s*\(",
    "DOM XSS Sink: eval": r"eval\s*\(",
    "DOM XSS Sink: insertAdjacentHTML": r"\.insertAdjacentHTML\s*\(",
    "DOM XSS Sink: outerHTML": r"\.outerHTML\s*=",
    "WordPress REST API": r"/wp-json/wp/v2/[a-zA-Z0-9\-_]+",
}

def parse_html(content):
    """Parse HTML and extract secrets from scripts, comments, and data attributes"""
    findings = []
    if not BS4_AVAILABLE:
        return findings
    
    try:
        soup = BeautifulSoup(content, 'html.parser')
        
        # Extract from script tags
        for script in soup.find_all('script'):
            script_content = script.string or ""
            findings.extend(scan_text(script_content, "HTML Script"))
        
        # Extract from HTML comments
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in str(text)):
            findings.extend(scan_text(str(comment), "HTML Comment"))
        
        # Extract from data attributes
        for tag in soup.find_all(attrs=lambda x: x and any(k.startswith('data-') for k in x.keys())):
            for attr, value in tag.attrs.items():
                if attr.startswith('data-'):
                    findings.extend(scan_text(str(value), f"HTML Data Attribute ({attr})"))
    except Exception as e:
        pass
    
    return findings

def parse_json(content):
    """Parse JSON and recursively search for secrets"""
    findings = []
    try:
        data = json.loads(content)
        findings.extend(scan_json_recursive(data, "JSON"))
    except Exception as e:
        pass
    
    return findings

def scan_json_recursive(obj, path=""):
    """Recursively scan JSON object for secrets"""
    findings = []
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            if isinstance(value, str):
                findings.extend(scan_text(value, f"JSON Key: {new_path}"))
            else:
                findings.extend(scan_json_recursive(value, new_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            findings.extend(scan_json_recursive(item, f"{path}[{i}]"))
    elif isinstance(obj, str):
        findings.extend(scan_text(obj, path))
    
    return findings

def parse_xml(content):
    """Parse XML and search text nodes and attributes"""
    findings = []
    try:
        root = ET.fromstring(content)
        for elem in root.iter():
            # Check text content
            if elem.text:
                findings.extend(scan_text(elem.text, f"XML Element: {elem.tag}"))
            # Check attributes
            for attr, value in elem.attrib.items():
                findings.extend(scan_text(value, f"XML Attribute: {elem.tag}@{attr}"))
    except Exception as e:
        pass
    
    return findings

def scan_text(text, source=""):
    """Scan text for secrets using regex patterns"""
    findings = []
    
    # Scan for emails
    emails = set(re.findall(EMAIL_REGEX, text))
    for email in emails:
        findings.append(f"[EMAIL] {email} | Source: {source}")
    
    # Scan for secret patterns
    for key_name, pattern in KEY_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            # Filter out false positives
            if isinstance(match, tuple):
                match = match[0] if match else ""
            
            if len(str(match)) > 8:
                # Truncate long secrets for display
                display_match = str(match)[:30] + "..." if len(str(match)) > 30 else str(match)
                findings.append(f"[SECRET] {key_name}: {display_match} | Source: {source}")
    
    return findings

def fetch_and_scan(url, parse_html_flag=False, parse_json_flag=False, parse_xml_flag=False, timeout=5):
    """Fetch URL and scan for secrets with content-type aware parsing"""
    findings = []
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        content = response.text
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Basic text scan for all content
        findings.extend(scan_text(content, f"URL: {url}"))
        
        # Content-type specific parsing
        if parse_html_flag and ('html' in content_type or '<html' in content[:1000].lower()):
            findings.extend(parse_html(content))
        
        if parse_json_flag and ('json' in content_type or content.strip().startswith('{')):
            findings.extend(parse_json(content))
        
        if parse_xml_flag and ('xml' in content_type or content.strip().startswith('<')):
            findings.extend(parse_xml(content))
        
    except Exception as e:
        pass  # Frequent errors expected in bulk scanning
    
    return findings

def main():
    parser = argparse.ArgumentParser(description="Enhanced Secret Scanner for Web Applications")
    parser.add_argument("url_file", help="File containing URLs to scan")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--parse-html", action="store_true", help="Enable HTML parsing")
    parser.add_argument("--parse-json", action="store_true", help="Enable JSON parsing")
    parser.add_argument("--parse-xml", action="store_true", help="Enable XML parsing")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    args = parser.parse_args()
    
    # Check for BeautifulSoup if HTML parsing is requested
    if args.parse_html and not BS4_AVAILABLE:
        print("Warning: BeautifulSoup4 not available. HTML parsing disabled.", file=sys.stderr)
        print("Install with: pip3 install beautifulsoup4", file=sys.stderr)
        args.parse_html = False
    
    # Read URLs
    urls = []
    with open(args.url_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip().startswith("http")]
    
    print(f"[-] Scanning {len(urls)} URLs for secrets and emails with {args.threads} threads...", file=sys.stderr)
    if args.parse_html:
        print(f"[-] HTML parsing enabled", file=sys.stderr)
    if args.parse_json:
        print(f"[-] JSON parsing enabled", file=sys.stderr)
    if args.parse_xml:
        print(f"[-] XML parsing enabled", file=sys.stderr)
    
    all_findings = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {
            executor.submit(
                fetch_and_scan, 
                url, 
                args.parse_html, 
                args.parse_json, 
                args.parse_xml,
                args.timeout
            ): url for url in urls
        }
        
        for future in future_to_url:
            result = future.result()
            if result:
                for item in result:
                    print(item)  # Print to stdout for capture
                    all_findings.append(item)
    
    if not all_findings:
        print("[-] No obvious secrets or emails found in crawled content.", file=sys.stderr)
    else:
        print(f"[+] Found {len(all_findings)} potential secrets/emails", file=sys.stderr)

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()

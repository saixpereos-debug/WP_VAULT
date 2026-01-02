#!/usr/bin/env python3
import requests
import sys
import argparse
import re
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

# Configuration
USER_AGENT = "Mozilla/5.0 (VAPT-Bot/2.0)"
INTERESTING_KEYWORDS = ["admin", "login", "dashboard", "config", "backup", "db", "auth", "private", "test", "staging", "dev", "api", "json", "xml", "env"]

def fetch_content(url):
    try:
        response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=10, verify=False)
        response.raise_for_status()
        return response.text
    except Exception as e:
        # print(f"[-] Error fetching {url}: {e}", file=sys.stderr)
        return None

def parse_robots(target_url):
    robots_url = urljoin(target_url, "/robots.txt")
    print(f"[*] Checking {robots_url}...", file=sys.stderr)
    content = fetch_content(robots_url)
    
    urls = set()
    sitemaps = set()
    
    if content:
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                # Extract path
                parts = line.split(":", 1)
                if len(parts) > 1:
                    path = parts[1].strip()
                    if path and path != "/":
                        full_url = urljoin(target_url, path)
                        urls.add(full_url)
            elif line.lower().startswith("sitemap:"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    sitemaps.add(parts[1].strip())
    
    return urls, sitemaps

def parse_sitemap(sitemap_url, depth=0, max_depth=2):
    if depth > max_depth:
        return set()
    
    print(f"[*] Parsing sitemap: {sitemap_url} (Depth: {depth})", file=sys.stderr)
    content = fetch_content(sitemap_url)
    urls = set()
    
    if not content:
        return urls

    try:
        # Simple regex for XML URLs to avoid complex namespace handling issues with ET sometimes
        # But ET is better for structure. Let's try ET first, fallback to regex.
        try:
            root = ET.fromstring(content)
            # Handle sitemapindex vs urlset
            # Namespaces are annoying in XML, so we ignore them by stripping or using regex
            # Regex is often more robust for malformed sitemaps in VAPT contexts
            raise Exception("Switching to Regex for robustness")
        except:
             # Regex Fallback
             found = re.findall(r'<loc>(.*?)</loc>', content)
             for u in found:
                 u = u.strip()
                 if u.endswith(".xml") and "sitemap" in u.lower():
                     # Recurse
                     urls.update(parse_sitemap(u, depth+1, max_depth))
                 else:
                     urls.add(u)
    except Exception as e:
        print(f"[-] Error parsing sitemap {sitemap_url}: {e}", file=sys.stderr)

    return urls

def is_interesting(url):
    for kw in INTERESTING_KEYWORDS:
        if kw in url.lower():
            return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Extract URLs from robots.txt and sitemap.xml")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--output", help="Output file for ALL URLs")
    parser.add_argument("--output-interesting", help="Output file for Interesting URLs")
    
    args = parser.parse_args()
    
    target = args.target
    if not target.startswith("http"):
        target = "https://" + target
        
    all_urls = set()
    
    # 1. Parse Robots.txt
    robots_urls, robots_sitemaps = parse_robots(target)
    all_urls.update(robots_urls)
    
    # 2. Parse Sitemaps (from robots.txt + default locations)
    sitemaps_to_check = robots_sitemaps
    if not sitemaps_to_check:
        # Add defaults
        sitemaps_to_check.add(urljoin(target, "/sitemap.xml"))
        sitemaps_to_check.add(urljoin(target, "/wp-sitemap.xml"))
        sitemaps_to_check.add(urljoin(target, "/sitemap_index.xml"))
    
    for sm in sitemaps_to_check:
        all_urls.update(parse_sitemap(sm))
        
    print(f"[+] Total URLs found: {len(all_urls)}", file=sys.stderr)
    
    # Filter Interesting
    interesting_urls = [u for u in all_urls if is_interesting(u)]
    print(f"[+] Interesting URLs found: {len(interesting_urls)}", file=sys.stderr)
    
    # Output
    if args.output:
        with open(args.output, "w") as f:
            for u in sorted(all_urls):
                f.write(u + "\n")
                
    if args.output_interesting:
        with open(args.output_interesting, "w") as f:
            for u in sorted(interesting_urls):
                f.write(u + "\n")
                
    # Print to stdout if no output file
    if not args.output and not args.output_interesting:
        for u in sorted(interesting_urls):
            print(u)

if __name__ == "__main__":
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()

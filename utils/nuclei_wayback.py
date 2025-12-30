#!/usr/bin/env python3
import subprocess
import requests
import time
import argparse
import concurrent.futures
from urllib.parse import urlparse
import os
import sys

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_wayback_urls(domain, max_urls=1000):
    """
    Retrieve URLs from the Wayback Machine for a given domain.
    """
    print(f"[+] Retrieving URLs from Wayback Machine for {domain}...")
    
    # Wayback Machine CDX API endpoint
    url = f"http://web.archive.org/cdx/search/cdx"
    params = {
        'url': f'*.{domain}',
        'output': 'json',
        'collapse': 'timestamp:8',
        'fl': 'original',
        'limit': max_urls
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        # Parse JSON response
        data = response.json()
        
        # Skip the first row (header) and extract URLs
        if len(data) > 1:
            urls = [row[0] for row in data[1:] if len(row) > 0]
            print(f"[+] Retrieved {len(urls)} URLs from Wayback Machine")
            return list(set(urls)) # De-duplicate
        else:
            print(f"[!] No URLs found in Wayback Machine for {domain}")
            return []
    except Exception as e:
        print(f"[!] Error retrieving URLs from Wayback Machine: {e}")
        return []

def check_url_alive(url, timeout=10):
    """
    Check if a URL is alive (returns a 2xx or 3xx status code).
    """
    try:
        # Parse the URL to ensure it has a scheme
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"
            
        headers = {'User-Agent': 'Mozilla/5.0 (Vṛthā VAPT Framework; +https://github.com/saixpereos-debug/Vrtha)'}
        response = requests.head(url, timeout=timeout, allow_redirects=True, headers=headers, verify=False)
        is_alive = 200 <= response.status_code < 400
        return (url, is_alive, response.status_code)
    except Exception:
        # Try GET if HEAD is blocked
        try:
             response = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers, verify=False, stream=True)
             is_alive = 200 <= response.status_code < 400
             return (url, is_alive, response.status_code)
        except Exception:
             return (url, False, None)

def filter_alive_urls(urls, max_workers=20, timeout=10):
    """
    Filter out dead or non-responsive URLs.
    """
    print(f"[+] Checking {len(urls)} URLs for aliveness...")
    
    alive_urls = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_url = {executor.submit(check_url_alive, url, timeout): url for url in urls}
        
        # Process as they complete
        for i, future in enumerate(concurrent.futures.as_completed(future_to_url)):
            url, is_alive, status_code = future.result()
            if is_alive:
                alive_urls.append(url)
            
            # Progress indicator (only on terminal, not in logs ideally)
            if (i + 1) % 100 == 0 or i == len(urls) - 1:
                print(f"[+] Processed {i+1}/{len(urls)} URLs, found {len(alive_urls)} alive URLs", end='\r')
    
    print(f"\n[+] Found {len(alive_urls)} alive URLs out of {len(urls)} total")
    return alive_urls

def run_nuclei(urls, templates, output_file, rate_limit=150, concurrency=25):
    """
    Run Nuclei on the list of URLs.
    """
    if not urls:
        print("[!] No URLs to scan with Nuclei.")
        return False

    print(f"[+] Running Nuclei on {len(urls)} URLs...")
    
    # Create a temporary file with URLs
    temp_file = f"temp_nuclei_urls_{int(time.time())}.txt"
    with open(temp_file, 'w') as f:
        for url in urls:
            f.write(f"{url}\n")
    
    # Build the Nuclei command
    cmd = [
        "nuclei",
        "-l", temp_file,
        "-o", output_file,
        "-rate-limit", str(rate_limit),
        "-c", str(concurrency),
        "-json"
    ]
    
    if templates:
        cmd.extend(["-t", templates])
    
    try:
        # Run Nuclei
        print(f"[+] Executing command: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Stream output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                sys.stdout.write(output)
                sys.stdout.flush()
        
        # Get return code
        return_code = process.poll()
        
        # Clean up temp file
        if os.path.exists(temp_file):
            os.remove(temp_file)
        
        if return_code == 0:
            print(f"[+] Nuclei scan completed successfully. Results saved to {output_file}")
            return True
        else:
            print(f"[!] Nuclei scan failed with return code {return_code}")
            return False
    except Exception as e:
        print(f"[!] Error running Nuclei: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return False

def main():
    parser = argparse.ArgumentParser(description="Vṛthā Nuclei automation with Wayback URLs")
    parser.add_argument("-d", "--domain", required=True, help="Domain to scan")
    parser.add_argument("-t", "--templates", default="", help="Nuclei templates to use")
    parser.add_argument("-o", "--output", default="nuclei_results.json", help="Output file")
    parser.add_argument("-m", "--max-urls", type=int, default=500, help="Max Wayback URLs")
    parser.add_argument("-r", "--rate-limit", type=int, default=150, help="Nuclei rate limit")
    parser.add_argument("-c", "--concurrency", type=int, default=25, help="Nuclei concurrency")
    parser.add_argument("-w", "--workers", type=int, default=20, help="Aliveness workers")
    
    args = parser.parse_args()
    
    # Ensure domain is clean
    domain = args.domain.replace("https://", "").replace("http://", "").split("/")[0]
    
    urls = get_wayback_urls(domain, args.max_urls)
    if not urls:
        # Fallback to main domain if no Wayback URLs found
        print("[!] Falling back to main domain.")
        urls = [f"https://{domain}", f"http://{domain}"]
    
    alive_urls = filter_alive_urls(urls, args.workers)
    if not alive_urls:
        print("[!] No alive URLs found. Attempting scan of main domain anyway.")
        alive_urls = [f"https://{domain}"]
    
    run_nuclei(
        alive_urls,
        args.templates,
        args.output,
        args.rate_limit,
        args.concurrency
    )

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import requests
import sys
import json
import datetime

def check_plugin_status(plugin_slug):
    """Checks the status of a plugin on the WordPress.org repository."""
    url = f"https://api.wordpress.org/plugins/info/1.0/{plugin_slug}.json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            last_updated_str = data.get("last_updated", "")
            if last_updated_str:
                last_updated = datetime.datetime.strptime(last_updated_str, "%Y-%m-%d %H:%M:%S")
                days_since_update = (datetime.datetime.now() - last_updated).days
                
                status = {
                    "slug": plugin_slug,
                    "last_updated": last_updated_str,
                    "days_since_update": days_since_update,
                    "abandoned": days_since_update > 730, # More than 2 years
                    "closed": data.get("closed", False),
                    "reason": data.get("closed_reason", "")
                }
                return status
    except Exception:
        pass
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: wp_repo_check.py <plugin_slug1> <plugin_slug2> ...")
        sys.exit(1)
        
    plugins = sys.argv[1:]
    results = []
    
    for slug in plugins:
        result = check_plugin_status(slug)
        if result:
            results.append(result)
            
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()

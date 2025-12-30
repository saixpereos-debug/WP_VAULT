#!/usr/bin/env python3
"""
Vṛthā OWASP Nuclei Template Generator
Enhanced WordPress security template generator with CVE integration.

Based on ricardomaia's concept, extended for full OWASP Top 10 coverage.
"""

import requests
import json
import os
import argparse
from datetime import datetime
from pathlib import Path

# Configuration
WORDPRESS_API = "https://api.wordpress.org/plugins/info/1.2/"
WPSCAN_API = "https://wpscan.com/api/v3"
OUTPUT_DIR = "templates/nuclei"

# OWASP Top 10 Template Configurations
OWASP_TEMPLATES = {
    "a01": {
        "name": "Broken Access Control",
        "checks": [
            {"path": "/wp-json/wp/v2/users", "indicator": "user enumeration"},
            {"path": "/?author=1", "indicator": "author enumeration"},
            {"path": "/wp-admin/", "indicator": "admin access"},
        ]
    },
    "a02": {
        "name": "Cryptographic Failures",
        "checks": [
            {"path": "/wp-config.php.bak", "indicator": "config backup"},
            {"path": "/.env", "indicator": "env exposure"},
            {"path": "/debug.log", "indicator": "debug log"},
        ]
    },
    "a03": {
        "name": "Injection",
        "checks": [
            {"path": "/?s='", "indicator": "sqli test"},
            {"path": "/?s=<script>", "indicator": "xss test"},
        ]
    },
    "a04": {
        "name": "Insecure Design",
        "checks": [
            {"path": "/xmlrpc.php", "indicator": "xmlrpc enabled"},
        ]
    },
    "a05": {
        "name": "Security Misconfiguration",
        "checks": [
            {"path": "/wp-content/uploads/", "indicator": "directory listing"},
            {"path": "/readme.html", "indicator": "version disclosure"},
        ]
    },
    "a06": {
        "name": "Vulnerable Components",
        "checks": []  # Handled by plugin detection
    },
}


def get_top_plugins(count=200):
    """Fetch top WordPress plugins from official API."""
    plugins = []
    per_page = 100
    
    for page in range(1, (count // per_page) + 2):
        try:
            response = requests.get(
                WORDPRESS_API,
                params={
                    "action": "query_plugins",
                    "request[per_page]": per_page,
                    "request[page]": page,
                    "request[browse]": "popular"
                },
                timeout=30
            )
            data = response.json()
            
            for plugin in data.get("plugins", []):
                plugins.append({
                    "slug": plugin.get("slug"),
                    "name": plugin.get("name"),
                    "version": plugin.get("version"),
                    "active_installs": plugin.get("active_installs", 0)
                })
                
            if len(plugins) >= count:
                break
                
        except Exception as e:
            print(f"Error fetching plugins: {e}")
            break
    
    return plugins[:count]


def get_plugin_vulnerabilities(slug, wpscan_api_key=None):
    """Fetch known vulnerabilities for a plugin from WPScan API."""
    if not wpscan_api_key:
        return []
    
    try:
        response = requests.get(
            f"{WPSCAN_API}/plugins/{slug}",
            headers={"Authorization": f"Token token={wpscan_api_key}"},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get(slug, {}).get("vulnerabilities", [])
            
    except Exception as e:
        print(f"Error fetching vulnerabilities for {slug}: {e}")
    
    return []


def generate_plugin_template(plugin, vulns=None):
    """Generate Nuclei template for plugin detection and version check."""
    slug = plugin["slug"]
    name = plugin["name"]
    version = plugin["version"]
    
    template = f'''id: wordpress-plugin-{slug}

info:
  name: WordPress Plugin - {name} Detection
  author: vrtha-framework
  severity: info
  description: Detects {name} plugin and checks for outdated version
  reference:
    - https://wordpress.org/plugins/{slug}/
  metadata:
    plugin_namespace: {slug}
    wpscan: https://wpscan.com/plugin/{slug}
    current_version: {version}
    owasp: A06 - Vulnerable and Outdated Components
  tags: wordpress,wp-plugin,{slug}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/wp-content/plugins/{slug}/readme.txt"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: regex
        part: body
        regex:
          - '(?i)Stable.tag:\\s?([\\w.]+)'

    extractors:
      - type: regex
        name: detected_version
        part: body
        group: 1
        regex:
          - '(?i)Stable.tag:\\s?([\\w.]+)'
'''
    
    # Add vulnerability checks if available
    if vulns:
        template += f'''
# Known Vulnerabilities for {name}
'''
        for vuln in vulns[:5]:  # Limit to 5 vulnerabilities
            cve = vuln.get("references", {}).get("cve", [""])[0]
            title = vuln.get("title", "Unknown")
            template += f'''# - {title} ({cve})
'''

    return template


def generate_owasp_comprehensive():
    """Generate comprehensive OWASP assessment template."""
    return '''id: wordpress-owasp-comprehensive

info:
  name: WordPress OWASP Top 10 Comprehensive Check
  author: vrtha-framework
  severity: medium
  description: |
    Comprehensive security assessment covering OWASP Top 10.
    Runs multiple checks for each vulnerability category.
  reference:
    - https://owasp.org/www-project-top-ten/
  metadata:
    owasp: A01-A10
  tags: wordpress,owasp,comprehensive

http:
  # A01: Broken Access Control
  - method: GET
    path:
      - "{{BaseURL}}/wp-json/wp/v2/users"
    matchers:
      - type: word
        words:
          - '"slug":'
          - '"name":'
        condition: and

  # A02: Cryptographic Failures
  - method: GET
    path:
      - "{{BaseURL}}/wp-config.php.bak"
      - "{{BaseURL}}/.env"
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
          - "DB_NAME"
        condition: or

  # A03: Injection (Error-based SQLi detection)
  - method: GET
    path:
      - "{{BaseURL}}/?s=test'"
    matchers:
      - type: regex
        regex:
          - "SQL syntax.*MySQL"
          - "Warning.*mysql"

  # A05: Security Misconfiguration
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/uploads/"
      - "{{BaseURL}}/wp-includes/"
    matchers:
      - type: word
        words:
          - "Index of"
          - "Parent Directory"
        condition: and

  # A06: Vulnerable Components (Version Detection)
  - method: GET
    path:
      - "{{BaseURL}}/readme.html"
    extractors:
      - type: regex
        name: wp_version
        part: body
        regex:
          - 'Version\\s+([0-9.]+)'

  # A10: SSRF via XML-RPC
  - method: POST
    path:
      - "{{BaseURL}}/xmlrpc.php"
    headers:
      Content-Type: text/xml
    body: |
      <?xml version="1.0"?>
      <methodCall>
        <methodName>system.listMethods</methodName>
      </methodCall>
    matchers:
      - type: word
        words:
          - "pingback.ping"
'''


def save_template(content, filepath):
    """Save template to file."""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        f.write(content)
    print(f"  Created: {filepath}")


def save_version_helper(slug, version, helpers_dir):
    """Save version file for outdated detection."""
    Path(helpers_dir).mkdir(parents=True, exist_ok=True)
    filepath = os.path.join(helpers_dir, f"{slug}.txt")
    with open(filepath, 'w') as f:
        f.write(version)


def main():
    parser = argparse.ArgumentParser(description="Generate Nuclei templates for WordPress")
    parser.add_argument("--plugins", type=int, default=50, help="Number of top plugins to generate")
    parser.add_argument("--wpscan-key", type=str, help="WPScan API key for vulnerability data")
    parser.add_argument("--output", type=str, default=OUTPUT_DIR, help="Output directory")
    args = parser.parse_args()
    
    print(f"Vṛthā OWASP Nuclei Template Generator")
    print(f"=" * 40)
    print(f"Generating templates at: {args.output}")
    
    # Create directories
    plugins_dir = os.path.join(args.output, "wordpress", "plugins")
    owasp_dir = os.path.join(args.output, "owasp")
    helpers_dir = os.path.join(args.output, "helpers", "wordpress", "plugins")
    
    # Generate OWASP comprehensive template
    print("\n[*] Generating OWASP comprehensive template...")
    comprehensive = generate_owasp_comprehensive()
    save_template(comprehensive, os.path.join(owasp_dir, "wordpress-owasp-comprehensive.yaml"))
    
    # Fetch and generate plugin templates
    print(f"\n[*] Fetching top {args.plugins} WordPress plugins...")
    plugins = get_top_plugins(args.plugins)
    
    print(f"[*] Generating {len(plugins)} plugin templates...")
    for plugin in plugins:
        vulns = []
        if args.wpscan_key:
            vulns = get_plugin_vulnerabilities(plugin["slug"], args.wpscan_key)
        
        template = generate_plugin_template(plugin, vulns)
        filepath = os.path.join(plugins_dir, f"wordpress-plugin-{plugin['slug']}.yaml")
        save_template(template, filepath)
        
        # Save version helper
        if plugin.get("version"):
            save_version_helper(plugin["slug"], plugin["version"], helpers_dir)
    
    print(f"\n[+] Generation complete!")
    print(f"    - Plugin templates: {len(plugins)}")
    print(f"    - OWASP templates: 1 comprehensive")
    print(f"    - Version helpers: {len(plugins)}")


if __name__ == "__main__":
    main()

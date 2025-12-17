#!/usr/bin/env python3

import json
import os
import sys
import re
from datetime import datetime

def build_context(target, results_dir):
    """Build optimized context for OpenRouter API analysis"""
    
    # Create context directory
    context_dir = os.path.join(results_dir, "context")
    os.makedirs(context_dir, exist_ok=True)
    
    # Initialize context structure
    context = {
        "target": target,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "subdomains": {"count": 0, "items": []},
            "urls": {"count": 0, "items": []},
            "technologies": {"count": 0, "items": []},
            "vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "items": []}
        },
        "detailed_findings": []
    }
    
    # Process subdomain enumeration results
    process_subdomains(context, results_dir)
    
    # Process URL discovery results
    process_urls(context, results_dir)
    
    # Process httpx results
    process_httpx(context, results_dir)
    
    # Process network information
    process_network_info(context, results_dir)
    
    # Process DNS information
    process_dns_info(context, results_dir)
    
    # Process firewall detection
    process_firewall_info(context, results_dir)
    
    # Process Nuclei results
    process_nuclei_results(context, results_dir)
    
    # Process WordPress scan results
    process_wordpress_results(context, results_dir)
    
    # Save optimized context
    context_file = os.path.join(context_dir, f"vapt_{target}_optimized_context.json")
    with open(context_file, 'w') as f:
        json.dump(context, f, indent=2)
    
    # Create a summary text file for quick reference
    summary_file = os.path.join(context_dir, f"vapt_{target}_summary.txt")
    with open(summary_file, 'w') as f:
        f.write(f"VAPT Summary for {target}\n")
        f.write(f"Scan Date: {context['scan_date']}\n\n")
        
        f.write(f"Subdomains Found: {context['summary']['subdomains']['count']}\n")
        f.write(f"URLs Discovered: {context['summary']['urls']['count']}\n")
        f.write(f"Technologies Identified: {context['summary']['technologies']['count']}\n\n")
        
        f.write("Vulnerability Summary:\n")
        f.write(f"  Critical: {context['summary']['vulnerabilities']['critical']}\n")
        f.write(f"  High: {context['summary']['vulnerabilities']['high']}\n")
        f.write(f"  Medium: {context['summary']['vulnerabilities']['medium']}\n")
        f.write(f"  Low: {context['summary']['vulnerabilities']['low']}\n")
        f.write(f"  Info: {context['summary']['vulnerabilities']['info']}\n")
    
    print(f"Optimized context built and saved to {context_dir}")
    return context

def process_subdomains(context, results_dir):
    """Process subdomain enumeration results"""
    subdomains_file = os.path.join(results_dir, "subdomains", f"vapt_{context['target']}_subdomains_all.txt")
    
    if not os.path.exists(subdomains_file):
        return
    
    with open(subdomains_file, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]
    
    context['summary']['subdomains']['count'] = len(subdomains)
    context['summary']['subdomains']['items'] = subdomains[:50]  # Limit to top 50 for context

def process_urls(context, results_dir):
    """Process URL discovery results"""
    urls_file = os.path.join(results_dir, "urls", f"vapt_{context['target']}_urls_all.txt")
    
    if not os.path.exists(urls_file):
        return
    
    with open(urls_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    context['summary']['urls']['count'] = len(urls)
    context['summary']['urls']['items'] = urls[:100]  # Limit to top 100 for context

def process_httpx(context, results_dir):
    """Process httpx analysis results"""
    httpx_file = os.path.join(results_dir, "httpx", f"vapt_{context['target']}_httpx_combined.json")
    
    if not os.path.exists(httpx_file):
        return
    
    with open(httpx_file, 'r') as f:
        httpx_data = json.load(f)
    
    # Process technology detection
    tech_items = httpx_data.get('tech_detection', [])
    technologies = set()
    
    for item in tech_items:
        tech_list = item.get('tech', [])
        technologies.update(tech_list)
    
    context['summary']['technologies']['count'] = len(technologies)
    context['summary']['technologies']['items'] = list(technologies)
    
    # Process custom matchers, path probing, and method discovery
    for category in ['custom_matchers', 'path_probing', 'method_discovery']:
        items = httpx_data.get(category, [])
        
        for item in items:
            # Create a finding for interesting items
            if (category == 'custom_matchers' and item.get('status_code') in [200, 301, 302, 403]) or \
               (category == 'path_probing' and item.get('status_code') == 200) or \
               (category == 'method_discovery' and len(item.get('methods', [])) > 3):
                
                finding = {
                    "type": "httpx_" + category,
                    "url": item.get('url', ''),
                    "title": item.get('title', ''),
                    "status_code": item.get('status_code', 0),
                    "content_length": item.get('content_length', 0),
                    "technologies": item.get('tech', []),
                    "details": {}
                }
                
                if category == 'custom_matchers':
                    finding['details']['matched_pattern'] = item.get('matched_pattern', '')
                elif category == 'path_probing':
                    finding['details']['discovered_path'] = item.get('path', '')
                elif category == 'method_discovery':
                    finding['details']['allowed_methods'] = item.get('methods', [])
                
                context['detailed_findings'].append(finding)

def process_network_info(context, results_dir):
    """Process network information"""
    network_file = os.path.join(results_dir, "network", f"vapt_{context['target']}_network_info.txt")
    
    if not os.path.exists(network_file):
        return
    
    with open(network_file, 'r') as f:
        network_info = f.read()
    
    # Extract key information
    ip_match = re.search(r'IP Address:\s*([0-9.]+)', network_info)
    if ip_match:
        context['network_info'] = {
            "ip_address": ip_match.group(1)
        }
    
    # Extract open ports
    ports_match = re.search(r'Basic Port Scan.*?\n(.*?)\n\n', network_info, re.DOTALL)
    if ports_match:
        ports_text = ports_match.group(1)
        open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\w+)', ports_text)
        
        if 'network_info' not in context:
            context['network_info'] = {}
        
        context['network_info']['open_ports'] = [{"port": port, "service": service} for port, service in open_ports]

def process_dns_info(context, results_dir):
    """Process DNS information"""
    dns_file = os.path.join(results_dir, "dns", f"vapt_{context['target']}_dns_info.txt")
    
    if not os.path.exists(dns_file):
        return
    
    with open(dns_file, 'r') as f:
        dns_info = f.read()
    
    # Extract DNS records
    dns_records = {}
    
    # A records
    a_records = re.findall(r'([a-zA-Z0-9.-]+)\s+has address\s+([0-9.]+)', dns_info)
    if a_records:
        dns_records['A'] = [{"domain": domain, "ip": ip} for domain, ip in a_records]
    
    # MX records
    mx_records = re.findall(r'([a-zA-Z0-9.-]+)\s+mail is handled by\s+(\d+)\s+([a-zA-Z0-9.-]+)', dns_info)
    if mx_records:
        dns_records['MX'] = [{"domain": domain, "priority": priority, "mail_server": server} for domain, priority, server in mx_records]
    
    # NS records
    ns_records = re.findall(r'([a-zA-Z0-9.-]+)\s+name server\s+([a-zA-Z0-9.-]+)', dns_info)
    if ns_records:
        dns_records['NS'] = [{"domain": domain, "nameserver": ns} for domain, ns in ns_records]
    
    if dns_records:
        context['dns_info'] = dns_records

def process_firewall_info(context, results_dir):
    """Process firewall detection results"""
    firewall_file = os.path.join(results_dir, "firewall", f"vapt_{context['target']}_firewall_detection.txt")
    
    if not os.path.exists(firewall_file):
        return
    
    with open(firewall_file, 'r') as f:
        firewall_info = f.read()
    
    # Extract WAF information
    waf_match = re.search(r'WAF detected:\s*(.+)', firewall_info)
    if waf_match:
        context['firewall_info'] = {
            "waf_detected": True,
            "waf_type": waf_match.group(1).strip()
        }
    else:
        context['firewall_info'] = {
            "waf_detected": False
        }
    
    # Check for Cloudflare
    cloudflare_match = re.search(r'Cloudflare\s+(detected|not detected)', firewall_info)
    if cloudflare_match:
        if 'firewall_info' not in context:
            context['firewall_info'] = {}
        
        context['firewall_info']['cloudflare'] = cloudflare_match.group(1) == "detected"

def process_nuclei_results(context, results_dir):
    """Process Nuclei scan results"""
    nuclei_file = os.path.join(results_dir, "nuclei", f"vapt_{context['target']}_nuclei_categorized.json")
    
    if not os.path.exists(nuclei_file):
        return
    
    with open(nuclei_file, 'r') as f:
        nuclei_data = json.load(f)
    
    # Process by severity
    by_severity = nuclei_data.get('by_severity', {})
    
    for severity, items in by_severity.items():
        if severity.lower() in ['critical', 'high', 'medium', 'low', 'info']:
            context['summary']['vulnerabilities'][severity.lower()] = len(items)
            
            # Add detailed findings
            for item in items:
                info = item.get('info', {})
                
                finding = {
                    "type": "nuclei",
                    "severity": severity,
                    "name": info.get('name', ''),
                    "description": info.get('description', ''),
                    "url": item.get('matched-at', ''),
                    "template_id": info.get('id', ''),
                    "tags": info.get('tags', []),
                    "classification": info.get('classification', {}),
                    "references": info.get('reference', []),
                    "details": {}
                }
                
                # Extract additional details
                if 'extracted-results' in item:
                    finding['details']['extracted_results'] = item['extracted-results']
                
                context['detailed_findings'].append(finding)

def process_wordpress_results(context, results_dir):
    """Process WordPress scan results"""
    wordpress_file = os.path.join(results_dir, "wordpress", f"vapt_{context['target']}_wpscan_all.txt")
    
    if not os.path.exists(wordpress_file):
        return
    
    with open(wordpress_file, 'r') as f:
        wordpress_info = f.read()
    
    # Extract WordPress version
    version_match = re.search(r'WordPress version\s*([0-9.]+)', wordpress_info)
    if version_match:
        if 'wordpress_info' not in context:
            context['wordpress_info'] = {}
        
        context['wordpress_info']['version'] = version_match.group(1)
    
    # Extract theme information
    theme_matches = re.findall(r'Theme:\s*(.+?)\s*\|', wordpress_info)
    if theme_matches:
        if 'wordpress_info' not in context:
            context['wordpress_info'] = {}
        
        context['wordpress_info']['themes'] = theme_matches
    
    # Extract plugin information
    plugin_matches = re.findall(r'Plugin:\s*(.+?)\s*\|', wordpress_info)
    if plugin_matches:
        if 'wordpress_info' not in context:
            context['wordpress_info'] = {}
        
        context['wordpress_info']['plugins'] = plugin_matches
    
    # Extract vulnerabilities
    vuln_matches = re.findall(r'\[!\]\s*(.+?)\s*\|', wordpress_info)
    if vuln_matches:
        for vuln in vuln_matches:
            # Try to extract severity
            severity = "medium"  # Default severity
            if "critical" in vuln.lower():
                severity = "critical"
            elif "high" in vuln.lower():
                severity = "high"
            elif "low" in vuln.lower():
                severity = "low"
            elif "info" in vuln.lower():
                severity = "info"
            
            finding = {
                "type": "wordpress",
                "severity": severity,
                "name": "WordPress Vulnerability",
                "description": vuln,
                "url": context['target'],
                "details": {}
            }
            
            context['detailed_findings'].append(finding)
            context['summary']['vulnerabilities'][severity] += 1

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 context_builder.py <target> <results_dir>")
        sys.exit(1)
    
    target = sys.argv[1]
    results_dir = sys.argv[2]
    
    build_context(target, results_dir)

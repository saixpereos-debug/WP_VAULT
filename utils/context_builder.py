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
    
    # Process Uncover results
    process_uncover_results(context, results_dir)
    
    # Process Nuclei results
    process_nuclei_results(context, results_dir)
    
    # Process WordPress scan results
    process_wordpress_results(context, results_dir)
    
    # Process secret scanning results
    process_secret_scanning(context, results_dir)
    
    # Process live host statistics
    process_live_hosts(context, results_dir)
    
    # Process vulnerable route analysis
    process_vulnerable_routes(context, results_dir)
    
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
    """Process httpx analysis results (handles JSONL format)"""
    httpx_file = os.path.join(results_dir, "httpx", f"vapt_{context['target']}_httpx_combined.json")
    
    if not os.path.exists(httpx_file):
        return
    
    technologies = set()
    
    try:
        with open(httpx_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    # Extract technologies
                    for field in ['tech', 'technologies', 'td']:
                        if field in item and item[field]:
                            if isinstance(item[field], list):
                                technologies.update(item[field])
                            elif isinstance(item[field], str):
                                technologies.add(item[field])
                    
                    # Create findings for interesting responses
                    status_code = item.get('status_code', 0)
                    url = item.get('url', '')
                    
                    if status_code in [403, 401] or any(path in url.lower() for path in ['/admin', '/backup', '/.env', '/.git']):
                        finding = {
                            "type": "httpx_interesting",
                            "url": url,
                            "title": item.get('title', ''),
                            "status_code": status_code,
                            "content_length": item.get('content_length', 0),
                            "technologies": item.get('tech', []) or item.get('technologies', []),
                            "server": item.get('server', ''),
                            "details": {}
                        }
                        
                        severity = 'info'
                        if status_code == 403:
                            severity = 'medium'
                            finding['details']['note'] = 'Forbidden resource - may indicate hidden functionality'
                        elif '/.env' in url or '/.git' in url:
                            severity = 'high'
                            finding['details']['note'] = 'Sensitive file exposure detected'
                        elif '/admin' in url or '/backup' in url:
                            severity = 'medium'
                            finding['details']['note'] = 'Administrative or backup endpoint discovered'
                        
                        finding['severity'] = severity
                        context['detailed_findings'].append(finding)
                        context['summary']['vulnerabilities'][severity] += 1
                        
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Error processing httpx results: {e}")
    
    context['summary']['technologies']['count'] = len(technologies)
    context['summary']['technologies']['items'] = sorted(list(technologies))
    context['summary']['technologies']['count'] = len(technologies)
    context['summary']['technologies']['items'] = sorted(list(technologies))

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
    
    # Extract open ports (Nmap style)
    ports_match = re.search(r'Basic Port Scan.*?\n(.*?)\n\n', network_info, re.DOTALL)
    if 'network_info' not in context:
        context['network_info'] = {}

    ports_list = []
    
    # Check Nmap
    if ports_match:
        ports_text = ports_match.group(1)
        open_ports_nmap = re.findall(r'(\d+)/tcp\s+open\s+(\w+)', ports_text)
        for port, service in open_ports_nmap:
            ports_list.append({"port": port, "service": service})
            
    # Check Naabu
    # Format: host:port, e.g. example.com:80 or 1.2.3.4:443
    # We look for the "Port Scan (Naabu):" section
    naabu_match = re.search(r'Port Scan \(Naabu\):.*?\n(.*?)$', network_info, re.DOTALL)
    if naabu_match:
        naabu_text = naabu_match.group(1)
        naabu_ports = re.findall(r':(\d+)', naabu_text)
        for port in naabu_ports:
            # Avoid duplicates if nmap found it
            if not any(p['port'] == port for p in ports_list):
                 ports_list.append({"port": port, "service": "unknown"})

    if ports_list:
        context['network_info']['open_ports'] = ports_list

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

def process_uncover_results(context, results_dir):
    """Process Uncover reconnaissance results"""
    uncover_file = os.path.join(results_dir, "uncover", f"vapt_{context['target']}_uncover.txt")
    
    if not os.path.exists(uncover_file):
        return
        
    with open(uncover_file, 'r') as f:
        assets = [line.strip() for line in f if line.strip()]
        
    if assets:
        if 'recon_info' not in context:
            context['recon_info'] = {}
        context['recon_info']['exposed_assets_count'] = len(assets)
        context['recon_info']['exposed_assets'] = assets[:20]

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

    # Process Extra Checks (Rule set findings)
    extra_checks_file = os.path.join(results_dir, "wordpress", f"vapt_{context['target']}_extra_checks.txt")
    if os.path.exists(extra_checks_file):
        with open(extra_checks_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                severity = "medium"
                if "[CRITICAL]" in line:
                    severity = "critical"
                elif "[HIGH]" in line:
                    severity = "high"
                elif "[!]" in line:
                    severity = "high" # Map [!] to High for security visibility
                
                finding = {
                    "type": "wordpress_extra",
                    "severity": severity,
                    "name": "WordPress Rule Finding",
                    "description": line,
                    "url": context['target'],
                    "details": {}
                }
                
                context['detailed_findings'].append(finding)
                context['summary']['vulnerabilities'][severity] += 1

def process_secret_scanning(context, results_dir):
    """Process secret scanning results"""
    secrets_file = os.path.join(results_dir, "secrets", f"vapt_{context['target']}_scraped_secrets.txt")
    
    if not os.path.exists(secrets_file):
        return
    
    with open(secrets_file, 'r') as f:
        secrets = [line.strip() for line in f if line.strip()]
    
    if secrets:
        if 'security_info' not in context:
            context['security_info'] = {}
        
        # Count by type
        secret_types = {}
        email_count = 0
        
        for secret in secrets:
            if '[EMAIL]' in secret:
                email_count += 1
            elif '[SECRET]' in secret:
                # Extract secret type
                match = re.search(r'\[SECRET\]\s+([^:]+):', secret)
                if match:
                    secret_type = match.group(1).strip()
                    secret_types[secret_type] = secret_types.get(secret_type, 0) + 1
        
        context['security_info']['secrets_found'] = len(secrets)
        context['security_info']['emails_found'] = email_count
        context['security_info']['secret_types'] = secret_types
        context['security_info']['sample_secrets'] = secrets[:10]  # First 10 for context

def process_live_hosts(context, results_dir):
    """Process live host statistics"""
    live_hosts_file = os.path.join(results_dir, "httpx", "live_hosts.txt")
    interesting_urls_file = os.path.join(results_dir, "httpx", "interesting_urls.txt")
    
    if os.path.exists(live_hosts_file):
        with open(live_hosts_file, 'r') as f:
            live_hosts = [line.strip() for line in f if line.strip()]
        
        if 'recon_info' not in context:
            context['recon_info'] = {}
        
        context['recon_info']['live_hosts_count'] = len(live_hosts)
        context['recon_info']['live_hosts'] = live_hosts[:20]  # First 20 for context
    
    if os.path.exists(interesting_urls_file):
        with open(interesting_urls_file, 'r') as f:
            interesting = [line.strip() for line in f if line.strip()]
        
        if 'recon_info' not in context:
            context['recon_info'] = {}
        
        context['recon_info']['interesting_urls_count'] = len(interesting)
        context['recon_info']['interesting_urls'] = interesting[:20]

def process_vulnerable_routes(context, results_dir):
    """Process vulnerable route analysis results"""
    routes_file = os.path.join(results_dir, "route_analysis", f"vapt_{context['target']}_vulnerable_routes.json")
    
    if not os.path.exists(routes_file):
        return
    
    try:
        with open(routes_file, 'r') as f:
            routes_data = json.load(f)
        
        if 'vulnerability_analysis' not in context:
            context['vulnerability_analysis'] = {}
        
        # Add summary
        context['vulnerability_analysis']['vulnerable_routes'] = routes_data.get('summary', {})
        
        # Add top findings by type
        findings_by_type = routes_data.get('findings', {})
        context['vulnerability_analysis']['top_vulnerable_routes'] = {}
        
        for vuln_type, findings in findings_by_type.items():
            # Keep top 10 of each type
            context['vulnerability_analysis']['top_vulnerable_routes'][vuln_type] = findings[:10]
        
        # Update vulnerability counts
        for vuln_type, findings in findings_by_type.items():
            for finding in findings:
                severity = finding.get('severity', 'info').lower()
                if severity in context['summary']['vulnerabilities']:
                    context['summary']['vulnerabilities'][severity] += 1
    
    except Exception as e:
        pass

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 context_builder.py <target> <results_dir>")
        sys.exit(1)
    
    target = sys.argv[1]
    results_dir = sys.argv[2]
    
    build_context(target, results_dir)

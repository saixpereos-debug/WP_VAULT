
import json
import os
import glob
import re
from pathlib import Path

def parse_nuclei_results(results_dir):
    """Parses Nuclei JSON output."""
    findings = []
    nuclei_file = os.path.join(results_dir, "nuclei", "*_nuclei.json")
    files = glob.glob(nuclei_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                # Nuclei often outputs one JSON object per line
                for line in f:
                    try:
                        data = json.loads(line)
                        findings.append({
                            "tool": "nuclei",
                            "name": data.get("info", {}).get("name", "Unknown"),
                            "severity": data.get("info", {}).get("severity", "info"),
                            "description": data.get("info", {}).get("description", ""),
                            "matched_at": data.get("matched-at", ""),
                            "curl_command": data.get("curl-command", "")
                        })
                    except: pass
        except Exception as e:
            print(f"Error reading nuclei file {fpath}: {e}")
    return findings

def parse_httpx_results(results_dir):
    """Parses HTTPX/Tech Detection results."""
    tech_stack = {}
    httpx_file = os.path.join(results_dir, "httpx", "*_httpx_tech.json")
    files = glob.glob(httpx_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        url = data.get("url")
                        tech = data.get("tech", [])
                        if url and tech:
                            tech_stack[url] = tech
                    except: pass
        except: pass
    return tech_stack

def parse_secrets_results(results_dir):
    """Parses Secrets scan results."""
    secrets = []
    secrets_file = os.path.join(results_dir, "secrets", "*_trufflehog.json")
    files = glob.glob(secrets_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                data = json.load(f)
                # Helper to recursive search? Or just simple parse if structure is known
                # Trufflehog V3 structure varies, assuming simple list or specific format
                # For now, let's just grab basic info if possible or raw count
                secrets.append(str(data)[:1000]) # Truncate for now
        except: pass
    return secrets

def parse_nmap_results(results_dir):
    """Parses Nmap scan results for open ports, services, and versions."""
    ports = []
    nmap_file = os.path.join(results_dir, "network", "*_network_info.txt")
    files = glob.glob(nmap_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                content = f.read()
                # Parse port lines (e.g., "21/tcp open ftp vsftpd 2.3.4")
                # pattern: port/proto state service version
                port_pattern = r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)'
                matches = re.findall(port_pattern, content)
                for match in matches:
                    ports.append({
                        "port": match[0],
                        "protocol": match[1],
                        "state": match[2],
                        "service": match[3],
                        "version": match[4].strip() if match[4] else "Unknown"
                    })
        except Exception as e:
            print(f"Error reading nmap file {fpath}: {e}")
    return ports

def parse_wordpress_results(results_dir):
    """Parses WordPress-specific scan results (WPScan) with enhanced extraction."""
    wp_data = {
        "version": None,
        "plugins": [],
        "themes": [],
        "users": [],
        "vulnerabilities": [],
        "interesting_findings": []
    }
    
    # Updated glob to match 'vapt_mahadevgranite.com_wpscan_all.txt'
    wpscan_file = os.path.join(results_dir, "wordpress", "*_wpscan*.txt")
    files = glob.glob(wpscan_file)
    
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                content = f.read()
                
                # Extract WordPress version
                version_match = re.search(r'WordPress version ([\d.]+)', content)
                if version_match:
                    wp_data["version"] = version_match.group(1)
                
                # Extract interesting findings (more robustly)
                if "[+] XML-RPC seems to be enabled" in content:
                    wp_data["interesting_findings"].append("XML-RPC enabled")
                if "[+] The external WP-Cron seems to be enabled" in content:
                    wp_data["interesting_findings"].append("External WP-Cron enabled")
                if "WordPress REST API Exposure" in content or "wp-json" in content:
                    wp_data["interesting_findings"].append("REST API exposure detected")
                
                # Extract vulnerabilities (look for [!] and References)
                vuln_sections = re.split(r'\[!\]', content)
                for section in vuln_sections[1:]: # Skip first part
                    name_match = re.search(r'^(.*?)\n', section)
                    if name_match:
                        vuln_name = name_match.group(1).strip()
                        ref_matches = re.findall(r'\|\s+-\s+(https?://\S+)', section)
                        wp_data["vulnerabilities"].append({
                            "name": vuln_name,
                            "references": ref_matches[:3], # Limit to first 3
                            "details": section[:300].strip() # Snip for context
                        })
                    
                # Extract plugin information
                plugin_blocks = re.split(r'\[\+\]', content)
                for block in plugin_blocks:
                    if "Version:" in block:
                        name_match = re.search(r'^(.*?)\n', block)
                        version_match = re.search(r'Version:\s+([\d.]+)', block)
                        if name_match and version_match:
                            wp_data["plugins"].append({
                                "name": name_match.group(1).strip(),
                                "version": version_match.group(1).strip()
                            })
                            
        except Exception as e:
            print(f"Error reading WordPress file {fpath}: {e}")
    
    return wp_data

def parse_sast_results(results_dir):
    """Parses Plugin SAST JSON results."""
    sast_findings = []
    sast_file = os.path.join(results_dir, "wordpress", "sast_*.json")
    files = glob.glob(sast_file)
    for fpath in files:
        try:
            plugin_name = os.path.basename(fpath).replace("sast_", "").replace(".json", "")
            with open(fpath, 'r') as f:
                data = json.load(f)
                if data:
                    sast_findings.append({
                        "plugin": plugin_name,
                        "findings": data
                    })
        except: pass
    return sast_findings

def parse_config_audit(results_dir):
    """Parses configuration audit and header audit results."""
    audit_data = {
        "hardening_issues": [],
        "header_issues": []
    }
    
    # 1. Parse text-based config audit
    config_file = os.path.join(results_dir, "context", "*_config_audit.txt")
    files = glob.glob(config_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                for line in f:
                    if line.strip().startswith("[!]"):
                        audit_data["hardening_issues"].append(line.strip())
        except: pass

    # 2. Parse header audit JSON
    header_file = os.path.join(results_dir, "context", "*_header_audit.json")
    files = glob.glob(header_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                data = json.load(f)
                # Header auditor returns a list of site findings
                for site in data:
                    for issue in site.get("issues", []):
                        audit_data["header_issues"].append({
                            "url": site.get("url"),
                            "header": issue.get("header"),
                            "impact": issue.get("impact")
                        })
        except: pass
        
    return audit_data

def parse_abandoned_plugins(results_dir):
    """Parses abandoned plugin audit results."""
    abandoned = []
    abandoned_file = os.path.join(results_dir, "wordpress", "*_abandoned_plugins.json")
    files = glob.glob(abandoned_file)
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                data = json.load(f)
                for item in data:
                    if item.get("abandoned") or item.get("closed"):
                        abandoned.append(item)
        except: pass
    return abandoned

def get_scan_context(results_dir):
    """Aggregates all results into a structured JSON context for AI analysis."""
    nuclei_data = parse_nuclei_results(results_dir)
    tech_data = parse_httpx_results(results_dir)
    secrets_data = parse_secrets_results(results_dir)
    nmap_data = parse_nmap_results(results_dir)
    wp_data = parse_wordpress_results(results_dir)
    sast_data = parse_sast_results(results_dir)
    audit_data = parse_config_audit(results_dir)
    abandoned_data = parse_abandoned_plugins(results_dir)
    
    # Get target domain from directory name
    target_domain = os.path.basename(results_dir)
    
    # Build structured context
    context = {
        "target": target_domain,
        "scan_date": "Recent scan",
        "technology_stack": tech_data,
        "open_ports": nmap_data,
        "wordpress": wp_data,
        "plugin_sast": sast_data,
        "config_audit": audit_data,
        "abandoned_plugins": abandoned_data,
        "nuclei_findings": nuclei_data,
        "secrets_found": len(secrets_data) > 0,
        "secrets_count": len(secrets_data)
    }
    
    # Convert to formatted JSON string for better readability
    context_json = json.dumps(context, indent=2)
    
    # Also create a human-readable summary
    summary = f"""# Scan Summary for {target_domain}

## Target Information
- Domain: {target_domain}
- Scan Type: Comprehensive VAPT Assessment

## Technology Stack Detected
"""
    
    for url, tech in tech_data.items():
        summary += f"- {url}: {', '.join(tech)}\n"
    
    summary += f"\n## Open Ports and Services\n"
    if nmap_data:
        for port in nmap_data:
            summary += f"- {port['port']}/{port['protocol']} - {port['state']} - {port['service']} ({port.get('version', 'Unknown')})\n"
    else:
        summary += "No port scan data available.\n"
    
    summary += f"\n## WordPress Information\n"
    if wp_data.get("version"):
        summary += f"- Version: {wp_data['version']}\n"
    if wp_data.get("plugins"):
        summary += f"- Plugins Found: {len(wp_data['plugins'])}\n"
        for plugin in wp_data['plugins'][:5]:  # Show first 5
            summary += f"  - {plugin['name']} (v{plugin['version']})\n"
    if wp_data.get("interesting_findings"):
        summary += f"- Interesting Findings:\n"
        for finding in wp_data['interesting_findings']:
            summary += f"  - {finding}\n"
    if wp_data.get("vulnerabilities"):
        summary += f"- WPScan Vulnerabilities:\n"
        for v in wp_data['vulnerabilities'][:5]:
            summary += f"  - [!] {v['name']}\n"

    summary += f"\n## Nuclei Vulnerability Scan Results\n"
    if not nuclei_data:
        summary += "No vulnerabilities found by Nuclei automated scan.\n"
    else:
        summary += f"Found {len(nuclei_data)} vulnerabilities:\n"
        for v in nuclei_data:
            summary += f"- [{v['severity'].upper()}] {v['name']}\n"
            summary += f"  - Location: {v['matched_at']}\n"
            if v.get('description'):
                summary += f"  - Description: {v['description']}\n"
            if v.get('curl_command'):
                summary += f"  - PoC Command: {v['curl_command'][:200]}...\n"
    
    summary += f"\n## Plugin Static Analysis (SAST)\n"
    if not sast_data:
        summary += "No specific plugin source analysis performed or no issues found.\n"
    else:
        for plugin in sast_data:
            summary += f"- Plugin: {plugin['plugin']}\n"
            for f in plugin['findings'][:5]:
                summary += f"  - [{f['severity']}] {f['category']} in {f['file']}:{f['line']}\n"
                summary += f"    Desc: {f['description']}\n"
    
    summary += f"\n## Configuration & Hardening Audit\n"
    if not audit_data["hardening_issues"] and not audit_data["header_issues"]:
        summary += "No significant configuration hardening issues found.\n"
    else:
        if audit_data["hardening_issues"]:
            summary += "### Hardening Issues:\n"
            for issue in audit_data["hardening_issues"]:
                summary += f"- {issue}\n"
        if audit_data["header_issues"]:
            summary += "### Missing/Weak Security Headers:\n"
            for issue in audit_data["header_issues"]:
                summary += f"- {issue['header']}: {issue['impact']}\n"

    summary += f"\n## Supply Chain Security (Abandoned Plugins)\n"
    if not abandoned_data:
        summary += "No abandoned or closed plugins detected.\n"
    else:
        for p in abandoned_data:
            summary += f"- [!] {p['slug']} (Last Updated: {p['last_updated']})\n"
            if p.get("closed"):
                summary += f"  - WARNING: Plugin is CLOSED on WordPress.org repository!\n"
    
    summary += f"\n## Secrets Detection\n"
    if not secrets_data:
        summary += "No secrets detected in scan.\n"
    else:
        summary += f"Found {len(secrets_data)} potential secret exposures.\n"
    
    summary += f"\n## Raw Scan Data (JSON)\n```json\n{context_json}\n```\n"
    
    return summary

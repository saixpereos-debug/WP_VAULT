#!/usr/bin/env python3

import json
import os
import sys
from datetime import datetime

def generate_html_report(target, results_dir):
    """Generate a standalone HTML report from scan results"""
    
    # Create final report directory
    final_report_dir = os.path.join(results_dir, "final_report")
    os.makedirs(final_report_dir, exist_ok=True)
    
    # Load optimized context
    context_file = os.path.join(results_dir, "context", f"vapt_{target}_optimized_context.json")
    
    if not os.path.exists(context_file):
        print(f"Error: Context file not found at {context_file}", file=sys.stderr)
        return False
    
    with open(context_file, 'r') as f:
        context = json.load(f)
    
    # Load AI report if exists
    ai_report_path = os.path.join(final_report_dir, f"vapt_{target}_ai_report.md")
    ai_report_content = ""
    if os.path.exists(ai_report_path):
        with open(ai_report_path, 'r') as f:
            ai_report_content = f.read()
    
    # Generate HTML
    html_content = generate_html(target, context, ai_report_content)
    
    # Save HTML report
    output_path = os.path.join(final_report_dir, f"vapt_{target}_report.html")
    with open(output_path, 'w') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {output_path}", file=sys.stderr)
    return True

def generate_html(target, context, ai_report=""):
    """Generate HTML content from context"""
    
    scan_date = context.get('scan_date', 'Unknown')
    summary = context.get('summary', {})
    findings = context.get('detailed_findings', [])
    
    # Count vulnerabilities
    vuln_summary = summary.get('vulnerabilities', {})
    # Only sum numeric severity counts, ignore 'items' list
    total_vulns = sum(v for v in vuln_summary.values() if isinstance(v, int))
    
    critical_findings = [f for f in findings if f.get('severity', '').lower() == 'critical']
    high_findings = [f for f in findings if f.get('severity', '').lower() == 'high']
    medium_findings = [f for f in findings if f.get('severity', '').lower() == 'medium']
    low_findings = [f for f in findings if f.get('severity', '').lower() == 'low']
    info_findings = [f for f in findings if f.get('severity', '').lower() == 'info']
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAPT Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f7fa;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        header .meta {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        
        .card h3 {{
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        
        .card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }}
        
        .severity-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        
        .severity-card.critical {{ border-left: 4px solid #e74c3c; }}
        .severity-card.high {{ border-left: 4px solid #e67e22; }}
        .severity-card.medium {{ border-left: 4px solid #f39c12; }}
        .severity-card.low {{ border-left: 4px solid #27ae60; }}
        .severity-card.info {{ border-left: 4px solid #3498db; }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{ background: #e74c3c; }}
        .severity-badge.high {{ background: #e67e22; }}
        .severity-badge.medium {{ background: #f39c12; }}
        .severity-badge.low {{ background: #27ae60; }}
        .severity-badge.info {{ background: #3498db; }}
        
        .finding {{
            background: #f8f9fa;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 3px solid #667eea;
        }}
        
        .finding h4 {{
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.2em;
        }}
        
        .finding-detail {{
            margin: 10px 0;
        }}
        
        .finding-detail strong {{
            color: #667eea;
            display: inline-block;
            min-width: 120px;
        }}
        
        .section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .section h3 {{
            color: #667eea;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.4em;
        }}
        
        code {{
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #e74c3c;
        }}
        
        pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        .ai-report {{
            background: #fff9e6;
            border-left: 4px solid #f39c12;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        
        .stat-item {{
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        
        .stat-item .label {{
            font-size: 0.9em;
            color: #7f8c8d;
            margin-bottom: 5px;
        }}
        
        .stat-item .value {{
            font-size: 1.8em;
            font-weight: bold;
            color: #667eea;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 WordPress VAPT Report</h1>
            <div class="meta">
                <strong>Target:</strong> {target}<br>
                <strong>Scan Date:</strong> {scan_date}
            </div>
        </header>
        
        <div class="summary-cards">
            <div class="card">
                <h3>Subdomains</h3>
                <div class="number">{summary.get('subdomains', {}).get('count', 0)}</div>
            </div>
            <div class="card">
                <h3>URLs Discovered</h3>
                <div class="number">{summary.get('urls', {}).get('count', 0)}</div>
            </div>
            <div class="card">
                <h3>Technologies</h3>
                <div class="number">{summary.get('technologies', {}).get('count', 0)}</div>
            </div>
            <div class="card">
                <h3>Total Findings</h3>
                <div class="number">{total_vulns}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Vulnerability Summary</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="label">Critical</div>
                    <div class="value" style="color: #e74c3c;">{vuln_summary.get('critical', 0)}</div>
                </div>
                <div class="stat-item">
                    <div class="label">High</div>
                    <div class="value" style="color: #e67e22;">{vuln_summary.get('high', 0)}</div>
                </div>
                <div class="stat-item">
                    <div class="label">Medium</div>
                    <div class="value" style="color: #f39c12;">{vuln_summary.get('medium', 0)}</div>
                </div>
                <div class="stat-item">
                    <div class="label">Low</div>
                    <div class="value" style="color: #27ae60;">{vuln_summary.get('low', 0)}</div>
                </div>
                <div class="stat-item">
                    <div class="label">Info</div>
                    <div class="value" style="color: #3498db;">{vuln_summary.get('info', 0)}</div>
                </div>
            </div>
        </div>
"""
    
    # Add AI Report if available
    if ai_report:
        html += f"""
        <div class="section">
            <h2>🤖 AI Security Analysis</h2>
            <div class="ai-report">
                <pre style="background: transparent; color: #333; white-space: pre-wrap;">{ai_report[:2000]}...</pre>
                <p><em>Full AI report available in the markdown file.</em></p>
            </div>
        </div>
"""
    
    # Add findings by severity
    for severity, severity_findings, severity_class in [
        ("Critical", critical_findings, "critical"),
        ("High", high_findings, "high"),
        ("Medium", medium_findings, "medium"),
        ("Low", low_findings, "low"),
        ("Informational", info_findings, "info")
    ]:
        if severity_findings:
            html += f"""
        <div class="section">
            <h2><span class="severity-badge {severity_class}">{severity}</span> Risk Findings ({len(severity_findings)})</h2>
"""
            for i, finding in enumerate(severity_findings[:10], 1):  # Limit to 10 per severity
                name = finding.get('name', 'Unknown Finding')
                url = finding.get('url', target)
                description = finding.get('description', 'No description available')[:200]
                template_id = finding.get('template_id', 'N/A')
                
                html += f"""
            <div class="finding">
                <h4>{i}. {name}</h4>
                <div class="finding-detail"><strong>URL:</strong> <code>{url}</code></div>
                <div class="finding-detail"><strong>Template ID:</strong> {template_id}</div>
                <div class="finding-detail"><strong>Description:</strong> {description}...</div>
            </div>
"""
            
            if len(severity_findings) > 10:
                html += f"""
            <p><em>... and {len(severity_findings) - 10} more {severity.lower()} findings</em></p>
"""
            
            html += """
        </div>

"""
    
    # Add Technologies section
    technologies = summary.get('technologies', {}).get('items', [])
    if technologies:
        html += """
        <div class="section">
            <h2>🛠️ Technologies Identified</h2>
            <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-top: 15px;">
"""
        for tech in technologies:
            html += f"""
                <span style="background: #e1e8f0; color: #2c3e50; padding: 5px 15px; border-radius: 20px; font-weight: bold; font-size: 0.9em; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">{tech}</span>
"""
        html += """
            </div>
        </div>
"""

    # Add infrastructure info
    if context.get('network_info') or context.get('dns_info'):
        html += """
        <div class="section">
            <h2>🌐 Infrastructure Information</h2>
"""
        
        if context.get('network_info'):
            network = context['network_info']
            html += f"""
            <h3>Network Information</h3>
            <p><strong>IP Address:</strong> <code>{network.get('ip_address', 'N/A')}</code></p>
"""
            if network.get('open_ports'):
                html += "<p><strong>Open Ports:</strong></p><ul>"
                for port in network['open_ports'][:10]:
                    html += f"<li>Port {port.get('port')}: {port.get('service', 'unknown')}</li>"
                html += "</ul>"
        
        if context.get('dns_info'):
            html += "<h3>DNS Records</h3>"
            dns = context['dns_info']
            if dns.get('A'):
                html += "<p><strong>A Records:</strong></p><ul>"
                for record in dns['A'][:5]:
                    html += f"<li>{record.get('domain')} → {record.get('ip')}</li>"
                html += "</ul>"
        
        html += """
        </div>
"""
    
    # Add Screenshots section
    screenshot_dir = os.path.join(results_dir, "screenshots")
    if os.path.exists(screenshot_dir):
        screenshots = [f for f in os.listdir(screenshot_dir) if f.endswith('.png')]
        if screenshots:
            html += """
        <div class="section">
            <h2>📸 Visual Evidence (Screenshots)</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
"""
            for screenshot in screenshots[:12]: # Limit to first 12
                # We assume screenshots are in the screenshots subfolder
                # For the HTML report to be portable, ideally we'd base64 them or keep relative paths
                screenshot_rel_path = os.path.join("..", "screenshots", screenshot)
                html += f"""
                <div style="background: #f8f9fa; padding: 10px; border-radius: 8px; text-align: center;">
                    <img src="{screenshot_rel_path}" alt="{screenshot}" style="max-width: 100%; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <p style="margin-top: 5px; font-size: 0.8em; color: #7f8c8d;">{screenshot}</p>
                </div>
"""
            html += """
            </div>
        </div>
"""

    html += """
        <footer>
            <p>Generated by Vṛthā VAPT Framework</p>
            <p>© 2025 - Automated Security Assessment</p>
        </footer>
    </div>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 report_generator.py <target> <results_dir>", file=sys.stderr)
        sys.exit(1)
    
    target = sys.argv[1]
    results_dir = sys.argv[2]
    
    success = generate_html_report(target, results_dir)
    sys.exit(0 if success else 1)

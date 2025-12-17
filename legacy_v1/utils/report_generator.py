#!/usr/bin/env python3

import json
import os
import sys
import requests
from datetime import datetime
import re

def generate_report(target, results_dir, api_key):
    """Generate a comprehensive VAPT report using OpenRouter API"""
    
    # Create final report directory
    final_report_dir = os.path.join(results_dir, "final_report")
    os.makedirs(final_report_dir, exist_ok=True)
    
    # Load optimized context
    context_file = os.path.join(results_dir, "context", f"vapt_{target}_optimized_context.json")
    
    if not os.path.exists(context_file):
        print(f"Error: Context file not found at {context_file}")
        return
    
    with open(context_file, 'r') as f:
        context = json.load(f)
    
    # Load CVSS scoring matrix
    cvss_file = os.path.join("config", "cvss-scoring.json")
    cvss_matrix = {}
    if os.path.exists(cvss_file):
        with open(cvss_file, 'r') as f:
            cvss_matrix = json.load(f)
    
    # Load CWE mapping
    cwe_file = os.path.join("config", "cwe-mapping.json")
    cwe_mapping = {}
    if os.path.exists(cwe_file):
        with open(cwe_file, 'r') as f:
            cwe_mapping = json.load(f)
    
    # Prepare prompt for OpenRouter
    with open("config/openrouter-prompts.txt", 'r') as f:
        prompts = f.read()
    
    report_prompt = prompts.split("REPORT_GENERATION_PROMPT")[1].strip() if "REPORT_GENERATION_PROMPT" in prompts else """
    Analyze the following WordPress VAPT scan results and generate a comprehensive security report.
    
    The report should include:
    1. Executive Summary - A high-level overview of the security posture
    2. Vulnerability Summary - A count of findings by severity level
    3. Detailed Findings - Each finding should include:
       - Severity (based on CVSS)
       - CVSS Vector (AV, AC, S, PR, N, UI, C, I, A)
       - CWE ID
       - Affected Asset
       - Description
       - Risk
       - Proof of Concept
       - Remediation
    
    Format the report in Markdown with clear sections and subsections.
    """
    
    # Create JSON payload for OpenRouter API
    payload = {
        "model": "gpt-4",  # or your preferred model
        "messages": [
            {
                "role": "system",
                "content": report_prompt
            },
            {
                "role": "user",
                "content": f"Target: {target}\n\nScan Results:\n{json.dumps(context, indent=2)}"
            }
        ]
    }
    
    # Send request to OpenRouter API
    print("Sending optimized context to OpenRouter for analysis...")
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        json=payload
    )
    
    if response.status_code == 200:
        # Extract and save the report
        report_content = response.json()["choices"][0]["message"]["content"]
        
        # Process the report to ensure it follows our desired format
        processed_report = process_report_format(report_content, context, cvss_matrix, cwe_mapping)
        
        # Save as Markdown
        with open(os.path.join(final_report_dir, f"vapt_{target}_report.md"), 'w') as f:
            f.write(processed_report)
        
        # Convert to HTML
        html_report = markdown_to_html(processed_report)
        with open(os.path.join(final_report_dir, f"vapt_{target}_report.html"), 'w') as f:
            f.write(html_report)
        
        print(f"Report generated successfully and saved in {final_report_dir}")
    else:
        print(f"Error generating report: {response.status_code} - {response.text}")
        
        # Save raw context as a fallback
        with open(os.path.join(final_report_dir, f"vapt_{target}_raw_context.txt"), 'w') as f:
            f.write(json.dumps(context, indent=2))
        
        print("Raw context saved as a fallback.")

def process_report_format(report_content, context, cvss_matrix, cwe_mapping):
    """Process the report content to ensure it follows our desired format"""
    
    # Initialize the processed report
    processed_report = f"# WordPress VAPT Report for {context['target']}\n\n"
    processed_report += f"**Scan Date:** {context['scan_date']}\n\n"
    
    # Add vulnerability summary
    vuln_summary = context['summary']['vulnerabilities']
    total_findings = sum(vuln_summary.values())
    
    processed_report += "## Vulnerability Summary\n\n"
    processed_report += f"A total of {total_findings} findings were identified during the engagement. These included:\n\n"
    processed_report += f"* {vuln_summary['critical']} Critical-risk\n"
    processed_report += f"* {vuln_summary['high']} High-risk\n"
    processed_report += f"* {vuln_summary['medium']} Medium-risk\n"
    processed_report += f"* {vuln_summary['low']} Low-risk\n"
    processed_report += f"* {vuln_summary['info']} Informational issues\n\n"
    
    # Add executive summary from OpenRouter
    exec_summary_match = re.search(r'## Executive Summary\s*\n(.*?)(?=##|\Z)', report_content, re.DOTALL)
    if exec_summary_match:
        processed_report += "## Executive Summary\n\n"
        processed_report += exec_summary_match.group(1).strip() + "\n\n"
    
    # Add detailed findings
    processed_report += "## Detailed Findings\n\n"
    
    # Process findings from context
    findings = context.get('detailed_findings', [])
    
    # Group findings by severity
    critical_findings = [f for f in findings if f.get('severity', '').lower() == 'critical']
    high_findings = [f for f in findings if f.get('severity', '').lower() == 'high']
    medium_findings = [f for f in findings if f.get('severity', '').lower() == 'medium']
    low_findings = [f for f in findings if f.get('severity', '').lower() == 'low']
    info_findings = [f for f in findings if f.get('severity', '').lower() == 'info']
    
    # Add findings by severity
    for severity, severity_findings in [
        ("Critical", critical_findings),
        ("High", high_findings),
        ("Medium", medium_findings),
        ("Low", low_findings),
        ("Informational", info_findings)
    ]:
        if severity_findings:
            processed_report += f"### {severity} Risk Findings\n\n"
            
            for i, finding in enumerate(severity_findings, 1):
                processed_report += f"#### {i}. {finding.get('name', 'Unknown Finding')}\n\n"
                
                # Add CVSS and CWE information
                finding_type = finding.get('type', '')
                template_id = finding.get('template_id', '')
                
                # Determine CVSS vector
                cvss_vector = determine_cvss_vector(finding, cvss_matrix)
                processed_report += f"**Severity:** {severity}\n\n"
                processed_report += f"**CVSS Vector:** {cvss_vector}\n\n"
                
                # Determine CWE
                cwe_id = determine_cwe_id(finding, cwe_mapping)
                processed_report += f"**CWE:** {cwe_id}\n\n"
                
                # Add affected asset
                processed_report += f"**Affected Asset:** {finding.get('url', context['target'])}\n\n"
                
                # Add description
                description = finding.get('description', '')
                if description:
                    processed_report += f"**Description:**\n{description}\n\n"
                
                # Add risk
                processed_report += f"**Risk:**\n"
                if severity.lower() == 'critical':
                    processed_report += "This vulnerability poses a critical risk to the application and could lead to complete system compromise, data theft, or service disruption.\n\n"
                elif severity.lower() == 'high':
                    processed_report += "This vulnerability poses a high risk to the application and could lead to significant data exposure, privilege escalation, or partial system compromise.\n\n"
                elif severity.lower() == 'medium':
                    processed_report += "This vulnerability poses a medium risk to the application and could lead to limited data exposure or minor system impact.\n\n"
                elif severity.lower() == 'low':
                    processed_report += "This vulnerability poses a low risk to the application but should be addressed as part of a comprehensive security strategy.\n\n"
                else:
                    processed_report += "This finding provides information about the application's security posture but does not represent an immediate risk.\n\n"
                
                # Add proof of concept
                poc = generate_proof_of_concept(finding)
                if poc:
                    processed_report += f"**Proof of Concept:**\n```\n{poc}\n```\n\n"
                
                # Add remediation
                remediation = generate_remediation(finding)
                if remediation:
                    processed_report += f"**Remediation:**\n{remediation}\n\n"
                
                processed_report += "---\n\n"
    
    # Add additional sections from OpenRouter if available
    additional_sections = re.findall(r'## (.*?)\s*\n(.*?)(?=##|\Z)', report_content, re.DOTALL)
    for section_title, section_content in additional_sections:
        if section_title not in ["Executive Summary", "Detailed Findings"]:
            processed_report += f"## {section_title}\n\n"
            processed_report += section_content.strip() + "\n\n"
    
    return processed_report

def determine_cvss_vector(finding, cvss_matrix):
    """Determine CVSS vector for a finding"""
    
    # Default CVSS vector
    default_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    # Try to determine CVSS based on finding type and severity
    finding_type = finding.get('type', '')
    severity = finding.get('severity', '').lower()
    
    # Check if we have a specific CVSS vector for this type of finding
    if finding_type in cvss_matrix:
        type_matrix = cvss_matrix[finding_type]
        if severity in type_matrix:
            return type_matrix[severity]
    
    # Return default vector
    return default_vector

def determine_cwe_id(finding, cwe_mapping):
    """Determine CWE ID for a finding"""
    
    # Default CWE ID
    default_cwe = "CWE-16: Configuration"
    
    # Try to determine CWE based on finding type and tags
    finding_type = finding.get('type', '')
    tags = finding.get('tags', [])
    
    # Check if we have a specific CWE mapping for this type of finding
    if finding_type in cwe_mapping:
        type_mapping = cwe_mapping[finding_type]
        
        # Try to match by tags
        for tag in tags:
            if tag in type_mapping:
                return type_mapping[tag]
        
        # Return default for this type if available
        if 'default' in type_mapping:
            return type_mapping['default']
    
    # Return default CWE
    return default_cwe

def generate_proof_of_concept(finding):
    """Generate a proof of concept for a finding"""
    
    finding_type = finding.get('type', '')
    url = finding.get('url', '')
    
    if finding_type == 'nuclei':
        # For Nuclei findings, use the matched URL
        return f"Vulnerability confirmed at: {url}"
    
    elif finding_type == 'wordpress':
        # For WordPress findings, use the description
        return finding.get('description', 'No specific proof of concept available')
    
    elif finding_type.startswith('httpx'):
        # For httpx findings, provide a specific example
        if finding_type == 'httpx_custom_matchers':
            return f"Custom matcher triggered at: {url}\nMatched pattern: {finding.get('details', {}).get('matched_pattern', 'Unknown')}"
        elif finding_type == 'httpx_path_probing':
            return f"Discovered path at: {url}\nPath: {finding.get('details', {}).get('discovered_path', 'Unknown')}"
        elif finding_type == 'httpx_method_discovery':
            return f"Multiple HTTP methods allowed at: {url}\nAllowed methods: {', '.join(finding.get('details', {}).get('allowed_methods', []))}"
    
    return "No specific proof of concept available"

def generate_remediation(finding):
    """Generate remediation advice for a finding"""
    
    finding_type = finding.get('type', '')
    tags = finding.get('tags', [])
    
    # General remediation advice based on finding type
    if finding_type == 'nuclei':
        if 'xss' in tags:
            return """
1. Implement proper input validation and output encoding
2. Use Content Security Policy (CSP) headers
3. Sanitize user input before displaying it
4. Use modern web frameworks that provide built-in XSS protection
5. Regularly update all third-party libraries and dependencies
"""
        elif 'sqli' in tags:
            return """
6. Use parameterized queries or prepared statements
7. Implement proper input validation
8. Apply the principle of least privilege to database accounts
9. Use web application firewalls (WAF) for additional protection
10. Regularly update and patch database management systems
"""
        elif 'csrf' in tags:
            return """
11. Implement anti-CSRF tokens
12. Use SameSite cookie attribute
13. Verify the origin header with strict pattern matching
14. Use double submit cookie pattern
15. Implement user interaction-based authentication for state-changing operations
"""
        elif 'lfi' in tags or 'rfi' in tags:
            return """
16. Disable file inclusion features when not needed
17. Implement strict input validation
18. Use whitelisting approach for allowed files
19. Implement proper access controls
20. Avoid using user input directly in file inclusion functions
"""
        elif 'rce' in tags:
            return """
21. Avoid using eval() and similar functions with user input
22. Implement strict input validation
23. Use allowlist approach for allowed commands
24. Apply the principle of least privilege
25. Implement proper sandboxing for untrusted code execution
"""
    
    elif finding_type == 'wordpress':
        return """
26. Update WordPress core, themes, and plugins to the latest versions
27. Remove unused themes and plugins
28. Implement strong password policies
29. Enable two-factor authentication
30. Regularly backup your WordPress site
31. Use a reputable security plugin
32. Implement proper file permissions
33. Disable XML-RPC if not needed
34. Limit login attempts
35. Hide WordPress version number
"""
    
    elif finding_type.startswith('httpx'):
        if finding_type == 'httpx_custom_matchers':
            return """
36. Review and secure the exposed endpoint
37. Implement proper access controls
38. Remove sensitive information from public access
39. Use authentication and authorization mechanisms
40. Regularly audit your web application for exposed sensitive endpoints
"""
        elif finding_type == 'httpx_path_probing':
            return """
41. Review the discovered path for security implications
42. Implement proper access controls if needed
43. Remove or secure sensitive directories
44. Use robots.txt to disallow crawling of sensitive paths
45. Regularly audit your web application for exposed paths
"""
        elif finding_type == 'httpx_method_discovery':
            return """
46. Disable HTTP methods that are not needed
47. Implement proper access controls for sensitive methods
48. Use method-specific authentication and authorization
49. Regularly audit allowed HTTP methods
50. Consider using a web application firewall (WAF) for additional protection
"""
    
    # Default remediation advice
    return """
51. Regularly update and patch all software components
52. Implement proper input validation and output encoding
53. Use the principle of least privilege
54. Implement proper access controls
55. Regularly audit your application for security vulnerabilities
56. Use a web application firewall (WAF) for additional protection
57. Conduct regular security assessments and penetration testing
"""

def markdown_to_html(markdown_text):
    """Convert Markdown to HTML with basic styling"""
    
    # Import markdown library if available
    try:
        import markdown
        md = markdown.Markdown(extensions=['tables', 'fenced_code'])
        html = md.convert(markdown_text)
    except ImportError:
        # Basic Markdown to HTML conversion if markdown library is not available
        html = markdown_text
        html = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        html = re.sub(r'^#### (.*?)$', r'<h4>\1</h4>', html, flags=re.MULTILINE)
        html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
        html = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html)
        html = re.sub(r'```(.*?)```', r'<pre><code>\1</code></pre>', html, flags=re.DOTALL)
        html = re.sub(r'`(.*?)`', r'<code>\1</code>', html)
        html = re.sub(r'^\* (.*?)$', r'<li>\1</li>', html, flags=re.MULTILINE)
        html = re.sub(r'(<li>.*?</li>)', r'<ul>\1</ul>', html, flags=re.DOTALL)
        html = re.sub(r'\n\n', '</p><p>', html)
        html = '<p>' + html + '</p>'
    
    # Add CSS styling
    styled_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>WordPress VAPT Report</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                margin: 40px; 
                line-height: 1.6;
                color: #333;
            }}
            h1 {{ 
                color: #2c3e50; 
                border-bottom: 2px solid #3498db; 
                padding-bottom: 10px; 
            }}
            h2 {{ 
                color: #3498db; 
                border-bottom: 1px solid #bdc3c7;
                padding-bottom: 5px;
            }}
            h3 {{ 
                color: #2980b9; 
            }}
            h4 {{ 
                color: #2980b9;
                margin-top: 25px;
            }}
            .critical {{ color: #e74c3c; font-weight: bold; }}
            .high {{ color: #e67e22; font-weight: bold; }}
            .medium {{ color: #f39c12; font-weight: bold; }}
            .low {{ color: #27ae60; font-weight: bold; }}
            .info {{ color: #3498db; font-weight: bold; }}
            table {{ 
                border-collapse: collapse; 
                width: 100%; 
                margin: 20px 0;
            }}
            th, td {{ 
                border: 1px solid #ddd; 
                padding: 12px; 
                text-align: left; 
            }}
            th {{ 
                background-color: #f2f2f2; 
                font-weight: bold;
            }}
            pre {{ 
                background-color: #f8f9fa; 
                padding: 15px; 
                border-radius: 5px;
                overflow-x: auto;
                border-left: 4px solid #3498db;
            }}
            code {{ 
                background-color: #f8f9fa; 
                padding: 2px 4px; 
                border-radius: 3px;
                font-family: 'Courier New', Courier, monospace;
            }}
            blockquote {{
                border-left: 4px solid #3498db;
                padding-left: 20px;
                margin: 20px 0;
                font-style: italic;
                color: #7f8c8d;
            }}
            hr {{
                border: none;
                height: 1px;
                background-color: #bdc3c7;
                margin: 30px 0;
            }}
        </style>
    </head>
    <body>
        {html}
    </body>
    </html>
    """
    
    return styled_html

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 report_generator.py <target> <results_dir> <api_key>")
        sys.exit(1)
    
    target = sys.argv[1]
    results_dir = sys.argv[2]
    api_key = sys.argv[3]
    
    generate_report(target, results_dir, api_key)

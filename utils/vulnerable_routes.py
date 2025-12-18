#!/usr/bin/env python3
"""
Vulnerable Route Analyzer
Identifies potentially vulnerable endpoints based on URL patterns and parameters
"""

import re
import sys
import json
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

class VulnerableRouteAnalyzer:
    def __init__(self):
        # IDOR patterns - numeric IDs in paths or parameters
        self.idor_patterns = {
            'path_numeric_id': r'/(\d{1,10})(?:/|$)',  # /users/123/profile
            'param_id': r'[?&](id|user_id|account_id|invoice_id|order_id|profile_id|doc_id)=(\d+)',
            'param_uuid': r'[?&]\w+_id=([a-f0-9-]{36})',  # UUID patterns
        }
        
        # SQL Injection indicators
        self.sqli_params = [
            'id', 'user', 'username', 'email', 'search', 'q', 'query', 'keyword',
            'category', 'cat', 'tag', 'sort', 'order', 'filter', 'page', 'limit',
            'author', 'author_id', 'post_id', 'article_id', 'product_id'
        ]
        
        # Path Traversal indicators
        self.path_traversal_params = [
            'file', 'filename', 'path', 'filepath', 'document', 'doc', 'page',
            'template', 'include', 'dir', 'folder', 'download', 'upload', 'view',
            'read', 'load', 'img', 'image', 'avatar', 'attachment'
        ]
        
        # SSRF indicators
        self.ssrf_params = [
            'url', 'uri', 'link', 'src', 'source', 'target', 'dest', 'destination',
            'redirect', 'return', 'next', 'callback', 'webhook', 'proxy', 'fetch',
            'download_url', 'image_url', 'target_url', 'external_url', 'remote'
        ]
        
        # XSS reflection indicators
        self.xss_params = [
            'q', 'search', 'query', 'keyword', 'name', 'title', 'msg', 'message',
            'error', 'success', 'alert', 'comment', 'text', 'description', 'bio',
            'status', 'reason', 'note', 'label', 'tag', 'category'
        ]
        
        # Sensitive endpoints
        self.sensitive_paths = [
            '/admin', '/api', '/v1', '/v2', '/v3', '/dashboard', '/panel',
            '/account', '/profile', '/user', '/users', '/settings', '/config',
            '/download', '/upload', '/delete', '/edit', '/update', '/create',
            '/invoice', '/payment', '/order', '/transaction', '/backup'
        ]

    def analyze_url(self, url):
        """Analyze a single URL for vulnerabilities"""
        parsed = urlparse(url)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        findings = []
        
        # Check for IDOR
        idor_findings = self._check_idor(url, path, params)
        findings.extend(idor_findings)
        
        # Check for SQL Injection
        sqli_findings = self._check_sqli(url, params)
        findings.extend(sqli_findings)
        
        # Check for Path Traversal
        path_traversal_findings = self._check_path_traversal(url, params)
        findings.extend(path_traversal_findings)
        
        # Check for SSRF
        ssrf_findings = self._check_ssrf(url, params)
        findings.extend(ssrf_findings)
        
        # Check for XSS
        xss_findings = self._check_xss(url, params)
        findings.extend(xss_findings)
        
        return findings

    def _check_idor(self, url, path, params):
        """Check for Insecure Direct Object References"""
        findings = []
        
        # Check path for numeric IDs
        if re.search(self.idor_patterns['path_numeric_id'], path):
            findings.append({
                'url': url,
                'vulnerability': 'IDOR',
                'severity': 'HIGH',
                'confidence': 'MEDIUM',
                'description': 'URL contains numeric ID in path - potential IDOR vulnerability',
                'exploitation': 'Try incrementing/decrementing the ID to access other resources',
                'example_payload': path.replace(re.search(r'/(\d+)', path).group(1), str(int(re.search(r'/(\d+)', path).group(1)) + 1)) if re.search(r'/(\d+)', path) else None
            })
        
        # Check parameters for IDs
        for param, values in params.items():
            if any(id_param in param.lower() for id_param in ['id', 'user', 'account', 'invoice', 'order']):
                if values and values[0].isdigit():
                    findings.append({
                        'url': url,
                        'vulnerability': 'IDOR',
                        'severity': 'HIGH',
                        'confidence': 'MEDIUM',
                        'parameter': param,
                        'value': values[0],
                        'description': f'Parameter "{param}" contains numeric ID - potential IDOR',
                        'exploitation': f'Modify {param} value to access other users\' data',
                        'example_payload': f'{param}={int(values[0]) + 1}'
                    })
        
        return findings

    def _check_sqli(self, url, params):
        """Check for SQL Injection potential"""
        findings = []
        
        for param, values in params.items():
            if param.lower() in self.sqli_params or any(sqli in param.lower() for sqli in ['id', 'search', 'query', 'filter']):
                findings.append({
                    'url': url,
                    'vulnerability': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'confidence': 'LOW',
                    'parameter': param,
                    'description': f'Parameter "{param}" may be vulnerable to SQL injection',
                    'exploitation': 'Database enumeration, authentication bypass, data exfiltration',
                    'example_payloads': [
                        f"{param}=' OR '1'='1",
                        f"{param}=1 UNION SELECT NULL--",
                        f"{param}=1' AND '1'='1",
                        f"{param}=1; DROP TABLE users--"
                    ]
                })
        
        return findings

    def _check_path_traversal(self, url, params):
        """Check for Path Traversal vulnerabilities"""
        findings = []
        
        for param, values in params.items():
            if param.lower() in self.path_traversal_params:
                findings.append({
                    'url': url,
                    'vulnerability': 'Path Traversal',
                    'severity': 'HIGH',
                    'confidence': 'MEDIUM',
                    'parameter': param,
                    'value': values[0] if values else '',
                    'description': f'Parameter "{param}" may allow directory traversal',
                    'exploitation': 'Access sensitive files like /etc/passwd, config files, source code',
                    'example_payloads': [
                        f'{param}=../../../../etc/passwd',
                        f'{param}=../../config/database.yml',
                        f'{param}=../../../.env',
                        f'{param}=....//....//....//etc/passwd'
                    ]
                })
        
        return findings

    def _check_ssrf(self, url, params):
        """Check for Server-Side Request Forgery"""
        findings = []
        
        for param, values in params.items():
            if param.lower() in self.ssrf_params:
                findings.append({
                    'url': url,
                    'vulnerability': 'SSRF',
                    'severity': 'CRITICAL',
                    'confidence': 'MEDIUM',
                    'parameter': param,
                    'description': f'Parameter "{param}" accepts URLs - potential SSRF',
                    'exploitation': 'Access internal services, cloud metadata, bypass firewalls',
                    'example_payloads': [
                        f'{param}=http://169.254.169.254/latest/meta-data/',  # AWS metadata
                        f'{param}=http://localhost:80',
                        f'{param}=http://192.168.1.1',
                        f'{param}=file:///etc/passwd'
                    ]
                })
        
        return findings

    def _check_xss(self, url, params):
        """Check for Cross-Site Scripting potential"""
        findings = []
        
        for param, values in params.items():
            if param.lower() in self.xss_params:
                findings.append({
                    'url': url,
                    'vulnerability': 'XSS',
                    'severity': 'MEDIUM',
                    'confidence': 'LOW',
                    'parameter': param,
                    'description': f'Parameter "{param}" may reflect user input - potential XSS',
                    'exploitation': 'Session hijacking, keylogging, phishing, defacement',
                    'example_payloads': [
                        f'{param}=<script>alert(1)</script>',
                        f'{param}=<img src=x onerror=alert(1)>',
                        f'{param}=<svg onload=alert(1)>',
                        f'{param}=javascript:alert(document.cookie)'
                    ]
                })
        
        return findings

    def analyze_urls_from_file(self, filepath):
        """Analyze all URLs from a file"""
        all_findings = defaultdict(list)
        
        with open(filepath, 'r') as f:
            urls = [line.strip() for line in f if line.strip().startswith('http')]
        
        for url in urls:
            findings = self.analyze_url(url)
            for finding in findings:
                vuln_type = finding['vulnerability']
                all_findings[vuln_type].append(finding)
        
        return all_findings

    def generate_report(self, findings, output_file):
        """Generate a detailed report"""
        report = {
            'summary': {
                'total_vulnerabilities': sum(len(v) for v in findings.values()),
                'by_type': {k: len(v) for k, v in findings.items()},
                'severity_breakdown': self._get_severity_breakdown(findings)
            },
            'findings': findings
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also create human-readable report
        txt_output = output_file.replace('.json', '.txt')
        with open(txt_output, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("VULNERABLE ROUTE ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Total Potential Vulnerabilities: {report['summary']['total_vulnerabilities']}\n\n")
            
            for vuln_type, count in report['summary']['by_type'].items():
                f.write(f"  {vuln_type}: {count}\n")
            
            f.write("\n" + "=" * 80 + "\n\n")
            
            for vuln_type, vuln_findings in findings.items():
                if vuln_findings:
                    f.write(f"\n{'#' * 80}\n")
                    f.write(f"# {vuln_type.upper()} VULNERABILITIES ({len(vuln_findings)})\n")
                    f.write(f"{'#' * 80}\n\n")
                    
                    for i, finding in enumerate(vuln_findings[:20], 1):  # Limit to top 20 per type
                        f.write(f"\n[{i}] {finding['url']}\n")
                        f.write(f"    Severity: {finding['severity']}\n")
                        f.write(f"    Confidence: {finding['confidence']}\n")
                        f.write(f"    Description: {finding['description']}\n")
                        f.write(f"    Exploitation: {finding['exploitation']}\n")
                        
                        if 'example_payloads' in finding:
                            f.write(f"    Example Payloads:\n")
                            for payload in finding['example_payloads'][:3]:
                                f.write(f"      - {payload}\n")
                        elif 'example_payload' in finding and finding['example_payload']:
                            f.write(f"    Example: {finding['example_payload']}\n")
                        
                        f.write("\n" + "-" * 80 + "\n")
                    
                    if len(vuln_findings) > 20:
                        f.write(f"\n... and {len(vuln_findings) - 20} more {vuln_type} findings\n")

    def _get_severity_breakdown(self, findings):
        """Get count by severity"""
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln_findings in findings.values():
            for finding in vuln_findings:
                severity_count[finding['severity']] += 1
        return severity_count

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 vulnerable_routes.py <url_file> <output_file>", file=sys.stderr)
        sys.exit(1)
    
    url_file = sys.argv[1]
    output_file = sys.argv[2]
    
    print(f"[*] Analyzing URLs from {url_file}...", file=sys.stderr)
    
    analyzer = VulnerableRouteAnalyzer()
    findings = analyzer.analyze_urls_from_file(url_file)
    
    print(f"[+] Found {sum(len(v) for v in findings.values())} potential vulnerabilities", file=sys.stderr)
    
    analyzer.generate_report(findings, output_file)
    
    print(f"[+] Report saved to {output_file}", file=sys.stderr)
    print(f"[+] Human-readable report: {output_file.replace('.json', '.txt')}", file=sys.stderr)

if __name__ == "__main__":
    main()

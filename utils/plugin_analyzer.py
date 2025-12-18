#!/usr/bin/env python3
import os
import re
import json
import argparse

# WordPress SAST Patterns
SINKS = {
    "RCE: Dangerous Functions": {
        "pattern": r"(?:eval|shell_exec|exec|system|passthru|proc_open|popen)\s*\(",
        "description": "Direct execution of code or system commands."
    },
    "Object Injection: Unserialize": {
        "pattern": r"(?:unserialize)\s*\(",
        "description": "Potentially insecure deserialization of user input."
    },
    "SQLi: Prepared Statement Misuse": {
        "pattern": r"\$wpdb->(?:get_results|get_row|get_var|query|execute)\s*\(\s*['\"].*?\$",
        "description": "Variables directly concatenated into SQL queries."
    },
    "XSS: Raw Output": {
        "pattern": r"(?:echo|print)\s+[^;]*?\$(?:_GET|_POST|_REQUEST|_REQUEST|ref|url)\b",
        "description": "Unescaped output of superglobal variables."
    },
    "Auth Bypass: Improper Nonce Check": {
        "pattern": r"add_action\s*\(\s*['\"]wp_ajax_",
        "missing": r"check_ajax_referer|check_admin_referer",
        "description": "AJAX action potentially missing nonce verification."
    },
    "File Upload: Insecure Check": {
        "pattern": r"move_uploaded_file\s*\(",
        "description": "Manual file upload handling without WP security wrappers."
    },
    "LFI: Directory Traversal": {
        "pattern": r"(?:include|require|include_once|require_once)\s*\(\s*[^;]*?\$(?:_GET|_POST|_REQUEST)",
        "description": "Including files based on user-controlled inputs."
    }
}

JS_SINKS = {
    "DOM XSS: innerHTML": {
        "pattern": r"\.innerHTML\s*=",
        "description": "Insecure DOM modification via innerHTML."
    },
    "DOM XSS: document.write": {
        "pattern": r"document\.write\s*\(",
        "description": "Direct write to document via document.write()."
    },
    "DOM XSS: Eval-like sinks": {
        "pattern": r"(?:eval|setTimeout|setInterval)\s*\(\s*[^'\"].*?\b(?:location|url|search|hash|cookie)\b",
        "description": "Evaluation of content derived from potentially untrusted URL or cookie data."
    }
}

class PluginAnalyzer:
    def __init__(self, directory):
        self.directory = directory
        self.findings = []

    def analyze(self):
        if not os.path.isdir(self.directory):
            return {"error": f"Not a directory: {self.directory}"}

        for root, _, files in os.walk(self.directory):
            for file in files:
                if file.endswith('.php'):
                    filepath = os.path.join(root, file)
                    self.analyze_file(filepath, SINKS)
                elif file.endswith('.js'):
                    filepath = os.path.join(root, file)
                    self.analyze_file(filepath, JS_SINKS)
        
        return self.findings

    def analyze_file(self, filepath, sink_dict):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                content = "".join(lines)
                
                for category, data in sink_dict.items():
                    pattern = data["pattern"]
                    matches = re.finditer(pattern, content)
                    
                    for match in matches:
                        line_no = content.count('\n', 0, match.start()) + 1
                        snippet = content[max(0, match.start()-40):min(len(content), match.end()+40)].strip()
                        
                        # Special check for "missing" patterns (like nonces)
                        if "missing" in data:
                            # Search the whole file for the required check
                            if not re.search(data["missing"], content):
                                self.findings.append({
                                    "category": category,
                                    "file": os.path.relpath(filepath, self.directory),
                                    "line": line_no,
                                    "snippet": snippet,
                                    "severity": "Medium",
                                    "description": f"{data['description']} (Required check '{data['missing']}' not found in file)"
                                })
                        else:
                            self.findings.append({
                                "category": category,
                                "file": os.path.relpath(filepath, self.directory),
                                "line": line_no,
                                "snippet": snippet,
                                "severity": "High" if "RCE" in category or "SQLi" in category else "Medium",
                                "description": data["description"]
                            })
                            
        except Exception as e:
            pass

def main():
    parser = argparse.ArgumentParser(description="WordPress Plugin Static Analysis Tool")
    parser.add_argument("directory", help="Directory of the plugin to analyze")
    parser.add_argument("--output", help="Save findings to JSON file")
    args = parser.parse_args()

    analyzer = PluginAnalyzer(args.directory)
    findings = analyzer.analyze()

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=4)
        print(f"[+] SAST Results saved to {args.output}")
    else:
        print(json.dumps(findings, indent=4))

if __name__ == "__main__":
    main()

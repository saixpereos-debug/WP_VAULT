import sys
import re
import os
import json
import subprocess

def parse_wpscan_log(logfile):
    """
    Parses wpscan output to extract plugins and versions.
    Expected format sections:
    [+] plugin-name
     | Version: 1.2.3
    """
    plugins = {}
    current_plugin = None
    
    try:
        with open(logfile, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line in lines:
            # Match plugin name
            # [i] Plugin(s) Identified:
            # [+] akismet
            plugin_match = re.search(r'\[\+\]\s+([a-z0-9\-_]+)', line)
            if plugin_match:
                current_plugin = plugin_match.group(1)
                if current_plugin not in plugins:
                    plugins[current_plugin] = "Unknown"
                continue
            
            # Match version
            #  | Version: 5.3 (100% confidence)
            if current_plugin:
                version_match = re.search(r'\|\s+Version:\s+([0-9\.]+)', line)
                if version_match:
                    plugins[current_plugin] = version_match.group(1)
                    current_plugin = None # Reset to avoid attaching version to wrong item
                    
    except Exception as e:
        print(f"Error parsing log: {e}")
        return {}

    return plugins

def query_ai(plugins):
    """
    Queries the configured AI via sec_ai module.
    """
    if not plugins:
        return "No plugins found to analyze."

    # Construct prompt
    plugin_list_str = "\n".join([f"- {p}: {v}" for p, v in plugins.items()])
    prompt = f"""
You are a Vulnerability Assessment Expert. Analyze the following WordPress plugins and their versions for known vulnerabilities.
Results:
{plugin_list_str}

Task:
1. For each plugin, check if the specific version is vulnerable to known CVEs or exploits.
2. Provide a summary of the vulnerability (SQLi, XSS, RCE, etc.).
3. Provide a link to ExploitDB or a CVE reference if available.
4. If the version is "Unknown", mention that verification is needed.
5. Prioritize "Critical" and "High" severity issues.

Format the output as a Markdown table with columns: Plugin, Version, Severity, Vulnerability, Reference.
"""
    
    # We need to call the sec_ai CLI. 
    # Assuming config is loaded in environment or we can't easily access the python CLI directly without path.
    # The caller script should handle the AI call if we print the prompt? 
    # Or better, we just execute the sec_ai/main.py if we know where it is.
    # We will print the prompt to stdout if --prompt-only is set, or try to run.
    
    return prompt

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 wp_plugin_audit.py <wpscan_output_file> [--ai]")
        sys.exit(1)

    logfile = sys.argv[1]
    use_ai = "--ai" in sys.argv
    
    plugins = parse_wpscan_log(logfile)
    
    if not plugins:
        # Fallback: check if we can grep plugins from URLs?
        # For now just exit
        print("[-] No plugins detected in WPScan output.")
        sys.exit(0)
        
    print(f"[+] Identified {len(plugins)} plugins.")
    for p, v in plugins.items():
        print(f"    - {p} (Version: {v})")

    if use_ai:
        # Check for API key in env
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
             print("[!] OPENROUTER_API_KEY not set. Skipping AI analysis.")
             return

        # Setup path to import sec_ai
        sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
        try:
            from sec_ai.api_client import OpenRouterClient
            model = os.environ.get("OPENROUTER_MODEL", "qwen/qwen-2.5-coder-32b-instruct")
            client = OpenRouterClient(api_key, model)
            
            print("[-] Asking AI for vulnerability assessment...")
            # We use a system prompt for context
            system_prompt = "You are an expert Security Researcher and VAPT specialist."
            response = client.chat_completion(query_ai(plugins), system_prompt=system_prompt)
            
            print("\n[+] AI Vulnerability Assessment:\n")
            print(response)
            
            # Save to file
            output_file = logfile.replace(".txt", "_ai_assessment.md")
            with open(output_file, "w") as f:
                f.write(response)
            print(f"\n[+] Assessment saved to: {output_file}")
            
        except ImportError:
            print("[!] Could not import OpenRouterClient. Make sure sec_ai module is accessible.")
        except Exception as e:
            print(f"[!] AI Analysis failed: {e}")

if __name__ == "__main__":
    main()

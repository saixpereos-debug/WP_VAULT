#!/usr/bin/env python3
import argparse
import os
import sys
try:
    from sec_ai.api_client import OpenRouterClient
    from sec_ai.prompts import CONNECTIVITY_PROMPT
    from sec_ai.report_writer import generate_pdf_report
except ImportError:
    # Fallback for when running script directly from within directory or if package structure differs
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from sec_ai.api_client import OpenRouterClient
        from sec_ai.prompts import CONNECTIVITY_PROMPT
        from sec_ai.report_writer import generate_pdf_report
    except ImportError:
         from api_client import OpenRouterClient
         from prompts import CONNECTIVITY_PROMPT
         from report_writer import generate_pdf_report

def load_config():
    # In a real scenario, we might parse config.sh or use environment variables passed from bash.
    # For now, we expect environment variables to be set by the caller (main.sh).
    api_key = os.environ.get("OPENROUTER_API_KEY")
    model = os.environ.get("OPENROUTER_MODEL", "qwen/qwen-2.5-coder-32b-instruct")
    
    if not api_key:
        print("Error: OPENROUTER_API_KEY environment variable not set.")
        sys.exit(1)
        
    return api_key, model

def command_check(client):
    print("[-] Testing OpenRouter API connectivity...")
    response = client.chat_completion(CONNECTIVITY_PROMPT, system_prompt="You are a helper.")
    
    if "Connection successful" in response or "Test" in response or len(response) > 0:
         # We accept any valid non-error response for now, but looking for specific phrasing is better if we enforced it.
         # The prompt asks for "Connection successful.", so let's check for that or basic success.
         if "Error" in response:
             print(f"[!] Connectivity Check Failed: {response}")
             sys.exit(1)
         else:
             print(f"[+] Connection Successful. Model: {client.model}")
             print(f"[>] Response: {response.strip()}")
             sys.exit(0)
    else:
        print("[!] No response received.")
        sys.exit(1)

def command_analyze(client, args):
    """
    Analyzes scan results and generates a report.
    """
    from sec_ai.results_parser import get_scan_context
    from sec_ai.prompts import ANALYSIS_PROMPT_TEMPLATE
    
    input_dir = args.input
    output_file = args.output
    
    print(f"[-] Parsing scan results from: {input_dir}")
    if not os.path.exists(input_dir):
        print(f"[!] Input directory not found: {input_dir}")
        sys.exit(1)
        
    # Aggregate data
    scan_context = get_scan_context(input_dir)
    
    # Construct prompt
    import datetime
    target_name = os.path.basename(input_dir).split('_')[0]
    current_date = datetime.date.today().strftime("%B %d, %Y")
    
    final_prompt = ANALYSIS_PROMPT_TEMPLATE.format(
        target_name=target_name,
        date=current_date,
        context=f"Target Scan Results for directory: {input_dir}",
        scan_data=scan_context
    )
    
    print("[-] Sending data to OpenRouter (this may take a minute)...")
    analysis = client.chat_completion(final_prompt)
    
    print(f"[-] Saving report to: {output_file}")
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(analysis)
        print(f"[+] Report generated successfully: {output_file}")
        
        # If PDF format requested
        if args.format == "pdf":
            pdf_output = output_file.replace(".md", ".pdf")
            print(f"[-] Converting to professional PDF: {pdf_output}")
            target_domain = os.path.basename(input_dir).split('_')[0]
            generate_pdf_report(analysis, pdf_output, target_domain)
            print(f"[+] PDF Report generated successfully.")
            
    except Exception as e:
        print(f"[!] Error saving report: {e}")

def main():
    parser = argparse.ArgumentParser(description="AI Security Analyst CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Check command
    parser_check = subparsers.add_parser("check", help="Verify API connectivity")
    
    # Analyze command
    parser_analyze = subparsers.add_parser("analyze", help="Analyze scan results")
    parser_analyze.add_argument("--input", required=True, help="Path to scan results (file or directory)")
    parser_analyze.add_argument("--output", required=True, help="Path to save report")
    parser_analyze.add_argument("--format", choices=["md", "pdf"], default="md", help="Output format (default: md)")
    
    args = parser.parse_args()
    
    api_key, model = load_config()
    client = OpenRouterClient(api_key, model)
    
    if args.command == "check":
        command_check(client)
    elif args.command == "analyze":
        command_analyze(client, args)

if __name__ == "__main__":
    main()

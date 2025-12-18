# AI Report Template - Quick Reference Guide

## Overview
The AI now generates professional VAPT reports with CVSS v3.1 scoring, CWE classification, and structured vulnerability findings.

## Usage

### Basic Command
```bash
python3 -m sec_ai analyze --input results/[domain] --output reports/[domain]_report.md
```

### Full Example
```bash
# Set API credentials
export OPENROUTER_API_KEY="your-api-key-here"
export OPENROUTER_MODEL="qwen/qwen-2.5-coder-32b-instruct"

# Run analysis
python3 -m sec_ai analyze \
  --input results/example.com_2025-12-18_02-48-04 \
  --output reports/example.com_vapt_report.md
```

## Report Structure

Each vulnerability finding includes:

1. **Severity** - Critical/High/Medium/Low
2. **CVSS v3.1 Score** - Numerical score and vector string
3. **CVSSv3.1 Vector** - Detailed metric breakdown
4. **CWE** - Vulnerability classification
5. **Affected Assets** - URLs, IPs, ports
6. **Description** - Technical details
7. **Risks** - Security impact
8. **Proof of Concept** - Actual scan output
9. **Remediation** - Actionable steps

## What Changed

### prompts.py
- Added comprehensive VAPT report template
- Included CVSS v3.1 scoring guide
- Added CWE classification mappings
- Enforced professional formatting

### results_parser.py
- New: `parse_nmap_results()` - extracts port/service data
- New: `parse_wordpress_results()` - extracts WP version, plugins, findings
- Enhanced: `get_scan_context()` - returns structured JSON + summary

## Example Output

See [EXAMPLE_REPORT.md](file:///home/sai/Professional/VAPT/Automations/wordpress-vapt/sec_ai/EXAMPLE_REPORT.md) for a complete example of AI-generated report.

## Key Features

✅ **Professional Format** - Client-ready reports
✅ **CVSS Scoring** - Accurate risk assessment
✅ **CWE Classification** - Industry-standard categorization
✅ **Actual PoC Data** - Real scan outputs included
✅ **Actionable Remediation** - Specific fix steps

## Verification

Test the implementation:
```bash
# Verify imports work
python3 -c "from sec_ai.prompts import ANALYSIS_PROMPT_TEMPLATE; print('✓ OK')"
python3 -c "from sec_ai.results_parser import parse_nmap_results; print('✓ OK')"

# Test with existing scan data
python3 -m sec_ai analyze \
  --input results/xpereos.in_2025-12-18_02-48-04 \
  --output test_report.md
```

## Files Modified

- `/sec_ai/prompts.py` - AI prompt template
- `/sec_ai/results_parser.py` - Data extraction
- `/sec_ai/EXAMPLE_REPORT.md` - Example output (new)
- `/sec_ai/README.md` - This guide (new)

## Support

For issues or questions:
1. Check the [walkthrough.md](file:///home/sai/.gemini/antigravity/brain/ac651885-ba10-4385-8a59-89b799a6ce07/walkthrough.md)
2. Review the [implementation_plan.md](file:///home/sai/.gemini/antigravity/brain/ac651885-ba10-4385-8a59-89b799a6ce07/implementation_plan.md)
3. See example output in [EXAMPLE_REPORT.md](file:///home/sai/Professional/VAPT/Automations/wordpress-vapt/sec_ai/EXAMPLE_REPORT.md)

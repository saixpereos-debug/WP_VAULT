# Vṛthā V2.1 - Comprehensive User Manual

**Target**: WordPress Environments  
**Role**: Automated Red Team VAPT Framework  
**AI Engine**: `sec_ai` (Red Team Persona)

---

## 📖 Introduction
Vṛthā is an advanced automation framework that treats "Vulnerability Assessment" not as a list of bugs, but as an integrated **Red Team operation**. It chains industry-standard tools (Nuclei, WPScan, Amass) with a custom Python AI engine to deliver:
1.  **Noise-Free Recon**: Optimized DNS and Tech Detection.
2.  **Deep Discovery**: Regex-based secret scraping across the entire site.
3.  **Actionable Intelligence**: An AI Analyst that writes Exploit PoCs and validates risk.

---

## 🚀 The 5-Phase Workflow

### Phase 1: Pre-Flight & Recon
*   **Connectivity Check**: The system validates your OpenRouter API key and checks connectivity to the `qwen/gpt-4` model.
*   **Subdomain Enum**: Uses `subfinder`, `amass`, and `crt.sh` to map the attack surface.
*   **URL Discovery**: Uses `katana` to crawl the site and build a map of endpoints.

### Phase 2: Analysis
*   **Tech Detection**: Replaces legacy tools with **HTTPX -tech-detect**. This identifies CMS versions, server types, and frameworks using the optimized Wappalyzer engine.
*   **DNS Security**: Queries for SPF, DMARC, and MX records to identify email spoofing risks.

### Phase 3: Identity & Secrets Extraction
*   **Identity Mining**: Aggregates data from scraped content and enumeration to find:
    *   **Emails/Phones**: For social engineering impact assessment.
    *   **WordPress Users/Authors**: For brute-force surface mapping.
*   **Secrets Scraping**: A custom multi-threaded Python scraper (`utils/regex_scraper.py`) fetches URLs and scans for API Keys (AWS, Google, Stripe, Slack).
*   **NOTE**: TruffleHog has been removed in favor of this specialized extraction logic.

### Phase 4: Vulnerability Scanning
*   **Orchestrator Logic**: Tools only run if their prerequisites are met (e.g., Nuclei waits for Live Hosts).
*   **Nuclei**: Runs custom and community templates focusing on WordPress CVEs.
*   **OWASP ZAP (Docker)**: Launches ZAP in daemon mode to perform:
    *   **Spidering**: Mapping the application structure.
    *   **Active Scan**: Testing for XSS, SQLi, and logic flaws.
*   **WPScan**: Now uses "Smart Detection" - only runs if WordPress fingerprints are confirmed.

### Phase 5: The Red Team AI Analyst
*   **Plugin Audit**: `wp_plugin_audit.py` parses WPScan results, extracts plugin versions, and queries the AI (Qwen/GPT-4) to identify version-specific CVEs and generate exploit advice.
*   **Ingestion**: The `sec_ai` module parses the JSON results from all previous phases.
*   **Contextualization**: It correlates "Outdated Plugin" (WPScan) with "RCE Vulnerability" (Nuclei) and "Exposed API Key" (Secrets).
*   **Reporting**: Generates a professional Markdown & PDF report with:
    *   **Exploit Proof-of-Concepts (PoCs)**.
    *   **Risk Justification** (Critical/High/Medium).
    *   **Remediation Steps**.

---

## ⚙️ Configuration Guide

### 1. API Keys (Essential)
The framework monitors `config/config.sh` for keys. It will ask for them **only once** on the first run and save them securely.
*   **OPENROUTER_API_KEY**: Required for the AI Analyst.
*   **WPSCAN_API_TOKEN**: Recommended for the latest vulnerability database.
*   **SHODAN_API_KEY**: Optional (via `~/.config/uncover/provider-config.yaml`) for Cloud Recon.

### 2. Screenshots & Delays
*   **SCREENSHOT_DELAY**: Define the wait time (in seconds) before capturing a screenshot. Useful for slow-loading sites. Format in `config/config.sh`:
    ```bash
    SCREENSHOT_DELAY="5"
    ```

### 3. Tuning Scans
Edit `config/config.sh`:
*   **Speed**: Increase `HTTPX_THREADS` or `NUCLEI_OPTIONS` (rate limit).
*   **Scope**: Adjust `HTTPX_MATCHER_DOMAINS` to filter interesting subdomains.

---

## 🛠 Troubleshooting

**Problem: "AI Connectivity Check Failed"**
*   **Cause**: Invalid API Key or OpenRouter downtime.
*   **Fix**: Check your key in `config/config.sh`. The script will auto-disable AI features to let the rest of the scan proceed.

**Problem: "WPScan folder is empty"**
*   **Cause**: Previous versions failed if initial fingerprinting missed.
*   **Fix (v2.1)**: The scanner now uses a robust "Detection Mode" fallback. If the folder is still empty, the site is likely not WordPress or is blocking scanning IPs.

**Problem: "Nuclei not working as expected"**
*   **Fix**: Check the `results/<target>/nuclei/nuclei_debug_*.log` files for detailed error messages. Ensure your templates are updated (`nuclei -update-templates`).

**Problem: "Critical Failure: Live_hosts.txt is empty"**
*   **Cause**: `httpx` failed to resolve any subdomains to live IP addresses.
*   **Fix**: Check your target domain resilience or internet connection. The pipeline stops to prevent empty scans.

**Problem: "ZAP Report generation failed"**
*   **Cause**: Docker might not be running or ZAP failed to start.
*   **Fix**: Ensure `docker ps` works and you have pulled `owasp/zap2docker-stable`.

---

## 📂 Output Directory Explained
Located in `results/<target>_<date>/`:

| Folder | Description |
| :--- | :--- |
| **`final_report/`** | **Start Here**. The AI-generated Red Team Report (PDF/MD). |
| `wordpress/` | `vapt_<target>_wpscan_all.txt` and `_ai_assessment.md`. |
| `nuclei/` | Raw JSON vulnerabilities and `nuclei_debug_*.log`. |
| `secrets/` | `vapt_<target>_scraped_secrets.txt` (Emails/Keys). |
| `httpx/` | Tech stack, status codes, and **Interesting URLs**. |
| `screenshots/` | PNG captures of critical pages (including JSON endpoints). |

---
**Author**: Sai | **Version**: 2.1

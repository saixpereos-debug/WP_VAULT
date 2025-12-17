# Vṛthā V2.0 - Comprehensive User Manual

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

### Phase 3: Deep Discovery & Secrets
*   **Uncover Scan**: Queries Shodan/Censys (if keys provided) to find exposed ports and services.
*   **Deep Secrets Scraping**: A custom multi-threaded Python scraper (`utils/regex_scraper.py`) fetches every unique URL found in Phase 1 and scans the *response body* for:
    *   Emails (for phishing/password spraying).
    *   API Keys (AWS, Google, Stripe, Slack).

### Phase 4: Vulnerability Scanning
*   **Nuclei**: Runs custom and community templates focusing on WordPress CVEs.
*   **WPScan**: Enumerates users, plugins, themes, and Timthumb vulnerabilities.
*   **TruffleHog**: Scans the filesystem for leftover secrets in backup files.

### Phase 5: The Red Team AI Analyst
*   **Ingestion**: The `sec_ai` module parses the JSON results from all previous phases.
*   **Contextualization**: It correlates "Outdated Plugin" (WPScan) with "RCE Vulnerability" (Nuclei) and "Exposed API Key" (Secrets).
*   **Reporting**: Generates a professional Markdown report with:
    *   **Exploit Proof-of-Concepts (PoCs)**.
    *   **Risk Justification** (Critical/High/Medium).
    *   **Remediation Steps**.

---

## ⚙️ Configuration Guide

### 1. API Keys (Essential)
The framework monitors `config/config.sh` for keys.
*   **OPENROUTER_API_KEY**: Required for the AI Analyst.
*   **WPSCAN_API_TOKEN**: Recommended for the latest vulnerability database.
*   **SHODAN_API_KEY**: Optional (via `~/.config/uncover/provider-config.yaml`) for Cloud Recon.

### 2. Customizing AI
You can modify the AI persona in `sec_ai/prompts.py`:
*   **SYSTEM_PROMPT**: Defines the "Red Team" rules (e.g., "Always provide PoCs").
*   **ANALYSIS_PROMPT**: Defines the report structure.

### 3. Tuning Scans
Edit `config/config.sh`:
*   **Speed**: Increase `HTTPX_THREADS` or `NUCLEI_OPTIONS` (rate limit).
*   **Scope**: Adjust `HTTPX_MATCHER_DOMAINS` to filter interesting subdomains.

---

## 🛠 Troubleshooting

**Problem: "AI Connectivity Check Failed"**
*   **Cause**: Invalid API Key or OpenRouter downtime.
*   **Fix**: Check your key in `config/config.sh`. The script will auto-disable AI features to let the rest of the scan proceed.

**Problem: "Uncover provider config not found"**
*   **Cause**: You haven't set up the Uncover tool's config file.
*   **Fix**: Create `~/.config/uncover/provider-config.yaml` with your Shodan/Censys keys. The tool will warn you but continue with public sources.

**Problem: "Secrets Scan is slow"**
*   **Cause**: The site has thousands of URLs.
*   **Fix**: The scraper currently scans *all* URLs. This is by design for maximum depth.

---

## 📂 Output Directory Explained
Located in `results/<target>_<date>/`:

| Folder | Description |
| :--- | :--- |
| **`final_report/`** | **Start Here**. The AI-generated Red Team Report. |
| `nuclei/` | Raw JSON vulnerabilities. |
| `secrets/` | `vapt_<target>_scraped_secrets.txt` (Emails/Keys). |
| `httpx/` | Tech stack and status codes. |
| `subdomains/` | Raw subdomain lists. |

---
**Author**: Sai | **Version**: 2.0

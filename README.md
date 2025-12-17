# Vṛthā (Ex-WP_VAULT) - Advanced WordPress VAPT Framework v2.0
> **Production-Grade, AI-Powered Red Team Automation for WordPress**

**Vṛthā** is the first WordPress VAPT framework to integrate a **"Red Team" AI Analyst** directly into the scanning workflow. It doesn't just list vulnerabilities—it correlates findings, removes false positives, and generates **Exploit PoCs** using a custom Python-based AI engine (`sec_ai`).

## 🚀 Key Innovation: The Red Team AI
Unlike generic tools that dump raw logs, Vṛthā's `sec_ai` module acts as a Senior Penetration Tester:
*   **Anti-Hallucination**: Strictly adhering to evidence-based reporting.
*   **Exploit Reasoning**: Suggests valid attack vectors (SQLi, RCE) and generates python/bash PoCs.
*   **Deep Context**: Correlates technology stack (HTTPX) with vulnerabilities (Nuclei) and secrets (Regex/TruffleHog).

## 🔥 Features
*   **⚡ Optimized Recon**:
    *   **Smart DNS**: Filters noise, focuses on TXT (SPF/DMARC) and MX records.
    *   **Tech Detection**: Uses `httpx` (Wappalyzer engine) for blazing fast, accurate fingerprinting.
*   **🕵️ Deep Secrets Scraping**:
    *   Custom multi-threaded scraper (`utils/regex_scraper.py`) scans **every found URL** for API keys (AWS, Google, Stripe) and emails.
*   **☁️ Cloud Recon**:
    *   Integrated **Uncover** support (Shodan/Censys) with smart API key handling.
*   **🧠 Red Team Persona**:
    *   The AI outputs a report focused on **Exploitation** and **Impact**, not just compliance.

## 🛠️ Tool Stack
| Category | Tools Used | Why? |
| :--- | :--- | :--- |
| **Recon** | `subfinder`, `amass`, `katana` | Industry standard for depth and coverage. |
| **Analysis** | `httpx`, `dig` | `httpx` replaces WhatWeb for JSON-compatible, fast tech detect. |
| **Scanning** | `nuclei`, `wpscan` | Nuclei for general vulns, WPScan for deep WP enumeration. |
| **Secrets** | `trufflehog`, `regex_scraper` | Hybrid approach: pattern matching + entropy analysis. |
| **AI** | `OpenRouter` (Qwen/GPT-4) | Connects via custom `sec_ai` Python CLI. |

## 📦 Quick Start

### 1. Installation
We provide a single script to setup Go, Python, and Ruby dependencies.
```bash
git clone https://github.com/yourusername/vrtha.git
cd vrtha
chmod +x install.sh
./install.sh
```

### 2. Configuration (Crucial)
Add your API keys to enable the AI and Cloud Recon features.
```bash
# Edit config/config.sh
OPENROUTER_API_KEY="sk-..."  # Required for AI Report
SHODAN_API_KEY="..."         # Optional for Uncover
```

### 3. Run
```bash
./main.sh target.com
```

## 📊 Output
Results are organized in `results/<target>_<date>/`:
*   `final_report/`: **The AI-generated Red Team Report** (Markdown/HTML).
*   `nuclei/`: Vulnerability logs.
*   `httpx/`: Tech stack details.
*   `secrets/`: Found API keys and emails.

## 📝 License
MIT License
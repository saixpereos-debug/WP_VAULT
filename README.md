# Vṛthā (वृथा) - Advanced WordPress VAPT Framework v2.0

![Vrtha Banner](utils/banner.py)

> **"Offensive Excellence for Defensive Strength"**
> 
> Vṛthā is a production-grade, AI-powered automation framework designed for comprehensive Vulnerability Assessment and Penetration Testing (VAPT) of WordPress environments. It chains industry-leading security tools with a sophisticated **Red Team AI Analyst** to deliver actionable intelligence, not just raw logs.

---

## 🌟 Why Vṛthā?

Traditional scanners often leave security professionals with mountains of disconnected logs. Vṛthā solves this by integrating:
- **Red Team AI Analyst**: A custom engine (`sec_ai`) that correlates findings and generates Exploit PoCs.
- **Contextual Intelligence**: It understands that an outdated plugin + a sensitive secret + an exposed route = a critical attack path.
- **Automated Workflow**: From reconnaissance to professional reporting in a single command.

---

## 🔥 Key Features

### 🕵️ Comprehensive Reconnaissance
- **Optimized Subdomain Enumeration**: Chaining `subfinder`, `amass`, and `crt.sh`.
- **Intelligent Tech Detection**: Blazing fast fingerprinting using the `httpx` Wappalyzer engine (replaces WhatWeb).
- **DNS Security Analysis**: Targeted identification of SPF/DMARC/MX misconfigurations.

### 🧠 Red Team AI Analyst (`sec_ai`)
- **Advanced Persona**: Operates as a Senior Penetration Tester with 15+ years of experience.
- **Anti-Hallucination**: Strictly evidence-based reporting using actual scan data.
- **Exploit Reasoning**: Generates valid Python/Bash PoCs and calculates precise **CVSS v3.1** scores.
- **CWE Mapping**: Automatically maps findings to standard Common Weakness Enumerations.

### 🛡️ Deep Discovery & Vulnerability Scanning
- **Deep Secrets Scraping**: Scans every discovered URL for AWS, Google, Stripe, and Slack keys.
- **Intelligent Route Analysis**: Identifies potential IDOR, SQLi, and SSRF endpoints.
- **WordPress Specifics**: Deep enumeration of users, plugins, themes, and Timthumb vulnerabilities via WPScan & Nuclei.
- **Cloud Recon**: Built-in support for **Uncover** (Shodan/Censys) to find exposed assets.

---

## 🛠️ Tool Stack

| Phase | Tools |
| :--- | :--- |
| **Recon** | `subfinder`, `amass`, `katana`, `httpx` |
| **Scanning** | `nuclei`, `wpscan`, `trufflehog` |
| **Analysis** | `naabu`, `uncover`, `regex_scraper` |
| **AI Content** | `sec_ai` (OpenRouter API - Qwen/GPT-4) |
| **Reporting** | Custom Python/Shell reporting engine |

---

## 📦 Installation & Setup

### Prerequisites
- **OS**: Linux (Ubuntu/Debian recommended) or macOS.
- **Permissions**: Sudo access for installing system dependencies.
- **Minimum versions**: Python 3.9+, Go 1.21+, Ruby 3.0+.

### Quick Start
```bash
# Clone the repository
git clone https://github.com/saixpereos-debug/WP_VAULT.git
cd WP_VAULT

# Run the automated installer
chmod +x install.sh
sudo ./install.sh
```

### Manual Configuration
1. **API Keys**: Edit `config/config.sh` and add your keys:
   - `OPENROUTER_API_KEY`: Required for AI-powered reports.
   - `WPSCAN_API_TOKEN`: Required for the latest WP vulnerability DB.
2. **Cloud Recon**: Setup `~/.config/uncover/provider-config.yaml` for Shodan/Censys.

---

## 🚀 Usage

### Running a Comprehensive Scan
```bash
./main.sh target.com
```

### Output & Reports
Results are organized in `results/<target>_<timestamp>/`:
- **`final_report/vapt_target_ai_report.md`**: The primary Red Team report.
- **`wordpress/`**: Detailed WPScan findings.
- **`nuclei/`**: Categorized vulnerability logs.
- **`secrets/`**: Found API keys and email exposures.

---

## 📊 Sample Output (AI Context)
```markdown
## 1. Outdated WordPress Installation (Critical)
Score: 9.8 (Critical)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

### Description
The WordPress installation is running version 6.4.2, which contains multiple high-severity CVEs related to remote code execution.

### Proof of Concept
[+] WordPress version 6.4.2 identified (Outdated).
| Found By: Rss Generator
| Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=6.4.2'
```

---

## 📝 License & Ethics
- **License**: MIT
- **Disclaimer**: Vṛthā is for authorized security testing only. Unauthorized use on systems without permission is illegal and unethical.

---
**Developed with ❤️ by [Sai](https://github.com/saixpereos-debug)**
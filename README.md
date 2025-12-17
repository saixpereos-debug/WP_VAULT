# Vṛthā (Ex-WP_VAULT) - Advanced WordPress VAPT Framework v2.0

An enhanced, automated vulnerability assessment and penetration testing framework specifically designed for WordPress environments. This tool integrates multiple open-source security tools into a streamlined workflow, providing comprehensive scanning, analysis, and AI-powered reporting.

## 🚀 Key Features

*   **Automated Workflow**: Chains subdomains enumeration, URL discovery, tech detection, and scanning.
*   **Smart Analysis**: Uses `httpx` for advanced probing and `nuclei` with custom templates.
*   **AI Reporting**: Integrates OpenAI/OpenRouter API to generate professional-grade, actionable reports.
*   **Configurable**: Highly customizable via `config/config.sh`.
*   **Easy Install**: One-script setup for all dependencies.

## 🛠️ Tools Included
*   **Subdomain Enum**: `subfinder`, `amass`, `crt.sh`
*   **Discovery**: `katana`, `hackcrawler` (optional)
*   **Analysis**: `httpx`, `wafw00f`
*   **Scanning**: `wpscan`, `nuclei` (with custom WP templates)
*   **Helpers**: `gowitness` (screenshots), `jq`

## 📦 Installation

We provide an `install.sh` script to automate the installation of all dependencies (Go, Python, Ruby tools) and configure the environment.

### Quick Start
```bash
git clone https://github.com/yourusername/wordpress-vapt.git
cd wordpress-vapt
chmod +x install.sh
./install.sh
```

### Manual Steps
If you prefer to install tools manually:
1.  Install the required tools (`subfinder`, `httpx`, `nuclei`, `wpscan`, etc.).
2.  Run `./setup.sh` to auto-detect their paths.
3.  Edit `config/config.sh` to review the configuration.

## ⚙️ Configuration
Before running a scan, ensure you add your API keys:
1.  Open `config/config.sh`.
2.  Add your `OPENROUTER_API_KEY` (or OpenAI key) for report generation.
3.  Verify tool paths if `install.sh` didn't catch them.

## 🏃 Usage

Run the main script with your target domain:

```bash
./main.sh example.com
```

### Output
Results are saved in `results/<target>_<date>/`:
*   `final_report/`: HTML and Markdown reports.
*   `subdomains/`: Discovered subdomains.
*   `nuclei/`: Vulnerability scan results.
*   `wordpress/`: WPScan specific results.

## 📝 License
MIT License
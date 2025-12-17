# Vṛthā - User Manual

**Version**: 2.0  
**Target**: WordPress Environments  
**Purpose**: Advanced Vulnerability Assessment and Penetration Testing (VAPT)

---

## 📖 Introduction
**Vṛthā** (formerly known as WP_VAULT) is a fully automated, agentic-style security framework for WordPress. It combines traditional security tools (Nuclei, WPScan, Feroxbuster) with modern AI analysis (OpenRouter/GPT-4) to provide deep insights, reliable content discovery, and automated threat modeling.

## 🚀 Key Features
1.  **Clean UI**: Minimalist, spinner-based interface.
2.  **Auto-Configuration**: Smart detection of installed tools.
3.  **Deep Discovery**:
    *   **Feroxbuster**: Auto-tuned fuzzing for directories.
    *   **Gospider**: JavaScript crawling and parameter mining.
4.  **AI Architecture Analysis**:
    *   Automatically answers: "How does this app pass data?", "Is it multi-tenant?", "What is the threat model?"
    *   Generates a `architecture_threat_model.md` artifact.
5.  **Smart Reporting**: Aggregates all findings into a Markdown and HTML report using AI.

---

## 🛠 Installation

### Option A: Easy Install (Recommended)
This method installs all dependencies (Go, Python, Ruby tools) for you.

```bash
git clone https://github.com/yourusername/vrtha.git
cd vrtha
chmod +x install.sh
sudo ./install.sh
```

### Option B: Manual Install
If you prefer to install tools yourself:
1.  Install: `subfinder`, `amass`, `katana`, `httpx`, `nuclei`, `wpscan`, `gowitness`, `feroxbuster`, `gospider`.
2.  Run the setup script to map them:
    ```bash
    ./setup.sh
    ```

---

## ⚙️ Configuration

### 1. API Keys (Vital for AI)
Vṛthā requires an **OpenRouter API Key** for its AI features.
*   **Prompted Setup**: The first time you run `./main.sh`, it will ask for your key if missing.
*   **Manual**: Edit `config/config.sh`:
    ```bash
    OPENROUTER_API_KEY="sk-..."
    WPSCAN_API_TOKEN="..."
    ```

### 2. Tuning
You can adjust tool behavior in `config/config.sh`:
*   `WPSCAN_OPTIONS`: Change thread count, wordlists, or stealth modes.
*   `NUCLEI_OPTIONS`: Adjust rate limits (`-rl`) or severities.

---

## 🏃 processing
Run the tool against your target domain:

```bash
./main.sh example.com
```

### The Scan Phases
1.  **Reconnaissance**: Subdomain enumeration (Subfinder, Amass) and URL Discovery (Katana).
2.  **Analysis**: Tech detection (HTTPx), DNS, Network, and Firewall checks (Wafw00f).
3.  **Deep Discovery**:
    *   **Fuzzing**: Uses Feroxbuster to find hidden paths.
    *   **Spidering**: uses Gospider to find JS files and parameters.
4.  **Vulnerability Scanning**:
    *   **Nuclei**: Custom & Official WP templates.
    *   **WPScan**: Deep WordPress enumeration (Users, Plugins, Themes, Timthumbs).
5.  **AI Analysis**:
    *   Constructs a Threat Model.
    *   Generates a final impact report.

---

## 📂 Output Structure
Results are saved in `results/<target>_<date>/`:

| Directory | Content |
| :--- | :--- |
| `final_report/` | **Start Here**. Contains `vapt_<target>_report.html` and `.md`. |
| `context/` | AI-generated `architecture_threat_model.md`. |
| `content/` | Results from Feroxbuster (hidden files/dirs). |
| `spidering/` | Discovered JS files and link output. |
| `nuclei/` | JSON findings from Nuclei. |
| `wordpress/` | Raw WPScan logs. |
| `screenshots/` | Validated screenshots of active URLs. |

---

## ❓ Troubleshooting

**Q: "Tool not found" error?**  
A: Run `./check_deps.sh` to see what is missing. Run `./install.sh` to fix it.

**Q: Scan is too slow?**  
A: Edit `config/config.sh`.
*   Increase `NUCLEI_OPTIONS ... -rl 100` (Rate limit).
*   Add `--fast` to WPScan options (though this reduces accuracy).

**Q: AI analysis skipped?**  
A: Ensure `OPENROUTER_API_KEY` is set in `config/config.sh`.

---

**Author**: Sai  
**License**: MIT

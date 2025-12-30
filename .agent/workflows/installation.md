---
description: Installation and Setup of Vṛthā VAPT Framework
---

# Installation and Setup

## 1. Prerequisites
Ensure you have the following installed on your system:
- `python3` (with `requests` library)
- `jq`
- `go` (for installing tools like subfinder, etc.)
- `ruby` (for wpscan)

## 2. Directory Structure
The tool is located in `/home/sai/Professional/VAPT/Automations/wordpress-vapt/`.
Ensure you are in this directory:
```bash
cd /home/sai/Professional/VAPT/Automations/wordpress-vapt/
```

## 3. Install Dependencies
If you haven't installed the underlying tools, run:

```bash
# Example for installing some common tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/sensepost/gowitness@latest
gem install wpscan
pip install wafw00f requests markdown
sudo apt-get install jq
```

## 4. Run Auto-Configuration
Run the setup script to detect your installed tools and configure the framework automatically:
```bash
// turbo
./setup.sh
```

## 5. Verify Configuration
Check `config/config.sh` to ensure all paths are correct.
If any tool was "Not found", install it and run `./setup.sh` again, or edit `config/config.sh` manually.

## 6. Run a Scan
Execute the main script with your target domain:
```bash
./main.sh example.com
```

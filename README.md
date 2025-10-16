# 🚀 Dax-W: Advanced Reconnaissance Automation Framework

Dax-W is a comprehensive, modular reconnaissance toolkit, built entirely in **Bash Script**. Its core mission is to automate the target scouting process for web application penetration testers and bug bounty hunters, providing highly curated and actionable results.

---

## 🌟 Features Overview

1. **Full Automation**  
   Automates the entire workflow of subdomain and URL gathering.

2. **Tool Integration**  
   Leverages a powerful set of industry-leading tools for maximum coverage.

3. **WAF/CDN Detection**  
   Attempts to detect the target's real IP and identify services like Cloudflare to adjust scanning parameters.

4. **Intelligent Scanning**  
   Supports three modes (`-safe`, `-medium`, `-aggressive`) to manage scan intensity and prevent blacklisting.

5. **Smart Output**  
   Categorizes and cleans all extracted URLs by response code (e.g., `200`, `301`, `403`) and separates those with/without parameters.

6. **HTML Reporting**  
   Generates a user-friendly `final_report.html` and a detailed `domain_report.html` for result visualization.

---

## 🛠️ Integrated Tools

Dax-W orchestrates the following tools:  
`sublist3r_v2 / amass / subfinder / assetfinder / gobuster / crt / httpx / katana / ffuf / gau / dirsearch / waymore / curl / jq`

---

## ⚙️ Installation Guide

Follow these steps to download and set up Dax-W on your Linux-based system:

### 1. Download the Tool
```bash
git clone https://github.com/waleedsmadi/daxw.git
cd daxw
```

### 2. Set Permissions and Install to PATH
```bash
# Give execution permission
chmod +x ./dax-w.sh

# Move the entire directory to /usr/local/bin
sudo cp -r daxw /usr/local/bin

# Create a symlink (shortcut) for the main script
sudo ln -s /usr/local/bin/daxw/dax-w.sh /usr/local/bin/dax-w
```

### 3. Dependency Management
Dax-W includes an internal mechanism to manage all required third-party tools:

```bash
dax-w --install      # Installs all missing dependencies required for a full scan.
dax-w --show-tools   # Displays supported tools and indicates which are installed or uninstalled.
```

---

## 🚀 Usage & Execution

You must specify one of two main actions: `subs` (for subdomains) or `urls` (for links). Use `-h` or `--help` for full options.

### 1. Subdomain Enumeration (subs)  
Find subdomains for a target.

**Example 1: Single domain, medium intensity**
```bash
dax-w subs -medium -d target.com
```

**Example 2: Multiple domains**
```bash
dax-w subs -medium -m target1.com target2.com
```

**Example 3: List of domains from a file**
```bash
dax-w subs -medium -l /path/to/domains.txt
```

### 2. Custom Tool Selection  
Run a custom scan by defining the specific tools you want to use:
```bash
dax-w subs -medium -d target.com -t sublist3r-passive subfinder assetfinder
```

### 3. URL/Endpoint Extraction (urls)  
Extract links and endpoints for a specific URL "Full Scan".

**Example: Single URL, medium intensity**
```bash
dax-w urls -medium -u https://target.com
```

---

# AutoRecon 🔍

Automated Reconnaissance & Vulnerability Mapping Framework for penetration testers.

## Features
- Subdomain enumeration via DNS brute force
- Multi-threaded TCP port scanning (ports 1–1024)
- Automatic CVE lookup via NIST NVD API
- Professional HTML + JSON report generation

## Installation
git clone https://github.com/Xark-Lymen/autorecon.git
cd autorecon
pip install -r requirements.txt

## Usage
# Basic scan
python autorecon.py -t scanme.nmap.org

# Skip CVE lookup (faster)
python autorecon.py -t scanme.nmap.org --no-cve

# Scan IP directly
python autorecon.py -t 192.168.1.1

## ⚠️ Legal Disclaimer
This tool is for authorized penetration testing and educational purposes only.
Never scan systems you do not have explicit written permission to test.

## Tech Stack
Python 3.10 | dnspython | requests | jinja2

## Project Structure
autorecon/
├── autorecon.py          # Main entry point
├── config.py             # Configuration
├── modules/
│   ├── subdomain_enum.py
│   ├── port_scanner.py
│   ├── cve_lookup.py
│   └── report_generator.py
└── wordlists/
    └── subdomains.txt
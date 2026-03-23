# autorecon.py

# -----------------------------------------------
# AutoRecon — Main Entry Point
# Orchestrates all modules in sequence:
#   1. Parse CLI arguments
#   2. Subdomain enumeration
#   3. Port scanning
#   4. CVE enrichment
#   5. Report generation
# -----------------------------------------------

import argparse
import sys
import os
from modules.subdomain_enum  import enumerate_subdomains
from modules.port_scanner    import scan_target
from modules.cve_lookup      import enrich_ports_with_cves
from modules.report_generator import generate_report

# ASCII banner — makes your tool look professional in terminal demos
BANNER = """
╔═══════════════════════════════════════════╗
║          A U T O R E C O N  v1.0         ║
║   Automated Reconnaissance Framework     ║
║   For authorized penetration testing     ║
╚═══════════════════════════════════════════╝
"""

def parse_args():
    """
    argparse: Python's standard CLI argument parser.
    Defines what flags/options the tool accepts.
    """
    parser = argparse.ArgumentParser(
        description="AutoRecon — Automated Recon & Vulnerability Mapping",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target domain or IP (e.g., example.com or 192.168.1.1)"
    )
    
    parser.add_argument(
        "-w", "--wordlist",
        default="wordlists/subdomains.txt",
        help="Path to subdomain wordlist (default: wordlists/subdomains.txt)"
    )
    
    parser.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Skip subdomain enumeration (useful for IP targets)"
    )
    
    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip CVE lookup (faster scan, no internet needed)"
    )
    
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()
    
    target     = args.target
    subdomains = []
    
    print(f"[*] Target: {target}")
    print("=" * 50)
    
    # ── PHASE 1: Subdomain Enumeration ───────────────────────────────────────
    if not args.no_subdomains and not target.replace(".", "").isdigit():
        # Only enumerate subdomains for domain names, not raw IPs
        if not os.path.exists(args.wordlist):
            print(f"[!] Wordlist not found: {args.wordlist}")
            print("[!] Skipping subdomain enumeration.")
        else:
            subdomains = enumerate_subdomains(target, args.wordlist)
    else:
        print("[*] Skipping subdomain enumeration.")
    
    # ── PHASE 2: Port Scanning ───────────────────────────────────────────────
    open_ports = scan_target(target)
    
    # ── PHASE 3: CVE Enrichment ──────────────────────────────────────────────
    if not args.no_cve and open_ports:
        open_ports = enrich_ports_with_cves(open_ports)
    
    # ── PHASE 4: Report Generation ───────────────────────────────────────────
    print("\n[*] Generating reports...")
    report_paths = generate_report(target, subdomains, open_ports)
    
    # ── SUMMARY ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 50)
    print("  SCAN COMPLETE")
    print("=" * 50)
    print(f"  Target:        {target}")
    print(f"  Subdomains:    {len(subdomains)}")
    print(f"  Open Ports:    {len(open_ports)}")
    total_cves = sum(len(p.get("cves", [])) for p in open_ports)
    print(f"  CVEs Found:    {total_cves}")
    print(f"  HTML Report:   {report_paths['html']}")
    print(f"  JSON Report:   {report_paths['json']}")
    print("=" * 50)


if __name__ == "__main__":
    # This block only runs when you execute the file directly
    # (not when it's imported as a module)
    # This is a standard Python best practice
    main()
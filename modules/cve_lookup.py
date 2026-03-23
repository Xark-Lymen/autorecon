# modules/cve_lookup.py

# -----------------------------------------------
# CVE Lookup Module
# Uses NIST NVD (National Vulnerability Database)
# REST API v2 to search for known vulnerabilities
# based on service/software names discovered
# during port scanning.
# -----------------------------------------------

import requests
import time
from config import NVD_API_URL, SERVICE_CPE_MAP


def lookup_cves_for_service(service_name: str, max_results: int = 5) -> list[dict]:
    """
    Query NVD API for CVEs related to a given service.
    
    NVD API v2 endpoint:
    GET /rest/json/cves/2.0?keywordSearch=<service>
    
    Args:
        service_name: e.g., "openssh", "apache", "mysql"
        max_results:  Max CVEs to return per service
    
    Returns:
        List of CVE dicts with id, description, severity, score
    """
    
    # Clean up service name — strip version numbers, take first word
    # "ssh / openssh" → "openssh"
    clean_name = service_name.split("/")[-1].strip().split(" ")[0]
    
    # Skip generic/unknown services
    if clean_name in ["unknown", "http-alt", "https-alt", "dns"]:
        return []
    
    params = {
        "keywordSearch": clean_name,    # NVD full-text search
        "resultsPerPage": max_results,
    }
    
    headers = {
        "User-Agent": "AutoRecon/1.0 (Educational Pentest Tool)"
    }
    
    try:
        print(f"  [~] CVE lookup for: {clean_name}")
        
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10)
        
        # Rate limit: NVD allows ~5 requests/30 seconds without API key
        # Add small delay to be respectful and avoid getting blocked
        time.sleep(1)
        
        if response.status_code != 200:
            print(f"  [!] NVD API error: {response.status_code}")
            return []
        
        data = response.json()
        
        # NVD response structure:
        # { "vulnerabilities": [ { "cve": { "id", "descriptions", "metrics" } } ] }
        vulnerabilities = data.get("vulnerabilities", [])
        
        cves = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            
            # Extract CVE ID (e.g., "CVE-2023-38408")
            cve_id = cve.get("id", "N/A")
            
            # Extract English description
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )
            # Truncate long descriptions
            description = description[:300] + "..." if len(description) > 300 else description
            
            # Extract CVSS score and severity
            # CVSS = Common Vulnerability Scoring System (0.0 - 10.0)
            score = "N/A"
            severity = "N/A"
            
            metrics = cve.get("metrics", {})
            
            # Try CVSSv3.1 first, then v3.0, then v2
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_key in metrics:
                    metric = metrics[metric_key][0]["cvssData"]
                    score    = metric.get("baseScore", "N/A")
                    severity = metric.get("baseSeverity", "N/A")
                    break
            
            cves.append({
                "id":          cve_id,
                "description": description,
                "score":       score,
                "severity":    severity,
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })
        
        return cves
    
    except requests.RequestException as e:
        print(f"  [!] Network error during CVE lookup: {e}")
        return []


def enrich_ports_with_cves(open_ports: list[dict]) -> list[dict]:
    """
    For each open port, look up CVEs for its service.
    Adds a 'cves' key to each port dict.
    
    Args:
        open_ports: List of port dicts from port_scanner.py
    
    Returns:
        Same list, with 'cves' field added to each port
    """
    print("\n[*] Starting CVE enrichment for discovered services...")
    
    for port_info in open_ports:
        service = port_info.get("service", "unknown")
        cves = lookup_cves_for_service(service)
        port_info["cves"] = cves   # Inject CVEs directly into port data
        
        if cves:
            print(f"  [+] {service}: {len(cves)} CVEs found "
                  f"(Top: {cves[0]['id']} | CVSS: {cves[0]['score']})")
    
    return open_ports
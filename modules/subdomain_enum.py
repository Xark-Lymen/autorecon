# modules/subdomain_enum.py

# -----------------------------------------------
# Subdomain Enumeration Module
# Strategy: DNS brute-force using a wordlist
# For each word (e.g., "mail", "api", "dev"),
# we construct "word.target.com" and try to
# resolve it to an IP via DNS lookup.
# If it resolves → subdomain exists.
# -----------------------------------------------

import dns.resolver          # dnspython library for DNS queries
import concurrent.futures    # For multi-threading
from config import THREAD_COUNT

def resolve_subdomain(subdomain: str, domain: str) -> dict | None:
    """
    Try to resolve a single subdomain.
    
    Args:
        subdomain: e.g., "mail"
        domain:    e.g., "example.com"
    
    Returns:
        dict with subdomain info if found, None if not
    """
    full_domain = f"{subdomain}.{domain}"   # e.g., mail.example.com
    
    try:
        # dns.resolver.resolve() performs an actual DNS A-record lookup
        # A-record = maps a hostname to an IPv4 address
        answers = dns.resolver.resolve(full_domain, "A")
        
        # If we get here, the subdomain exists — collect all IPs
        ips = [str(r) for r in answers]
        
        return {
            "subdomain": full_domain,
            "ips": ips,
            "status": "found"
        }
    
    except dns.resolver.NXDOMAIN:
        # NXDOMAIN = "Non-Existent Domain" — subdomain doesn't exist
        return None
    
    except dns.resolver.NoAnswer:
        # Domain exists but has no A record (might have MX, CNAME, etc.)
        return None
    
    except dns.exception.DNSException:
        # Catch-all for timeouts, connection errors, etc.
        return None


def enumerate_subdomains(domain: str, wordlist_path: str) -> list[dict]:
    """
    Main function: brute-force enumerate subdomains using a wordlist.
    Uses ThreadPoolExecutor to run multiple DNS lookups in parallel.
    
    Args:
        domain:        Target domain, e.g., "example.com"
        wordlist_path: Path to file with one subdomain prefix per line
    
    Returns:
        List of found subdomain dicts
    """
    
    # Load wordlist — each line is one subdomain prefix
    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip()]
    
    found = []
    
    print(f"[*] Starting subdomain enumeration on: {domain}")
    print(f"[*] Wordlist size: {len(words)} entries | Threads: {THREAD_COUNT}")
    
    # ThreadPoolExecutor runs `THREAD_COUNT` threads simultaneously
    # Instead of checking one subdomain at a time (slow),
    # we check 100 at once (fast)
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        
        # Submit all tasks to the thread pool
        # Each task = resolve_subdomain(word, domain)
        future_to_word = {
            executor.submit(resolve_subdomain, word, domain): word
            for word in words
        }
        
        # As each task completes (in any order), collect results
        for future in concurrent.futures.as_completed(future_to_word):
            result = future.result()
            if result:  # Only keep successful resolutions
                found.append(result)
                print(f"  [+] Found: {result['subdomain']} → {result['ips']}")
    
    print(f"[*] Subdomain enumeration complete. Found: {len(found)}")
    return found
# modules/port_scanner.py

# -----------------------------------------------
# Port Scanner Module
# Strategy: TCP Connect Scan (non-raw socket)
# We attempt to open a full TCP connection to
# each port. If it succeeds → port is OPEN.
# We also grab the service banner if available.
# -----------------------------------------------

import socket
import concurrent.futures
from config import THREAD_COUNT, SOCKET_TIMEOUT, PORT_RANGE_START, PORT_RANGE_END

# Common port-to-service name mappings
# socket.getservbyport() can do this too, but this is faster + more reliable
PORT_SERVICE_MAP = {
    21:   "ftp",
    22:   "ssh / openssh",
    23:   "telnet",
    25:   "smtp",
    53:   "dns",
    80:   "http",
    110:  "pop3",
    143:  "imap",
    443:  "https",
    445:  "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017:"mongodb",
}


def scan_port(host: str, port: int) -> dict | None:
    """
    Attempt TCP connection to a single port.
    
    The TCP handshake (SYN → SYN-ACK → ACK) either
    completes (port open) or is refused/times out (port closed/filtered).
    
    Returns dict with port info if open, None if closed.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)   # Don't wait more than 0.5s per port
        
        # connect_ex returns 0 on success, error code on failure
        # Unlike connect(), it doesn't raise an exception — cleaner for scanning
        result = sock.connect_ex((host, port))
        
        if result == 0:  # Port is OPEN
            
            # Try to grab a service banner
            # Many services (FTP, SSH, SMTP) send a greeting message on connect
            banner = ""
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")  # HTTP probe
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                banner = banner[:200]   # Truncate long banners
            except:
                pass    # No banner — that's fine
            
            sock.close()
            
            # Look up service name from our map, fallback to "unknown"
            service = PORT_SERVICE_MAP.get(port, "unknown")
            
            return {
                "port":    port,
                "state":   "open",
                "service": service,
                "banner":  banner
            }
        
        sock.close()
        return None     # Port closed or filtered
    
    except socket.error:
        return None


def scan_target(host: str) -> list[dict]:
    """
    Scan all ports in range on a given host using threading.
    
    Args:
        host: IP address or hostname to scan
    
    Returns:
        List of open port dicts, sorted by port number
    """
    
    print(f"\n[*] Starting port scan on: {host}")
    print(f"[*] Range: {PORT_RANGE_START}-{PORT_RANGE_END} | Threads: {THREAD_COUNT}")
    
    open_ports = []
    ports = range(PORT_RANGE_START, PORT_RANGE_END + 1)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        
        future_to_port = {
            executor.submit(scan_port, host, port): port
            for port in ports
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"  [+] {result['port']}/tcp  OPEN  {result['service']}")
    
    # Sort results by port number for clean output
    open_ports.sort(key=lambda x: x["port"])
    
    print(f"[*] Port scan complete. Open ports: {len(open_ports)}")
    return open_ports
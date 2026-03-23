# config.py

# -----------------------------------------------
# Central configuration file for AutoRecon
# All constants, toggles, and API keys live here
# -----------------------------------------------

# NVD (National Vulnerability Database) API base URL
# Free API — no key needed for basic use, but rate-limited
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# How many threads to use for port scanning
# Higher = faster, but noisier on the network
THREAD_COUNT = 100

# Port range to scan
PORT_RANGE_START = 1
PORT_RANGE_END = 1024

# Timeout in seconds for each port connection attempt
SOCKET_TIMEOUT = 0.5

# Where to save generated reports
REPORT_OUTPUT_DIR = "reports"

# Common service-to-CPE mappings for CVE lookup
# CPE = Common Platform Enumeration — a standard naming format
# used by NVD to identify software/services
SERVICE_CPE_MAP = {
    "apache":   "cpe:2.3:a:apache:http_server",
    "nginx":    "cpe:2.3:a:nginx:nginx",
    "openssh":  "cpe:2.3:a:openbsd:openssh",
    "ftp":      "cpe:2.3:a:vsftpd:vsftpd",
    "mysql":    "cpe:2.3:a:mysql:mysql",
    "rdp":      "cpe:2.3:o:microsoft:windows",
    "smb":      "cpe:2.3:o:microsoft:windows",
}
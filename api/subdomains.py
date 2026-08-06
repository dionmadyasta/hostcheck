from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import socket

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

COMMON_PREFIXES = [
    "www", "mail", "webmail", "cpanel", "admin", "dev", "staging",
    "api", "blog", "portal", "store", "shop", "app", "direct", "ftp",
    "autodiscover", "pop", "imap", "smtp", "m", "client", "billing"
]


def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def find_subdomains(domain):
    subdomains = {}  # hostname -> ip

    # 1. Try HackerTarget HostSearch API (fast, free)
    if REQUESTS_OK:
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            r = requests.get(url, timeout=5)
            if r.status_code == 200 and "API count exceeded" not in r.text and "error" not in r.text:
                for line in r.text.strip().split("\n"):
                    if "," in line:
                        parts = line.split(",")
                        sub = parts[0].strip().lower()
                        ip = parts[1].strip() if len(parts) > 1 else None
                        if sub.endswith(domain) and sub != domain:
                            subdomains[sub] = ip
        except Exception:
            pass

    # 2. Fast check common hosting prefixes as fallback / boost
    for prefix in COMMON_PREFIXES:
        sub = f"{prefix}.{domain}"
        if sub not in subdomains:
            ip = resolve_ip(sub)
            if ip:
                subdomains[sub] = ip

    # Format result list sorted
    items = []
    for sub, ip in sorted(subdomains.items()):
        items.append({
            "subdomain": sub,
            "ip": ip or "Not resolved",
            "has_ip": ip is not None
        })

    return {
        "domain": domain,
        "total": len(items),
        "subdomains": items
    }


class handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        domain = qs.get("domain", [""])[0].strip().lower()
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

        if not domain:
            self._json(400, {"error": "Missing required parameter: domain"})
            return

        try:
            self._json(200, find_subdomains(domain))
        except Exception as e:
            self._json(500, {"error": str(e)})

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code, data):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

from http.server import BaseHTTPRequestHandler
import json
import urllib.parse

try:
    import dns.resolver
    import dns.exception
    DNS_OK = True
except ImportError:
    DNS_OK = False

RESOLVERS = [
    {"name": "Google",          "ip": "8.8.8.8",          "flag": "🇺🇸", "region": "US"},
    {"name": "Google Alt",      "ip": "8.8.4.4",          "flag": "🇺🇸", "region": "US"},
    {"name": "Cloudflare",      "ip": "1.1.1.1",          "flag": "🌐", "region": "Global"},
    {"name": "Cloudflare Alt",  "ip": "1.0.0.1",          "flag": "🌐", "region": "Global"},
    {"name": "Quad9",           "ip": "9.9.9.9",          "flag": "🇺🇸", "region": "US"},
    {"name": "OpenDNS",         "ip": "208.67.222.222",   "flag": "🇺🇸", "region": "US"},
    {"name": "Yandex",          "ip": "77.88.8.8",        "flag": "🇷🇺", "region": "RU"},
    {"name": "Comodo",          "ip": "8.26.56.26",       "flag": "🇺🇸", "region": "US"},
    {"name": "Level3",          "ip": "209.244.0.3",      "flag": "🇺🇸", "region": "US"},
    {"name": "Telkom ID",       "ip": "203.130.196.5",    "flag": "🇮🇩", "region": "ID"},
    {"name": "Nawala ID",       "ip": "180.131.144.144",  "flag": "🇮🇩", "region": "ID"},
]


def check_propagation(domain, record_type="A"):
    if not DNS_OK:
        return {"error": "dnspython not installed"}

    results = []
    reference_ips = None

    for info in RESOLVERS:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [info["ip"]]
        resolver.timeout = 3
        resolver.lifetime = 4

        entry = {**info}
        try:
            answers = resolver.resolve(domain, record_type)
            values = sorted([str(r) for r in answers])
            entry.update({"status": "resolved", "values": values, "ttl": answers.rrset.ttl})
        except dns.resolver.NXDOMAIN:
            entry.update({"status": "nxdomain", "values": []})
        except dns.exception.Timeout:
            entry.update({"status": "timeout", "values": []})
        except dns.resolver.NoNameservers:
            entry.update({"status": "no_nameservers", "values": []})
        except Exception as e:
            entry.update({"status": "error", "values": [], "detail": str(e)})

        results.append(entry)

    # Use Google (8.8.8.8) as reference baseline
    for r in results:
        if r["ip"] == "8.8.8.8" and r["status"] == "resolved":
            reference_ips = r["values"]
            break

    # Mark each result against reference
    for r in results:
        if r["status"] == "resolved":
            r["match"] = (r["values"] == reference_ips) if reference_ips is not None else None
        else:
            r["match"] = False

    resolved = [r for r in results if r["status"] == "resolved"]
    matching = [r for r in results if r.get("match") is True]
    total = len(RESOLVERS)

    return {
        "domain": domain,
        "record_type": record_type,
        "reference": reference_ips,
        "total": total,
        "resolved": len(resolved),
        "matching": len(matching),
        "propagation_pct": round(len(matching) / total * 100) if total else 0,
        "results": results
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
        rtype = qs.get("type", ["A"])[0].upper()

        if not domain:
            self._json(400, {"error": "Missing required parameter: domain"})
            return

        try:
            self._json(200, check_propagation(domain, rtype))
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

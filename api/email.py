from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import socket

try:
    import dns.resolver
    import dns.exception
    DNS_OK = True
except ImportError:
    DNS_OK = False

DKIM_SELECTORS = [
    "default", "mail", "google", "k1", "k2", "s1", "s2",
    "smtp", "dkim", "email", "mimecast", "selector1", "selector2",
]

SMTP_PORTS = [
    {"port": 25,  "label": "SMTP"},
    {"port": 587, "label": "Submission"},
    {"port": 465, "label": "SMTPS"},
]


def check_port(host, port, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_email(domain):
    if not DNS_OK:
        return {"error": "dnspython not installed"}

    r = dns.resolver.Resolver()
    r.timeout = 4
    r.lifetime = 7

    result = {
        "domain": domain,
        "mx_records": [],
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "smtp_ports": [],
        "summary": {}
    }

    # ─── MX Records ──────────────────────────────────────────────────────────
    try:
        mx_answers = list(r.resolve(domain, "MX"))
        mx_answers.sort(key=lambda x: x.preference)
        result["mx_records"] = [
            {"host": str(x.exchange).rstrip("."), "priority": x.preference}
            for x in mx_answers
        ]
    except Exception:
        result["mx_records"] = []

    # ─── SPF ─────────────────────────────────────────────────────────────────
    try:
        txt = list(r.resolve(domain, "TXT"))
        for t in txt:
            val = b"".join(t.strings).decode("utf-8", errors="replace")
            if val.startswith("v=spf1"):
                # Parse mechanism for summary
                mechanisms = val.split()[1:]
                result["spf"] = {"record": val, "mechanisms": mechanisms, "valid": True}
                break
    except Exception:
        pass

    if result["spf"] is None:
        result["spf"] = {"record": None, "valid": False}

    # ─── DMARC ───────────────────────────────────────────────────────────────
    try:
        dmarc_txts = list(r.resolve(f"_dmarc.{domain}", "TXT"))
        for t in dmarc_txts:
            val = b"".join(t.strings).decode("utf-8", errors="replace")
            if "v=DMARC1" in val:
                policy = "none"
                for part in val.split(";"):
                    p = part.strip()
                    if p.startswith("p="):
                        policy = p[2:].strip()
                result["dmarc"] = {"record": val, "policy": policy, "valid": True}
                break
    except Exception:
        pass

    if result["dmarc"] is None:
        result["dmarc"] = {"record": None, "policy": None, "valid": False}

    # ─── DKIM (common selectors) ──────────────────────────────────────────────
    dkim_found = None
    for sel in DKIM_SELECTORS:
        try:
            dkim_txts = list(r.resolve(f"{sel}._domainkey.{domain}", "TXT"))
            if dkim_txts:
                val = b"".join(dkim_txts[0].strings).decode("utf-8", errors="replace")
                dkim_found = {"selector": sel, "record": val[:120] + "..." if len(val) > 120 else val}
                break
        except Exception:
            continue

    result["dkim"] = dkim_found if dkim_found else {"selector": None, "record": None}

    # ─── SMTP Port check on first MX host ────────────────────────────────────
    if result["mx_records"]:
        primary_mx = result["mx_records"][0]["host"]
        for port_info in SMTP_PORTS:
            reachable = check_port(primary_mx, port_info["port"])
            result["smtp_ports"].append({
                **port_info,
                "host": primary_mx,
                "reachable": reachable
            })

    # ─── Summary ─────────────────────────────────────────────────────────────
    result["summary"] = {
        "mx_exists": len(result["mx_records"]) > 0,
        "mx_redundant": len(result["mx_records"]) >= 2,
        "spf_valid": result["spf"]["valid"],
        "dkim_found": result["dkim"]["selector"] is not None,
        "dmarc_valid": result["dmarc"]["valid"],
        "dmarc_policy": result["dmarc"]["policy"],
        "email_ready": (
            len(result["mx_records"]) > 0
            and result["spf"]["valid"]
            and result["dmarc"]["valid"]
        )
    }

    return result


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
            self._json(200, check_email(domain))
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

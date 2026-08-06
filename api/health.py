from http.server import BaseHTTPRequestHandler
import json
import urllib.parse

try:
    import dns.resolver
    import dns.exception
    DNS_OK = True
except ImportError:
    DNS_OK = False

DKIM_SELECTORS = [
    "default", "mail", "google", "k1", "k2", "s1", "s2",
    "smtp", "dkim", "email", "mimecast", "selector1", "selector2",
    "protonmail", "zoho", "sendgrid", "mailchimp", "amazonses",
]


def _resolve(resolver, domain, rtype):
    try:
        return list(resolver.resolve(domain, rtype))
    except Exception:
        return []


def check_health(domain):
    if not DNS_OK:
        return {"error": "dnspython not installed"}

    r = dns.resolver.Resolver()
    r.timeout = 4
    r.lifetime = 7

    checks = []
    score = 0
    max_score = 9

    def add(name, status, message, detail=None):
        nonlocal score
        entry = {"name": name, "status": status, "message": message}
        if detail:
            entry["detail"] = detail
        if status == "pass":
            score += 1
        checks.append(entry)

    # 1. A Record
    a = _resolve(r, domain, "A")
    if a:
        add("A Record", "pass", f"{len(a)} A record(s) found", [str(x) for x in a])
    else:
        add("A Record", "fail", "No A record — domain may not resolve to a server")

    # 2. MX Record(s)
    mx = _resolve(r, domain, "MX")
    if len(mx) >= 2:
        add("MX Redundancy", "pass", f"{len(mx)} MX records (redundant ✓)",
            sorted([f"[{x.preference}] {str(x.exchange).rstrip('.')}" for x in mx]))
    elif len(mx) == 1:
        add("MX Redundancy", "warn", "Only 1 MX record — recommend at least 2 for redundancy",
            [f"[{mx[0].preference}] {str(mx[0].exchange).rstrip('.')}"])
    else:
        add("MX Record", "fail", "No MX record — email cannot be received")

    # 3. NS Redundancy
    ns = _resolve(r, domain, "NS")
    if len(ns) >= 2:
        add("NS Redundancy", "pass", f"{len(ns)} NS records (redundant ✓)",
            [str(x).rstrip(".") for x in ns])
    elif len(ns) == 1:
        add("NS Redundancy", "warn", "Only 1 NS record — single point of failure",
            [str(ns[0]).rstrip(".")])
    else:
        add("NS Record", "fail", "No NS record found")

    # 4. SPF Record
    txt = _resolve(r, domain, "TXT")
    spf_records = []
    for t in txt:
        val = b"".join(t.strings).decode("utf-8", errors="replace")
        if val.startswith("v=spf1"):
            spf_records.append(val)

    if len(spf_records) == 1:
        add("SPF Record", "pass", "Valid SPF record found", spf_records)
    elif len(spf_records) > 1:
        add("SPF Record", "warn",
            f"Multiple SPF records found ({len(spf_records)}) — this is invalid, only 1 allowed",
            spf_records)
        score += 1
    else:
        add("SPF Record", "fail", "No SPF record — emails may be marked as spam")

    # 5. DMARC
    dmarc_txts = _resolve(r, f"_dmarc.{domain}", "TXT")
    dmarc_found = None
    for t in dmarc_txts:
        val = b"".join(t.strings).decode("utf-8", errors="replace")
        if "v=DMARC1" in val:
            dmarc_found = val
            break

    if dmarc_found:
        policy = "unknown"
        for part in dmarc_found.split(";"):
            p = part.strip()
            if p.startswith("p="):
                policy = p[2:].strip()
        add("DMARC Record", "pass", f"DMARC found (policy: {policy})", [dmarc_found])
    else:
        add("DMARC Record", "fail",
            "No DMARC record at _dmarc." + domain + " — email spoofing risk")

    # 6. DKIM (common selectors scan)
    dkim_found = None
    for sel in DKIM_SELECTORS:
        dkim_txts = _resolve(r, f"{sel}._domainkey.{domain}", "TXT")
        if dkim_txts:
            dkim_found = sel
            break

    if dkim_found:
        add("DKIM Record", "pass", f"DKIM found (selector: {dkim_found})")
    else:
        add("DKIM Record", "warn",
            "No common DKIM selector found — may exist with custom selector")
        # Warn = no score, but not a hard fail

    # 7. CAA Record
    caa = _resolve(r, domain, "CAA")
    if caa:
        details = []
        for c in caa:
            tag = c.tag.decode() if isinstance(c.tag, bytes) else str(c.tag)
            details.append(f"{tag}: {str(c.value).strip(chr(34))}")
        add("CAA Record", "pass", f"{len(caa)} CAA record(s) — SSL issuance controlled", details)
    else:
        add("CAA Record", "warn",
            "No CAA record — any CA can issue an SSL cert for this domain")
        # Warn = partial scoring
        score += 0  # No score for missing CAA

    # 8. SOA Record
    soa = _resolve(r, domain, "SOA")
    if soa:
        s = soa[0]
        add("SOA Record", "pass", f"SOA found — serial {s.serial}",
            [f"Primary NS: {str(s.mname).rstrip('.')}", f"Admin: {str(s.rname).rstrip('.')}"])
        score += 1
    else:
        add("SOA Record", "fail", "No SOA record found")

    # 9. IPv6 (AAAA)
    aaaa = _resolve(r, domain, "AAAA")
    if aaaa:
        add("IPv6 (AAAA)", "pass", f"IPv6 supported — {len(aaaa)} record(s)",
            [str(x) for x in aaaa])
        score += 1
    else:
        add("IPv6 (AAAA)", "warn", "No IPv6 (AAAA) record — IPv4 only")
        # Warn = no score

    # Grade
    pct = score / max_score
    grade = "A" if pct >= 0.88 else "B" if pct >= 0.72 else "C" if pct >= 0.55 else "D" if pct >= 0.4 else "F"

    return {
        "domain": domain,
        "score": score,
        "max_score": max_score,
        "grade": grade,
        "checks": checks
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
            self._json(200, check_health(domain))
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

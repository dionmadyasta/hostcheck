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


def clean_domain(raw):
    """Strip protocol, www, paths from input."""
    d = raw.strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    d = d.split("/")[0].split("?")[0].split("#")[0]
    return d


def resolve_records(domain):
    if not DNS_OK:
        return {"error": "dnspython not installed", "records": {}}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 7

    result = {"domain": domain, "records": {}, "error": None}
    record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "CAA"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                ttl = answers.rrset.ttl
                if rtype == "MX":
                    records.append({
                        "value": str(rdata.exchange).rstrip("."),
                        "priority": rdata.preference,
                        "ttl": ttl
                    })
                elif rtype == "SOA":
                    records.append({
                        "value": str(rdata),
                        "mname": str(rdata.mname).rstrip("."),
                        "rname": str(rdata.rname).rstrip(".").replace(".", "@", 1),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "ttl": ttl
                    })
                elif rtype == "CAA":
                    tag = rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag)
                    records.append({
                        "value": str(rdata.value).strip('"'),
                        "tag": tag,
                        "flags": rdata.flags,
                        "ttl": ttl
                    })
                elif rtype in ("NS", "CNAME"):
                    records.append({"value": str(rdata).rstrip("."), "ttl": ttl})
                elif rtype == "TXT":
                    # TXT records can be multi-part, join them
                    val = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    records.append({"value": val, "ttl": ttl})
                else:
                    records.append({"value": str(rdata), "ttl": ttl})
            result["records"][rtype] = records

        except dns.resolver.NoAnswer:
            result["records"][rtype] = []
        except dns.resolver.NXDOMAIN:
            result["records"][rtype] = []
            result["error"] = f'Domain "{domain}" does not exist (NXDOMAIN)'
        except dns.exception.Timeout:
            result["records"][rtype] = None  # None = timeout
        except Exception:
            result["records"][rtype] = []

    # PTR — reverse DNS of primary A record
    try:
        a_list = result["records"].get("A") or []
        if isinstance(a_list, list) and a_list:
            ip = a_list[0]["value"]
            ptr_host = socket.gethostbyaddr(ip)[0]
            result["records"]["PTR"] = [{"value": ptr_host, "ip": ip, "ttl": 0}]
        else:
            result["records"]["PTR"] = []
    except Exception:
        result["records"]["PTR"] = []

    return result


class handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        raw = qs.get("domain", [""])[0]
        domain = clean_domain(raw)

        if not domain:
            self._json(400, {"error": "Missing required parameter: domain"})
            return

        try:
            data = resolve_records(domain)
            self._json(200, data)
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

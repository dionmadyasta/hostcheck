from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import socket
import ssl
from datetime import datetime, timezone


def parse_dn(dn_tuple):
    """Convert RDNSequence list of tuples into a clean dictionary."""
    res = {}
    if not dn_tuple:
        return res
    for item in dn_tuple:
        for key, val in item:
            res[key] = val
    return res


def inspect_ssl(domain):
    result = {
        "domain": domain,
        "valid": False,
        "status": "unknown",  # valid, expiring_soon, expired, error
        "issuer": {},
        "subject": {},
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "serial_number": None,
        "sans": [],
        "version": None,
        "cipher": None,
        "error": None
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher, version, secret_bits = ssock.cipher()
                result["cipher"] = cipher
                result["version"] = version

                # Issuer & Subject
                result["issuer"] = parse_dn(cert.get("issuer"))
                result["subject"] = parse_dn(cert.get("subject"))

                # Serial Number
                result["serial_number"] = cert.get("serialNumber")

                # SANs (Subject Alternative Names)
                sans = []
                for type_, name in cert.get("subjectAltName", []):
                    if type_ == "DNS":
                        sans.append(name)
                result["sans"] = sans

                # Dates
                fmt = "%b %d %H:%M:%S %Y %Z"
                not_before = datetime.strptime(cert["notBefore"], fmt).replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)

                result["valid_from"] = not_before.isoformat()
                result["valid_to"] = not_after.isoformat()

                days_left = (not_after - now).days
                result["days_remaining"] = days_left

                if days_left < 0:
                    result["status"] = "expired"
                    result["valid"] = False
                elif days_left <= 30:
                    result["status"] = "expiring_soon"
                    result["valid"] = True
                else:
                    result["status"] = "valid"
                    result["valid"] = True

    except ssl.SSLCertVerificationError as e:
        result["status"] = "expired"
        result["error"] = f"Certificate verification failed: {e.verify_message}"
    except ssl.SSLError as e:
        result["status"] = "error"
        result["error"] = f"SSL error: {e.reason or str(e)}"
    except socket.timeout:
        result["status"] = "error"
        result["error"] = "Connection timed out on port 443"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:150]

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
            self._json(200, inspect_ssl(domain))
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

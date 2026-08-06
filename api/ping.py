from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import time

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

UA = "Mozilla/5.0 (compatible; HostCheck/1.0)"


def http_ping(domain):
    if not REQUESTS_OK:
        return {"error": "requests library not available"}

    result = {
        "domain": domain,
        "status_code": None,
        "latency_ms": None,
        "final_url": None,
        "redirect_chain": [],
        "ssl": False,
        "ssl_error": False,
        "server": None,
        "content_type": None,
        "x_powered_by": None,
        "content_length": None,
        "error": None
    }

    urls_to_try = [f"https://{domain}", f"http://{domain}"]

    for url in urls_to_try:
        try:
            start = time.time()
            r = requests.get(
                url,
                timeout=8,
                allow_redirects=True,
                headers={"User-Agent": UA}
            )
            elapsed = round((time.time() - start) * 1000)

            result["status_code"] = r.status_code
            result["latency_ms"] = elapsed
            result["final_url"] = r.url
            result["ssl"] = r.url.startswith("https://")
            result["server"] = r.headers.get("Server")
            result["content_type"] = r.headers.get("Content-Type", "").split(";")[0].strip()
            result["x_powered_by"] = r.headers.get("X-Powered-By")
            cl = r.headers.get("Content-Length")
            if cl:
                result["content_length"] = int(cl)

            # Build redirect chain
            for resp in r.history:
                result["redirect_chain"].append({
                    "from": resp.url,
                    "to": resp.headers.get("Location", "?"),
                    "status": resp.status_code
                })

            break  # Success — stop trying other URLs

        except requests.exceptions.SSLError as e:
            result["ssl_error"] = True
            result["error"] = f"SSL error: {str(e)[:100]}"
            # Try HTTP fallback
            continue
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection refused or host unreachable"
            continue
        except requests.exceptions.Timeout:
            result["error"] = "Request timed out (>8s)"
            continue
        except Exception as e:
            result["error"] = str(e)[:100]
            continue

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
            self._json(200, http_ping(domain))
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

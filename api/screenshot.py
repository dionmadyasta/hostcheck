from http.server import BaseHTTPRequestHandler
import json
import urllib.parse


def get_screenshot(domain):
    url = f"https://{domain}"
    encoded_url = urllib.parse.quote(url, safe="")
    
    # WordPress mshots — 100% free, no API key, unlimited (by Automattic)
    screenshot_url = f"https://s0.wp.com/mshots/v1/{encoded_url}?w=960&h=540"
    
    return {
        "domain": domain,
        "url": url,
        "screenshot_url": screenshot_url,
        "provider": "WordPress mshots"
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

        self._json(200, get_screenshot(domain))

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

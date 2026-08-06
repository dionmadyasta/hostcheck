from http.server import BaseHTTPRequestHandler
import json
import urllib.parse


def get_screenshot(domain):
    url = f"https://{domain}"
    return {
        "domain": domain,
        "url": url,
        # thum.io — free, no API key, instant thumbnail service
        "screenshot_url": f"https://image.thum.io/get/width/1200/crop/630/noanimate/{url}",
        "provider": "thum.io"
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

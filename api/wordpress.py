from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import re

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"


def detect_wordpress(domain):
    if not REQUESTS_OK:
        return {"error": "requests library not available"}

    result = {
        "domain": domain,
        "is_wordpress": False,
        "version": None,
        "php_version": None,
        "server": None,
        "theme": None,
        "wp_json_active": False,
        "wp_login_exposed": False,
        "readme_exposed": False,
        "site_name": None,
        "detection_methods": [],
        "headers": {}
    }

    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    base = f"https://{domain}"

    def get(url, timeout=7):
        try:
            return session.get(url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.SSLError:
            try:
                # Fallback to HTTP
                return session.get(url.replace("https://", "http://"), timeout=timeout, allow_redirects=True)
            except Exception:
                return None
        except Exception:
            return None

    # ─── 1. wp-json endpoint ─────────────────────────────────────────────────
    r = get(f"{base}/wp-json/")
    if r and r.status_code == 200:
        try:
            data = r.json()
            ns = data.get("namespaces", [])
            if "wp/v2" in ns or "wp/v2" in str(data):
                result["is_wordpress"] = True
                result["wp_json_active"] = True
                result["detection_methods"].append("wp-json")
                result["site_name"] = data.get("name", "")
        except Exception:
            if r and "WordPress" in r.text:
                result["is_wordpress"] = True
                result["detection_methods"].append("wp-json text")

        # Harvest headers
        if r:
            result["server"] = r.headers.get("Server")
            powered = r.headers.get("X-Powered-By", "")
            if "PHP" in powered:
                result["php_version"] = powered

    # ─── 2. readme.html ──────────────────────────────────────────────────────
    r2 = get(f"{base}/readme.html", timeout=5)
    if r2 and r2.status_code == 200 and "WordPress" in r2.text:
        result["is_wordpress"] = True
        result["readme_exposed"] = True
        result["detection_methods"].append("readme.html (exposed!)")
        m = re.search(r"Version\s+([\d.]+)", r2.text, re.IGNORECASE)
        if m:
            result["version"] = m.group(1)

    # ─── 3. Main page scan ───────────────────────────────────────────────────
    r3 = get(base, timeout=7)
    if r3 and r3.status_code == 200:
        html = r3.text

        # Server headers (if not already captured)
        if not result["server"]:
            result["server"] = r3.headers.get("Server")
        if not result["php_version"]:
            powered = r3.headers.get("X-Powered-By", "")
            if "PHP" in powered:
                result["php_version"] = powered

        # WP detection via content
        if "wp-content" in html or "wp-includes" in html:
            result["is_wordpress"] = True
            if "wp-content" not in result["detection_methods"]:
                result["detection_methods"].append("wp-content paths in HTML")

        # Version from meta generator
        if not result["version"]:
            m = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)',
                html, re.IGNORECASE
            )
            if not m:
                m = re.search(r'content=["\']WordPress\s+([\d.]+)', html, re.IGNORECASE)
            if m:
                result["version"] = m.group(1)
                result["detection_methods"].append("meta generator")

        # Version from asset ?ver= parameter
        if not result["version"] and result["is_wordpress"]:
            m = re.search(r'wp-includes/[^?]+\?ver=([\d.]+)', html)
            if m:
                result["version"] = m.group(1)
                result["detection_methods"].append("asset ver param")

        # Theme name
        m = re.search(r'/wp-content/themes/([^/"\s]+)/', html)
        if m:
            result["theme"] = m.group(1)

    # ─── 4. wp-login.php ─────────────────────────────────────────────────────
    if not result["is_wordpress"]:
        r4 = get(f"{base}/wp-login.php", timeout=5)
        if r4 and r4.status_code in (200, 302, 403):
            if r4.url and "wp-login" in r4.url:
                result["is_wordpress"] = True
                result["detection_methods"].append("wp-login.php redirect")

    # ─── 5. Collect key response headers ─────────────────────────────────────
    for resp in [r, r3]:
        if resp is None:
            continue
        for h in ["X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security",
                   "Content-Security-Policy", "X-Cache", "CF-Cache-Status"]:
            val = resp.headers.get(h)
            if val:
                result["headers"][h] = val
        break

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
            self._json(200, detect_wordpress(domain))
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

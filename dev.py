"""
HostCheck — Local Dev Server
Pure Python, no extra dependencies.
Usage: python3 dev.py
       python3 dev.py 8080  (custom port)
"""
import sys
import os
import json
import mimetypes
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

# Make sure api/ modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load .env for local API keys
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Import logic functions directly from each worker
from api.dns          import resolve_records
from api.propagation  import check_propagation
from api.health       import check_health
from api.wordpress    import detect_wordpress
from api.email        import check_email
from api.ip           import check_ip
from api.ping         import http_ping
from api.geo          import check_geo
from api.screenshot   import get_screenshot

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def clean(params, key):
    val = params.get(key, [''])[0].strip().lower()
    return val.replace('https://', '').replace('http://', '').split('/')[0]


# Route map: path → function that takes parsed params and returns dict
ROUTES = {
    '/api/dns':         lambda p: resolve_records(clean(p, 'domain')),
    '/api/health':      lambda p: check_health(clean(p, 'domain')),
    '/api/propagation': lambda p: check_propagation(clean(p, 'domain'), p.get('type', ['A'])[0].upper()),
    '/api/wordpress':   lambda p: detect_wordpress(clean(p, 'domain')),
    '/api/email':       lambda p: check_email(clean(p, 'domain')),
    '/api/ping':        lambda p: http_ping(clean(p, 'domain')),
    '/api/geo':         lambda p: check_geo(clean(p, 'domain')),
    '/api/ip':          lambda p: check_ip(p.get('ip', [''])[0].strip()),
    '/api/screenshot':  lambda p: get_screenshot(clean(p, 'domain')),
}


class DevServer(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # ── API routes ────────────────────────────────────────────
        if path in ROUTES:
            try:
                result = ROUTES[path](params)
                self._json(200, result)
            except Exception as e:
                self._json(500, {'error': str(e)})
            return

        # ── Static files ──────────────────────────────────────────
        if path == '/':
            path = '/index.html'

        file_path = os.path.join(BASE_DIR, path.lstrip('/'))

        if os.path.isfile(file_path):
            mime, _ = mimetypes.guess_type(file_path)
            with open(file_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', mime or 'text/plain')
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, f'Not found: {path}')

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def _json(self, code, data):
        body = json.dumps(data, default=str).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        status = args[1] if len(args) > 1 else '?'
        print(f'  {args[0]}  [{status}]')


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    server = HTTPServer(('localhost', port), DevServer)

    print()
    print('  ⚡ HostCheck dev server')
    print(f'  → http://localhost:{port}')
    print('  → Ctrl+C to stop')
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n  Stopped.')

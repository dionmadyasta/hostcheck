from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import time

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

GLOBALPING_API = "https://api.globalping.io/v1/measurements"

# 5 representative global regions
PROBE_LOCATIONS = [
    {"continent": "NA", "limit": 1},
    {"continent": "EU", "limit": 1},
    {"continent": "AS", "limit": 1},
    {"continent": "OC", "limit": 1},
    {"continent": "SA", "limit": 1},
]

CONTINENT_NAMES = {
    "NA": "North America",
    "EU": "Europe",
    "AS": "Asia",
    "OC": "Oceania",
    "SA": "South America",
    "AF": "Africa",
}

COUNTRY_FLAGS = {
    "US": "🇺🇸", "DE": "🇩🇪", "GB": "🇬🇧", "FR": "🇫🇷", "NL": "🇳🇱",
    "SG": "🇸🇬", "JP": "🇯🇵", "KR": "🇰🇷", "IN": "🇮🇳", "ID": "🇮🇩",
    "AU": "🇦🇺", "BR": "🇧🇷", "CA": "🇨🇦", "RU": "🇷🇺", "CN": "🇨🇳",
    "HK": "🇭🇰", "TW": "🇹🇼", "PH": "🇵🇭", "MY": "🇲🇾", "TH": "🇹🇭",
    "ZA": "🇿🇦", "NG": "🇳🇬", "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱",
    "PL": "🇵🇱", "SE": "🇸🇪", "FI": "🇫🇮", "CH": "🇨🇭", "ES": "🇪🇸",
}


def check_geo(domain):
    if not REQUESTS_OK:
        return {"error": "requests library not available"}

    result = {
        "domain": domain,
        "status": "pending",
        "results": [],
        "error": None
    }

    try:
        # 1. Submit measurement to GlobalPing
        payload = {
            "type": "http",
            "target": domain,
            "locations": PROBE_LOCATIONS,
            "limit": 5,
            "measurementOptions": {
                "protocol": "HTTPS",
                "request": {
                    "method": "HEAD",
                    "path": "/"
                },
                "ipVersion": 4
            }
        }

        r = requests.post(GLOBALPING_API, json=payload, timeout=10)

        if r.status_code == 202:
            measurement_id = r.json().get("id")
        elif r.status_code == 429:
            result["error"] = "GlobalPing rate limit reached — try again later"
            return result
        else:
            result["error"] = f"GlobalPing API error: {r.status_code}"
            return result

        # 2. Poll for results (up to 7 seconds)
        data = None
        for _ in range(5):
            time.sleep(1.5)
            poll = requests.get(
                f"{GLOBALPING_API}/{measurement_id}",
                timeout=5
            )
            if poll.status_code == 200:
                data = poll.json()
                status = data.get("status", "")
                if status in ("finished", "partial"):
                    break

        if not data:
            result["error"] = "Timeout waiting for geo results"
            return result

        result["status"] = data.get("status", "unknown")

        # 3. Format results
        for probe in data.get("results", []):
            probe_info = probe.get("probe", {})
            probe_result = probe.get("result", {})

            country_code = probe_info.get("country", "??")
            flag = COUNTRY_FLAGS.get(country_code, "🌐")
            continent = probe_info.get("continent", "?")

            timings = probe_result.get("timings", {})
            total_ms = timings.get("total")
            dns_ms = timings.get("dns")

            http_status = probe_result.get("statusCode")
            probe_status = probe_result.get("status", "unknown")

            result["results"].append({
                "location": f"{probe_info.get('city', 'Unknown')}, {country_code}",
                "city": probe_info.get("city", "Unknown"),
                "country": country_code,
                "flag": flag,
                "continent": CONTINENT_NAMES.get(continent, continent),
                "network": probe_info.get("network", "Unknown"),
                "status": probe_status,
                "http_status": http_status,
                "latency_ms": round(total_ms) if total_ms is not None else None,
                "dns_ms": round(dns_ms) if dns_ms is not None else None,
                "reachable": probe_status == "finished" and http_status in (200, 301, 302, 303, 307, 308),
            })

    except Exception as e:
        result["error"] = str(e)[:200]

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
            self._json(200, check_geo(domain))
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

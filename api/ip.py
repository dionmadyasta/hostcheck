from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import os

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def check_ip(ip):
    if not REQUESTS_OK:
        return {"error": "requests library not available"}

    result = {
        "ip": ip,
        "geo": {},
        "abuse": {},
        "error": None
    }

    # ─── Geolocation: ip-api.com (free, no key) ──────────────────────────────
    try:
        fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": fields},
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result["geo"] = {
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "zip": data.get("zip"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                }
            else:
                result["geo"]["error"] = data.get("message", "ip-api error")
    except Exception as e:
        result["geo"]["error"] = str(e)

    # ─── AbuseIPDB ───────────────────────────────────────────────────────────
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if api_key:
        try:
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            }
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=8
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                result["abuse"] = {
                    "is_public": data.get("isPublic"),
                    "ip_version": data.get("ipVersion"),
                    "is_whitelisted": data.get("isWhitelisted"),
                    "abuse_confidence_score": data.get("abuseConfidenceScore"),
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "total_reports": data.get("totalReports"),
                    "num_distinct_users": data.get("numDistinctUsers"),
                    "last_reported_at": data.get("lastReportedAt"),
                    "reports": [
                        {
                            "reported_at": rep.get("reportedAt"),
                            "comment": (rep.get("comment") or "")[:200],
                            "categories": rep.get("categories", []),
                            "reporter_country": rep.get("reporterCountryCode"),
                        }
                        for rep in (data.get("reports") or [])[:10]  # last 10 reports
                    ]
                }
            elif r.status_code == 429:
                result["abuse"]["error"] = "AbuseIPDB rate limit reached"
            else:
                result["abuse"]["error"] = f"AbuseIPDB returned status {r.status_code}"
        except Exception as e:
            result["abuse"]["error"] = str(e)
    else:
        result["abuse"]["error"] = "ABUSEIPDB_API_KEY not configured"

    # ─── Risk label ──────────────────────────────────────────────────────────
    score = result["abuse"].get("abuse_confidence_score")
    if score is not None:
        if score >= 75:
            result["risk_level"] = "high"
        elif score >= 25:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"

    return result


class handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        ip = qs.get("ip", [""])[0].strip()

        if not ip:
            self._json(400, {"error": "Missing required parameter: ip"})
            return

        try:
            self._json(200, check_ip(ip))
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

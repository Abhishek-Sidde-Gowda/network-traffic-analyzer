"""
Lightweight GeoIP resolver using ip-api.com (free, no API key needed).
Falls back to a local private-range classifier when offline.
"""
from __future__ import annotations

import ipaddress
import json
import urllib.request
import urllib.error
from functools import lru_cache

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


@lru_cache(maxsize=512)
def lookup(ip: str) -> dict:
    """Return GeoIP dict with keys: country, country_code, city, org, is_private."""
    if _is_private(ip):
        return {
            "country": "Private Network",
            "country_code": "LAN",
            "city": "",
            "org": "Internal",
            "is_private": True,
        }
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,org,status"
        req = urllib.request.Request(url, headers={"User-Agent": "NTA/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "??"),
                "city": data.get("city", ""),
                "org": data.get("org", ""),
                "is_private": False,
            }
    except Exception:
        pass
    return {
        "country": "Unknown",
        "country_code": "??",
        "city": "",
        "org": "",
        "is_private": False,
    }


def enrich_flows(records: list[dict], max_lookups: int = 50) -> list[dict]:
    """Add country/org fields to flow records (limits external calls)."""
    seen: dict[str, dict] = {}
    calls = 0
    for rec in records:
        for field in ("src_ip", "dst_ip"):
            ip = rec.get(field, "")
            if ip and ip not in seen:
                if calls < max_lookups:
                    seen[ip] = lookup(ip)
                    calls += 1
                else:
                    seen[ip] = {"country": "—", "country_code": "—", "city": "", "org": "", "is_private": False}
            if ip in seen:
                prefix = "src" if field == "src_ip" else "dst"
                rec[f"{prefix}_country"] = seen[ip]["country"]
                rec[f"{prefix}_country_code"] = seen[ip]["country_code"]
                rec[f"{prefix}_org"] = seen[ip]["org"]
    return records

"""
threat_intel.py — VirusTotal, AbuseIPDB, MalwareBazaar lookups.

Same pattern as the IOC Enricher project, adapted for use inside the
phishing analyzer (checking origin IPs, URL domains, and attachment hashes).
"""

import os
import httpx

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")


async def check_vt_ip(ip: str) -> dict:
    if not VT_API_KEY:
        return {}
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    return {}


async def check_vt_domain(domain: str) -> dict:
    if not VT_API_KEY:
        return {}
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    return {}


async def check_vt_hash(file_hash: str) -> dict:
    if not VT_API_KEY:
        return {}
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    return {}


async def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    return {}


async def check_malwarebazaar(file_hash: str) -> dict:
    if not MALWAREBAZAAR_API_KEY:
        return {"query_status": "no_api_key"}
    headers = {"Auth-Key": MALWAREBAZAAR_API_KEY}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                headers=headers,
                data={"query": "get_info", "hash": file_hash},
            )
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    return {}


def parse_vt_stats(vt_data: dict) -> dict:
    """Normalize VT response into {malicious, total, ratio}."""
    try:
        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        total = sum(stats.values())
        return {"malicious": stats.get("malicious", 0), "total": total,
                "ratio": f"{stats.get('malicious', 0)}/{total}"}
    except Exception:
        return {"malicious": 0, "total": 0, "ratio": "0/0"}

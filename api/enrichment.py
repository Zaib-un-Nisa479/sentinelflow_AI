import base64
import certifi
import httpx
import os
from datetime import datetime

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Before: query_virustotal always hit the /ip_addresses/ endpoint, no matter
# what ioc_type was passed in. A domain or hash sent through would either
# 404 or, worse, silently return garbage stats for the wrong resource type.
# This maps ioc_type -> the correct VirusTotal v3 endpoint shape.
VT_ENDPOINTS = {
    "ip": "ip_addresses/{ioc}",
    "domain": "domains/{ioc}",
    "hash": "files/{ioc}",
    # VT identifies URLs by a base64(no padding) hash of the URL itself,
    # not the raw URL string in the path.
    "url": "urls/{ioc}",
}


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def query_virustotal(ioc: str, ioc_type: str = "ip") -> dict:
    if ioc_type not in VT_ENDPOINTS:
        return {
            "source": "virustotal",
            "error": f"Unsupported ioc_type '{ioc_type}'",
            "malicious_count": 0,
            "suspicious_count": 0,
        }

    path_ioc = _vt_url_id(ioc) if ioc_type == "url" else ioc
    path = VT_ENDPOINTS[ioc_type].format(ioc=path_ioc)
    url = f"https://www.virustotal.com/api/v3/{path}"
    headers = {"x-apikey": VT_API_KEY}

    async with httpx.AsyncClient(verify=certifi.where()) as client:
        try:
            resp = await client.get(url, headers=headers, timeout=10)
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "raw": data,
            }
        except Exception as e:
            return {"source": "virustotal", "error": str(e), "malicious_count": 0, "suspicious_count": 0}


async def query_abuseipdb(ioc: str, ioc_type: str = "ip") -> dict:
    # AbuseIPDB is IP-only by design. For any other ioc_type, skip the call
    # cleanly instead of sending a domain/hash into an endpoint that expects
    # an IP address and getting back a confusing error.
    if ioc_type != "ip":
        return {
            "source": "abuseipdb",
            "skipped": True,
            "reason": f"AbuseIPDB does not support ioc_type '{ioc_type}'",
            "abuse_confidence_score": 0,
            "total_reports": 0,
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}
    async with httpx.AsyncClient(verify=certifi.where()) as client:
        try:
            resp = await client.get(url, headers=headers, params=params, timeout=10)
            data = resp.json()
            confidence = data.get("data", {}).get("abuseConfidenceScore", 0)
            total_reports = data.get("data", {}).get("totalReports", 0)
            return {
                "source": "abuseipdb",
                "abuse_confidence_score": confidence,
                "total_reports": total_reports,
                "raw": data,
            }
        except Exception as e:
            return {"source": "abuseipdb", "error": str(e), "abuse_confidence_score": 0, "total_reports": 0}


def compute_composite_score(vt_result: dict, abuse_result: dict) -> dict:
    """
    Weighted composite risk score, combining two independent threat-intel sources.
    MAX, not average — see original rationale: a strong flag from either source
    is worth escalating on, and false negatives are costlier than false positives
    in a security triage context.
    """
    vt_score = min(100, (vt_result.get("malicious_count", 0) * 8) +
                         (vt_result.get("suspicious_count", 0) * 3))

    abuse_score = abuse_result.get("abuse_confidence_score", 0)

    composite_score = max(vt_score, abuse_score)

    if composite_score >= 70:
        verdict = "malicious"
    elif composite_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "benign"

    return {
        "score": composite_score,
        "verdict": verdict,
        "vt_contribution": vt_score,
        "abuseipdb_contribution": abuse_score,
    }


async def enrich_ioc(ioc: str, ioc_type: str = "ip") -> dict:
    vt_result = await query_virustotal(ioc, ioc_type)
    abuse_result = await query_abuseipdb(ioc, ioc_type)
    scoring = compute_composite_score(vt_result, abuse_result)
    return {
        "ioc": ioc,
        "riskScore": scoring["score"],
        "verdict": scoring["verdict"],
        "sources": [vt_result, abuse_result],
        "scoreBreakdown": {
            "virustotal": scoring["vt_contribution"],
            "abuseipdb": scoring["abuseipdb_contribution"],
        },
        "enrichedAt": datetime.utcnow().isoformat(),
    }
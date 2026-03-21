"""
VirusTotal v3 API client for threat intelligence enrichment.

Capabilities:
  - File hash reputation lookup
  - URL/domain/IP analysis
  - File submission and scanning
  - Behavioral sandbox reports
  - Relationship graph queries (related domains, contacted IPs)

API docs: https://developers.virustotal.com/reference/overview
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class VirusTotalClient:
    """
    VirusTotal v3 API client for malware and IOC enrichment.

    Usage:
        vt = VirusTotalClient(api_key="YOUR_VT_API_KEY")
        result = vt.get_file_report("44d88612fea8a8f36de82e1278abb02f")
        if result.is_malicious:
            print(f"Malicious! {result.detections}/{result.total_engines} engines")
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, rate_limit_delay: float = 15.0):
        """
        Args:
            api_key: VirusTotal API key
            rate_limit_delay: Seconds to wait between requests (4 req/min for free tier)
        """
        self.api_key = api_key
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time: float = 0

        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required. Run: pip install requests")

    def _headers(self) -> dict:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def _get(self, endpoint: str, params: dict = None) -> dict:
        self._rate_limit()
        resp = requests.get(
            f"{self.BASE_URL}/{endpoint.lstrip('/')}",
            headers=self._headers(),
            params=params,
            timeout=30,
        )
        if resp.status_code == 404:
            return {"error": "not_found", "status_code": 404}
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, data=None, files=None, json_data=None) -> dict:
        self._rate_limit()
        resp = requests.post(
            f"{self.BASE_URL}/{endpoint.lstrip('/')}",
            headers=self._headers() if not files else {"x-apikey": self.api_key},
            data=data,
            files=files,
            json=json_data,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()

    def _rate_limit(self):
        """Enforce rate limiting to avoid API quota errors."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    # ------------------------------------------------------------------
    # File Analysis
    # ------------------------------------------------------------------

    def get_file_report(self, file_hash: str) -> dict:
        """
        Get analysis report for a file by MD5, SHA1, or SHA256 hash.

        Returns normalized dict with:
          - is_malicious: bool
          - detections: int
          - total_engines: int
          - threat_names: list
          - threat_categories: list
          - first_seen: str
          - last_analysis_date: str
          - tags: list
        """
        raw = self._get(f"/files/{file_hash}")
        if "error" in raw:
            return {"hash": file_hash, "found": False, "error": raw.get("error")}

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        threat_names = list(set(
            r.get("result") for r in results.values()
            if r.get("result") and r.get("category") in ("malicious", "suspicious")
        ))

        return {
            "hash": file_hash,
            "found": True,
            "is_malicious": malicious > 0,
            "detections": malicious + suspicious,
            "total_engines": total,
            "detection_ratio": f"{malicious + suspicious}/{total}",
            "threat_names": threat_names[:10],
            "threat_categories": list(set(
                r.get("category", "") for r in results.values()
                if r.get("category") in ("malicious", "suspicious")
            )),
            "first_submission": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "file_type": attrs.get("type_description"),
            "file_size": attrs.get("size"),
            "names": attrs.get("names", [])[:5],
            "tags": attrs.get("tags", []),
            "sandbox_verdict": attrs.get("sandbox_verdicts", {}),
            "vhash": attrs.get("vhash"),
            "magic": attrs.get("magic"),
            "raw": attrs,
        }

    def submit_file(self, file_path: str) -> str:
        """Submit a file for analysis and return the analysis ID."""
        path = Path(file_path)
        with open(path, "rb") as fh:
            resp = self._post(
                "/files",
                files={"file": (path.name, fh, "application/octet-stream")}
            )
        return resp.get("data", {}).get("id", "")

    def get_file_behavior(self, file_hash: str, sandbox: str = "") -> List[dict]:
        """Get behavioral/dynamic analysis reports for a file."""
        raw = self._get(f"/files/{file_hash}/behaviours")
        if "error" in raw:
            return []
        return raw.get("data", [])

    # ------------------------------------------------------------------
    # IP Analysis
    # ------------------------------------------------------------------

    def get_ip_report(self, ip_address: str) -> dict:
        """Get reputation and analysis report for an IP address."""
        raw = self._get(f"/ip_addresses/{ip_address}")
        if "error" in raw:
            return {"ip": ip_address, "found": False}

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1

        return {
            "ip": ip_address,
            "found": True,
            "is_malicious": malicious > 0,
            "detections": malicious,
            "total_engines": total,
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "asn": attrs.get("asn"),
            "reputation": attrs.get("reputation", 0),
            "whois": attrs.get("whois", "")[:500],
            "tags": attrs.get("tags", []),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

    # ------------------------------------------------------------------
    # Domain Analysis
    # ------------------------------------------------------------------

    def get_domain_report(self, domain: str) -> dict:
        """Get reputation report for a domain."""
        raw = self._get(f"/domains/{domain}")
        if "error" in raw:
            return {"domain": domain, "found": False}

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1

        return {
            "domain": domain,
            "found": True,
            "is_malicious": malicious > 0,
            "detections": malicious,
            "total_engines": total,
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "last_update_date": attrs.get("last_update_date"),
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
            "tags": attrs.get("tags", []),
            "last_dns_records": attrs.get("last_dns_records", [])[:5],
        }

    # ------------------------------------------------------------------
    # URL Analysis
    # ------------------------------------------------------------------

    def get_url_report(self, url: str) -> dict:
        """Get analysis report for a URL (URL ID = base64url-encoded URL)."""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        raw = self._get(f"/urls/{url_id}")
        if "error" in raw:
            return {"url": url, "found": False}

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1

        return {
            "url": url,
            "found": True,
            "is_malicious": malicious > 0,
            "detections": malicious,
            "total_engines": total,
            "categories": attrs.get("categories", {}),
            "final_url": attrs.get("last_final_url"),
            "title": attrs.get("title"),
            "tags": attrs.get("tags", []),
        }

    # ------------------------------------------------------------------
    # Bulk Enrichment
    # ------------------------------------------------------------------

    def enrich_ioc_bundle(self, ioc_bundle: dict, max_per_type: int = 10) -> dict:
        """
        Enrich an IOCBundle dict with VirusTotal data.
        Returns enrichment results keyed by IOC value.
        """
        enriched = {}

        for ip in list(ioc_bundle.get("ips", []))[:max_per_type]:
            enriched[ip] = self.get_ip_report(ip)

        for domain in list(ioc_bundle.get("domains", []))[:max_per_type]:
            enriched[domain] = self.get_domain_report(domain)

        for h in list(ioc_bundle.get("sha256s", []))[:max_per_type]:
            enriched[h] = self.get_file_report(h)

        for h in list(ioc_bundle.get("md5s", []))[:max_per_type]:
            if h not in enriched:
                enriched[h] = self.get_file_report(h)

        return enriched

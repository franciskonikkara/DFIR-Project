"""IOC (Indicator of Compromise) extraction from raw text/log data."""

import re
from dataclasses import dataclass, field
from typing import List, Set


# Regex patterns
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_RE_REGISTRY = re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s\"']+", re.IGNORECASE)


# Private ranges to exclude from IPs
_PRIVATE_NETS = (
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
)


@dataclass
class IOCBundle:
    ips: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    md5s: Set[str] = field(default_factory=set)
    sha1s: Set[str] = field(default_factory=set)
    sha256s: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    cves: Set[str] = field(default_factory=set)
    registry_keys: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "ips": sorted(self.ips),
            "domains": sorted(self.domains),
            "urls": sorted(self.urls),
            "md5s": sorted(self.md5s),
            "sha1s": sorted(self.sha1s),
            "sha256s": sorted(self.sha256s),
            "emails": sorted(self.emails),
            "cves": sorted(self.cves),
            "registry_keys": sorted(self.registry_keys),
        }

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.to_dict().values())


class IOCExtractor:
    """Extract indicators of compromise from text sources."""

    def __init__(self, exclude_private_ips: bool = True):
        self.exclude_private_ips = exclude_private_ips

    def extract(self, text: str) -> IOCBundle:
        """Extract all IOC types from a text string."""
        bundle = IOCBundle()

        # IPs
        for ip in _RE_IPV4.findall(text):
            if self.exclude_private_ips and any(p.match(ip) for p in _PRIVATE_NETS):
                continue
            bundle.ips.add(ip)

        # URLs (before domain extraction to avoid double-counting)
        bundle.urls.update(_RE_URL.findall(text))

        # Domains (exclude those already in URLs)
        url_set = bundle.urls
        for domain in _RE_DOMAIN.findall(text):
            if not any(domain in u for u in url_set):
                bundle.domains.add(domain.lower())

        # Hashes
        bundle.sha256s.update(h.lower() for h in _RE_SHA256.findall(text))
        remaining = re.sub(_RE_SHA256.pattern, "", text)
        bundle.sha1s.update(h.lower() for h in _RE_SHA1.findall(remaining))
        remaining2 = re.sub(_RE_SHA1.pattern, "", remaining)
        bundle.md5s.update(h.lower() for h in _RE_MD5.findall(remaining2))

        # Other types
        bundle.emails.update(e.lower() for e in _RE_EMAIL.findall(text))
        bundle.cves.update(c.upper() for c in _RE_CVE.findall(text))
        bundle.registry_keys.update(_RE_REGISTRY.findall(text))

        return bundle

    def extract_from_file(self, file_path: str) -> IOCBundle:
        """Extract IOCs from a file."""
        with open(file_path, "r", errors="replace") as fh:
            return self.extract(fh.read())

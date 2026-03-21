"""
IOC Matcher - match threat intelligence IOCs against log data and events.

Supports matching:
  - IP addresses against event logs
  - Domain names against DNS logs
  - File hashes against process/file events
  - CVE identifiers against vulnerability data
  - MITRE techniques against behavioral events

Integrates with MISP, OpenCTI, AlienVault OTX, and local IOC feeds.
"""

import csv
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set


@dataclass
class IOCEntry:
    value: str
    ioc_type: str       # ip | domain | hash_md5 | hash_sha1 | hash_sha256 | url | email | cve
    source: str
    confidence: int     # 0-100
    severity: str
    tags: List[str]
    added_at: str
    description: str = ""
    mitre_technique: str = ""
    expiry: Optional[str] = None


@dataclass
class IOCHit:
    ioc: IOCEntry
    matched_field: str
    matched_value: str
    event: dict
    hit_time: str
    host: str


class IOCMatcher:
    """
    Match IOCs against log events and telemetry data.

    Usage:
        matcher = IOCMatcher()
        matcher.load_ioc_csv("threat_intel/iocs.csv")
        matcher.load_misp_feed("threat_intel/misp_feed.json")
        hits = matcher.match_events(wazuh_alerts)
        matcher.export_hits_csv(hits, "ioc_hits.csv")
    """

    def __init__(self):
        self._iocs: Dict[str, List[IOCEntry]] = {
            "ip": [], "domain": [], "hash_md5": [], "hash_sha1": [],
            "hash_sha256": [], "url": [], "email": [], "cve": []
        }
        # Fast lookup sets
        self._ip_set: Set[str] = set()
        self._domain_set: Set[str] = set()
        self._md5_set: Set[str] = set()
        self._sha1_set: Set[str] = set()
        self._sha256_set: Set[str] = set()

    # ------------------------------------------------------------------
    # IOC Loading
    # ------------------------------------------------------------------

    def add_ioc(self, ioc: IOCEntry):
        """Add a single IOC to the matcher."""
        ioc_type = ioc.ioc_type.lower()
        if ioc_type in self._iocs:
            self._iocs[ioc_type].append(ioc)
        self._update_sets(ioc)

    def load_ioc_csv(self, csv_path: str, field_map: dict = None) -> int:
        """
        Load IOCs from a CSV file.

        Default column mapping: value, type, source, confidence, severity, tags, description
        """
        fm = field_map or {
            "value": "value", "type": "type", "source": "source",
            "confidence": "confidence", "severity": "severity",
        }
        count = 0
        with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    ioc = IOCEntry(
                        value=row.get(fm.get("value", "value"), "").strip().lower(),
                        ioc_type=row.get(fm.get("type", "type"), "ip").strip().lower(),
                        source=row.get(fm.get("source", "source"), "unknown"),
                        confidence=int(row.get(fm.get("confidence", "confidence"), 50) or 50),
                        severity=row.get(fm.get("severity", "severity"), "medium"),
                        tags=row.get("tags", "").split(",") if row.get("tags") else [],
                        added_at=datetime.now(timezone.utc).isoformat(),
                        description=row.get("description", ""),
                    )
                    if ioc.value:
                        self.add_ioc(ioc)
                        count += 1
                except (ValueError, KeyError):
                    continue
        return count

    def load_misp_feed(self, json_path: str) -> int:
        """Load IOCs from a MISP event JSON export."""
        count = 0
        with open(json_path) as fh:
            data = json.load(fh)

        events = data if isinstance(data, list) else [data]
        for event in events:
            misp_event = event.get("Event", event)
            source = misp_event.get("info", "MISP")
            for attr in misp_event.get("Attribute", []):
                attr_type = attr.get("type", "")
                value = str(attr.get("value", "")).strip().lower()
                if not value:
                    continue

                ioc_type = self._map_misp_type(attr_type)
                if not ioc_type:
                    continue

                ioc = IOCEntry(
                    value=value,
                    ioc_type=ioc_type,
                    source=source,
                    confidence=int(attr.get("confidence", 75) or 75),
                    severity="high",
                    tags=[t.get("name", "") for t in attr.get("Tag", [])],
                    added_at=attr.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    description=attr.get("comment", ""),
                )
                self.add_ioc(ioc)
                count += 1
        return count

    def load_otx_pulse(self, json_path: str) -> int:
        """Load IOCs from an AlienVault OTX pulse JSON export."""
        count = 0
        with open(json_path) as fh:
            pulse = json.load(fh)

        source = pulse.get("name", "OTX")
        for indicator in pulse.get("indicators", []):
            ioc_type = self._map_otx_type(indicator.get("type", ""))
            value = str(indicator.get("indicator", "")).strip().lower()
            if not value or not ioc_type:
                continue
            ioc = IOCEntry(
                value=value,
                ioc_type=ioc_type,
                source=source,
                confidence=int(indicator.get("confidence", 75)),
                severity="high",
                tags=indicator.get("tags", []),
                added_at=indicator.get("created", datetime.now(timezone.utc).isoformat()),
                description=indicator.get("description", ""),
            )
            self.add_ioc(ioc)
            count += 1
        return count

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match_event(self, event: dict) -> List[IOCHit]:
        """Match a single event dict against all loaded IOCs."""
        hits = []
        event_str = json.dumps(event).lower()
        host = str(event.get("host") or event.get("agent", {}).get("name") or "unknown")

        # IP matching
        ips_in_event = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', event_str)
        for ip in ips_in_event:
            for ioc in self._iocs.get("ip", []):
                if ioc.value == ip:
                    hits.append(IOCHit(
                        ioc=ioc, matched_field="ip", matched_value=ip,
                        event=event, hit_time=datetime.now(timezone.utc).isoformat(), host=host
                    ))

        # Domain matching
        domains_in_event = re.findall(r'\b(?:[a-z0-9][-a-z0-9]{0,61}[a-z0-9]?\.)+[a-z]{2,}\b', event_str)
        for domain in domains_in_event:
            if domain in self._domain_set:
                for ioc in self._iocs.get("domain", []):
                    if ioc.value == domain:
                        hits.append(IOCHit(
                            ioc=ioc, matched_field="domain", matched_value=domain,
                            event=event, hit_time=datetime.now(timezone.utc).isoformat(), host=host
                        ))

        # Hash matching
        sha256s = re.findall(r'\b[0-9a-f]{64}\b', event_str)
        for h in sha256s:
            if h in self._sha256_set:
                for ioc in self._iocs.get("hash_sha256", []):
                    if ioc.value == h:
                        hits.append(IOCHit(
                            ioc=ioc, matched_field="sha256", matched_value=h,
                            event=event, hit_time=datetime.now(timezone.utc).isoformat(), host=host
                        ))

        return hits

    def match_events(self, events: List[dict]) -> List[IOCHit]:
        """Match a list of events against all IOCs."""
        all_hits = []
        for event in events:
            all_hits.extend(self.match_event(event))
        return all_hits

    def match_file_hashes(self, hash_list: List[str]) -> List[IOCEntry]:
        """Check a list of file hashes against the IOC database."""
        results = []
        for h in hash_list:
            h = h.lower()
            if len(h) == 32 and h in self._md5_set:
                results.extend([i for i in self._iocs["hash_md5"] if i.value == h])
            elif len(h) == 40 and h in self._sha1_set:
                results.extend([i for i in self._iocs["hash_sha1"] if i.value == h])
            elif len(h) == 64 and h in self._sha256_set:
                results.extend([i for i in self._iocs["hash_sha256"] if i.value == h])
        return results

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_hits_csv(self, hits: List[IOCHit], output_path: str) -> str:
        """Export IOC hit results to CSV."""
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "Hit Time", "Host", "IOC Value", "IOC Type", "Severity",
                "Confidence", "Source", "Matched Field", "Description"
            ])
            for hit in hits:
                writer.writerow([
                    hit.hit_time, hit.host, hit.ioc.value, hit.ioc.ioc_type,
                    hit.ioc.severity, hit.ioc.confidence, hit.ioc.source,
                    hit.matched_field, hit.ioc.description[:100]
                ])
        return output_path

    def get_stats(self) -> dict:
        return {
            ioc_type: len(iocs)
            for ioc_type, iocs in self._iocs.items()
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_sets(self, ioc: IOCEntry):
        t = ioc.ioc_type
        v = ioc.value
        if t == "ip":
            self._ip_set.add(v)
        elif t == "domain":
            self._domain_set.add(v)
        elif t == "hash_md5":
            self._md5_set.add(v)
        elif t == "hash_sha1":
            self._sha1_set.add(v)
        elif t == "hash_sha256":
            self._sha256_set.add(v)

    @staticmethod
    def _map_misp_type(misp_type: str) -> Optional[str]:
        mapping = {
            "ip-src": "ip", "ip-dst": "ip", "ip-src|port": "ip", "ip-dst|port": "ip",
            "domain": "domain", "hostname": "domain", "domain|ip": "domain",
            "md5": "hash_md5", "sha1": "hash_sha1", "sha256": "hash_sha256",
            "url": "url", "email-src": "email", "email-dst": "email",
            "vulnerability": "cve",
        }
        return mapping.get(misp_type)

    @staticmethod
    def _map_otx_type(otx_type: str) -> Optional[str]:
        mapping = {
            "IPv4": "ip", "IPv6": "ip",
            "domain": "domain", "hostname": "domain",
            "FileHash-MD5": "hash_md5", "FileHash-SHA1": "hash_sha1",
            "FileHash-SHA256": "hash_sha256",
            "URL": "url", "email": "email",
            "CVE": "cve",
        }
        return mapping.get(otx_type)

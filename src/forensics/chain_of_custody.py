"""
Chain of Custody (CoC) documentation for digital evidence.

Implements NIST SP 800-86 and ACPO Principles for defensible evidence handling.
Each evidence item gets a unique ID, cryptographic hashes at acquisition time,
and a full audit trail of every transfer/access.
"""

import hashlib
import json
import os
import platform
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from src.utils.hash_utils import compute_hashes


@dataclass
class CustodyEvent:
    timestamp: str
    action: str          # acquired | transferred | accessed | analyzed | stored
    actor: str           # analyst name / system
    location: str        # physical or logical location
    notes: str = ""


@dataclass
class EvidenceItem:
    evidence_id: str
    case_id: str
    description: str
    source_path: str
    acquisition_timestamp: str
    acquired_by: str
    md5: str
    sha1: str
    sha256: str
    file_size_bytes: int
    evidence_type: str   # disk_image | memory_dump | pcap | log | malware_sample | other
    custody_log: List[CustodyEvent] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def add_event(self, action: str, actor: str, location: str, notes: str = ""):
        self.custody_log.append(CustodyEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            actor=actor,
            location=location,
            notes=notes,
        ))

    def verify_integrity(self, current_path: str) -> dict:
        """Re-hash the file and compare against acquisition hashes."""
        current = compute_hashes(current_path, ("md5", "sha1", "sha256"))
        return {
            "md5_match": current["md5"] == self.md5,
            "sha1_match": current["sha1"] == self.sha1,
            "sha256_match": current["sha256"] == self.sha256,
            "intact": all([
                current["md5"] == self.md5,
                current["sha1"] == self.sha1,
                current["sha256"] == self.sha256,
            ]),
        }


class ChainOfCustody:
    """
    Manage chain of custody for a DFIR case.

    Usage:
        coc = ChainOfCustody(case_id="IR-2024-001", analyst="J. Smith",
                             output_dir="evidence_store/chain_of_custody")
        item = coc.acquire("C:/suspicious.exe", evidence_type="malware_sample",
                           description="Dropped binary from phishing email")
        coc.save()
    """

    def __init__(self, case_id: str, analyst: str, output_dir: str = "evidence_store/chain_of_custody"):
        self.case_id = case_id
        self.analyst = analyst
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.items: List[EvidenceItem] = []
        self._coc_file = self.output_dir / f"{case_id}_coc.json"

        if self._coc_file.exists():
            self._load()

    def acquire(
        self,
        source_path: str,
        evidence_type: str = "other",
        description: str = "",
        tags: list = None,
        notes: str = "",
    ) -> EvidenceItem:
        """Record acquisition of a new evidence item with hashes."""
        path = Path(source_path)
        if not path.exists():
            raise FileNotFoundError(f"Evidence file not found: {source_path}")

        hashes = compute_hashes(str(path), ("md5", "sha1", "sha256"))
        evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"

        item = EvidenceItem(
            evidence_id=evidence_id,
            case_id=self.case_id,
            description=description or path.name,
            source_path=str(path.resolve()),
            acquisition_timestamp=datetime.now(timezone.utc).isoformat(),
            acquired_by=self.analyst,
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
            file_size_bytes=path.stat().st_size,
            evidence_type=evidence_type,
            tags=tags or [],
            notes=notes,
        )
        item.add_event(
            action="acquired",
            actor=self.analyst,
            location=str(path.resolve()),
            notes=f"System: {platform.node()} | OS: {platform.system()} {platform.release()}",
        )
        self.items.append(item)
        self.save()
        return item

    def transfer(self, evidence_id: str, new_location: str, recipient: str, notes: str = ""):
        """Record transfer of custody."""
        item = self._get_item(evidence_id)
        item.add_event("transferred", recipient, new_location, notes)
        self.save()

    def access(self, evidence_id: str, accessor: str, purpose: str = ""):
        """Record read/analysis access without transfer."""
        item = self._get_item(evidence_id)
        item.add_event("accessed", accessor, "working copy", purpose)
        self.save()

    def verify_all(self) -> dict:
        """Verify integrity of all evidence items at their source paths."""
        results = {}
        for item in self.items:
            try:
                check = item.verify_integrity(item.source_path)
                results[item.evidence_id] = check
            except FileNotFoundError:
                results[item.evidence_id] = {"intact": False, "error": "File not found"}
        return results

    def save(self):
        """Persist the CoC registry to disk as JSON."""
        data = {
            "case_id": self.case_id,
            "analyst": self.analyst,
            "generated": datetime.now(timezone.utc).isoformat(),
            "evidence_items": [asdict(item) for item in self.items],
        }
        with open(self._coc_file, "w") as fh:
            json.dump(data, fh, indent=2, default=str)

    def export_report(self, output_path: Optional[str] = None) -> str:
        """Generate a human-readable CoC report."""
        lines = [
            "=" * 70,
            f"CHAIN OF CUSTODY REPORT",
            f"Case ID  : {self.case_id}",
            f"Analyst  : {self.analyst}",
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            "=" * 70,
            "",
        ]
        for item in self.items:
            lines += [
                f"Evidence ID  : {item.evidence_id}",
                f"Type         : {item.evidence_type}",
                f"Description  : {item.description}",
                f"Source       : {item.source_path}",
                f"Size         : {item.file_size_bytes:,} bytes",
                f"Acquired By  : {item.acquired_by}",
                f"Acquired At  : {item.acquisition_timestamp}",
                f"MD5          : {item.md5}",
                f"SHA1         : {item.sha1}",
                f"SHA256       : {item.sha256}",
                "",
                "  Custody Log:",
            ]
            for evt in item.custody_log:
                lines.append(
                    f"    [{evt.timestamp}] {evt.action.upper()} by {evt.actor} @ {evt.location}"
                )
                if evt.notes:
                    lines.append(f"      Notes: {evt.notes}")
            lines.append("-" * 70)

        report = "\n".join(lines)
        out_path = output_path or str(self.output_dir / f"{self.case_id}_coc_report.txt")
        with open(out_path, "w") as fh:
            fh.write(report)
        return out_path

    def _get_item(self, evidence_id: str) -> EvidenceItem:
        for item in self.items:
            if item.evidence_id == evidence_id:
                return item
        raise KeyError(f"Evidence ID not found: {evidence_id}")

    def _load(self):
        with open(self._coc_file) as fh:
            data = json.load(fh)
        self.items = []
        for raw in data.get("evidence_items", []):
            raw["custody_log"] = [CustodyEvent(**e) for e in raw.get("custody_log", [])]
            self.items.append(EvidenceItem(**raw))

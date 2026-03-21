"""
Evidence documentation reporter - generates per-artifact examination reports
and supports e-discovery data export (for litigation support workflows).
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


class EvidenceReporter:
    """
    Generate standardized evidence examination reports and e-discovery exports.

    Usage:
        reporter = EvidenceReporter(case_id="LIT-2024-001", output_dir="reports/")
        reporter.add_evidence_item(ev_item_dict)
        reporter.generate_evidence_log()
        reporter.generate_ediscovery_export()
    """

    def __init__(self, case_id: str, output_dir: str = "reports"):
        self.case_id = case_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._items: List[dict] = []

    def add_evidence_item(self, item: dict):
        self._items.append(item)

    def add_evidence_items(self, items: List[dict]):
        self._items.extend(items)

    def generate_evidence_log(self, output_path: Optional[str] = None) -> str:
        """Generate a CSV evidence log for court/litigation use."""
        out = output_path or str(self.output_dir / f"{self.case_id}_evidence_log.csv")
        with open(out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "Evidence ID", "Case ID", "Type", "Description",
                "Source Path", "File Size (bytes)",
                "MD5", "SHA1", "SHA256",
                "Acquired By", "Acquisition Time",
                "Chain of Custody Events", "Tags", "Notes"
            ])
            for item in self._items:
                coc_events = "; ".join(
                    f"{e.get('action','?')} by {e.get('actor','?')} @ {e.get('timestamp','?')[:19]}"
                    for e in item.get("custody_log", [])
                )
                writer.writerow([
                    item.get("evidence_id", ""),
                    item.get("case_id", ""),
                    item.get("evidence_type", ""),
                    item.get("description", ""),
                    item.get("source_path", ""),
                    item.get("file_size_bytes", 0),
                    item.get("md5", ""),
                    item.get("sha1", ""),
                    item.get("sha256", ""),
                    item.get("acquired_by", ""),
                    item.get("acquisition_timestamp", ""),
                    coc_events,
                    ", ".join(item.get("tags", [])),
                    item.get("notes", ""),
                ])
        return out

    def generate_ediscovery_export(self, output_path: Optional[str] = None) -> str:
        """
        Generate an e-discovery export in DAT/CSV format compatible with
        Concordance and other legal review platforms.
        """
        out = output_path or str(self.output_dir / f"{self.case_id}_ediscovery.dat")
        # Concordance DAT format uses þ (254) as field delimiter, ÿ (255) as text qualifier
        FIELD_SEP = "\xfe"
        TEXT_QUAL = "\xff"

        headers = [
            "BEGDOC", "ENDDOC", "FILENAME", "DOCDATE", "DOCTYPE",
            "CUSTODIAN", "MD5HASH", "SHA256HASH", "FILEPATH", "FILESIZE"
        ]

        lines = [FIELD_SEP.join(f"{TEXT_QUAL}{h}{TEXT_QUAL}" for h in headers)]
        for item in self._items:
            ev_id = item.get("evidence_id", "N/A")
            row = [
                ev_id, ev_id,
                item.get("description", ""),
                item.get("acquisition_timestamp", "")[:10],
                item.get("evidence_type", ""),
                item.get("acquired_by", ""),
                item.get("md5", ""),
                item.get("sha256", ""),
                item.get("source_path", ""),
                str(item.get("file_size_bytes", 0)),
            ]
            lines.append(FIELD_SEP.join(f"{TEXT_QUAL}{v}{TEXT_QUAL}" for v in row))

        with open(out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return out

    def generate_hash_verification_report(self, output_path: Optional[str] = None) -> str:
        """Generate a hash verification report for integrity attestation."""
        lines = [
            "EVIDENCE INTEGRITY VERIFICATION REPORT",
            "=" * 60,
            f"Case ID: {self.case_id}",
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            f"Total Items: {len(self._items)}",
            "=" * 60,
            "",
        ]

        all_intact = True
        for item in self._items:
            source = item.get("source_path", "")
            try:
                from src.utils.hash_utils import compute_hashes
                current = compute_hashes(source, ("md5", "sha256"))
                md5_ok = current["md5"] == item.get("md5", "")
                sha256_ok = current["sha256"] == item.get("sha256", "")
                intact = md5_ok and sha256_ok
                if not intact:
                    all_intact = False
                status = "✓ INTACT" if intact else "✗ MODIFIED"
            except FileNotFoundError:
                intact = False
                all_intact = False
                status = "✗ FILE NOT FOUND"

            lines += [
                f"Evidence ID: {item.get('evidence_id', 'N/A')}",
                f"Status     : {status}",
                f"Path       : {source}",
                f"MD5        : {item.get('md5', 'N/A')}",
                f"SHA256     : {item.get('sha256', 'N/A')}",
                "",
            ]

        lines += [
            "=" * 60,
            f"OVERALL INTEGRITY: {'✓ ALL INTACT' if all_intact else '✗ INTEGRITY FAILURES DETECTED'}",
        ]

        out = output_path or str(self.output_dir / f"{self.case_id}_hash_verification.txt")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return out

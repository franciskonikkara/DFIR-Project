"""
Event timeline builder for incident reconstruction.

Aggregates events from:
  - Windows Event Logs
  - Sysmon logs
  - Wazuh alerts
  - File system MAC times
  - Network logs
  - Custom analyst notes

Outputs to CSV, JSON, and HTML for visualization.
"""

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


EVENT_CATEGORIES = {
    "process": "Process Execution",
    "network": "Network Activity",
    "file": "File System Activity",
    "registry": "Registry Modification",
    "auth": "Authentication",
    "service": "Service/Task",
    "persistence": "Persistence",
    "lateral_movement": "Lateral Movement",
    "exfiltration": "Potential Exfiltration",
    "analyst_note": "Analyst Note",
    "alert": "Security Alert",
}

MITRE_TECHNIQUES = {
    "T1059": "Command and Scripting Interpreter",
    "T1055": "Process Injection",
    "T1003": "Credential Dumping",
    "T1083": "File and Directory Discovery",
    "T1021": "Remote Services",
    "T1071": "Application Layer Protocol (C2)",
    "T1547": "Boot/Logon Autostart Execution",
    "T1053": "Scheduled Task/Job",
    "T1078": "Valid Accounts",
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1041": "Exfiltration Over C2 Channel",
    "T1190": "Exploit Public-Facing Application",
    "T1566": "Phishing",
}


@dataclass
class TimelineEvent:
    timestamp: datetime
    category: str
    description: str
    source: str           # Event Log | Sysmon | Wazuh | FileSystem | Analyst
    host: str
    user: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    file_path: Optional[str] = None
    network_info: Optional[str] = None
    registry_key: Optional[str] = None
    event_id: Optional[int] = None
    rule_name: Optional[str] = None
    mitre_technique: Optional[str] = None
    severity: str = "info"   # info | low | medium | high | critical
    raw_data: str = ""
    analyst_note: str = ""


class EventTimeline:
    """
    Build and analyze a chronological incident timeline.

    Usage:
        tl = EventTimeline(case_id="IR-2024-001")
        tl.add_event(timestamp=dt, category="process", description="powershell.exe spawned",
                     source="Sysmon", host="WKSTN-01")
        tl.ingest_wazuh_alerts("alerts.json")
        tl.export_csv("timeline.csv")
    """

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.events: List[TimelineEvent] = []

    # ------------------------------------------------------------------
    # Event Ingestion
    # ------------------------------------------------------------------

    def add_event(self, **kwargs) -> TimelineEvent:
        """Add a single event to the timeline."""
        if "timestamp" in kwargs and isinstance(kwargs["timestamp"], str):
            kwargs["timestamp"] = self._parse_ts(kwargs["timestamp"])
        event = TimelineEvent(**kwargs)
        self.events.append(event)
        self.events.sort(key=lambda e: e.timestamp)
        return event

    def ingest_wazuh_alerts(self, alerts_json_path: str) -> int:
        """Parse Wazuh JSON alert export and add to timeline."""
        count = 0
        with open(alerts_json_path, "r", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    alert = json.loads(line)
                    ts_str = alert.get("timestamp") or alert.get("@timestamp", "")
                    ts = self._parse_ts(ts_str)
                    if not ts:
                        continue

                    rule = alert.get("rule", {})
                    agent = alert.get("agent", {})
                    syscheck = alert.get("syscheck", {})
                    data = alert.get("data", {})

                    self.events.append(TimelineEvent(
                        timestamp=ts,
                        category="alert",
                        description=rule.get("description", "Wazuh Alert"),
                        source="Wazuh",
                        host=agent.get("name", "unknown"),
                        event_id=rule.get("id"),
                        rule_name=rule.get("description"),
                        severity=self._map_wazuh_level(rule.get("level", 3)),
                        file_path=syscheck.get("path"),
                        raw_data=json.dumps(alert),
                    ))
                    count += 1
                except (json.JSONDecodeError, KeyError):
                    continue
        self.events.sort(key=lambda e: e.timestamp)
        return count

    def ingest_sysmon_csv(self, csv_path: str) -> int:
        """Parse Sysmon event CSV export."""
        count = 0
        with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                ts = self._parse_ts(row.get("UtcTime") or row.get("TimeCreated"))
                if not ts:
                    continue
                event_id = int(row.get("EventID", 0) or 0)
                desc = self._sysmon_event_description(event_id, row)
                self.events.append(TimelineEvent(
                    timestamp=ts,
                    category=self._sysmon_category(event_id),
                    description=desc,
                    source="Sysmon",
                    host=row.get("Computer", "unknown"),
                    user=row.get("User"),
                    process=row.get("Image") or row.get("ProcessName"),
                    pid=int(row.get("ProcessId", 0) or 0) or None,
                    file_path=row.get("TargetFilename") or row.get("ImageLoaded"),
                    network_info=f"{row.get('DestinationIp')}:{row.get('DestinationPort')}"
                                 if row.get("DestinationIp") else None,
                    event_id=event_id,
                    raw_data=json.dumps(row),
                ))
                count += 1
        self.events.sort(key=lambda e: e.timestamp)
        return count

    def ingest_windows_evtx_json(self, evtx_json_path: str) -> int:
        """Parse Windows EVTX JSON export (e.g., from python-evtx or evtx_dump)."""
        count = 0
        with open(evtx_json_path, "r", errors="replace") as fh:
            try:
                records = json.load(fh)
                if not isinstance(records, list):
                    records = [records]
            except json.JSONDecodeError:
                fh.seek(0)
                records = []
                for line in fh:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for rec in records:
            sys = rec.get("System", {})
            ts = self._parse_ts(sys.get("TimeCreated", {}).get("SystemTime") if isinstance(sys.get("TimeCreated"), dict) else sys.get("TimeCreated"))
            if not ts:
                continue
            event_id = int(sys.get("EventID", 0) or 0)
            event_data = rec.get("EventData", {})
            desc = f"EventID {event_id}: {json.dumps(event_data)[:100]}"
            self.events.append(TimelineEvent(
                timestamp=ts,
                category="auth" if event_id in {4624, 4625, 4648} else "process" if event_id == 4688 else "service",
                description=desc,
                source="Windows Event Log",
                host=sys.get("Computer", "unknown"),
                event_id=event_id,
                raw_data=json.dumps(rec),
            ))
            count += 1
        self.events.sort(key=lambda e: e.timestamp)
        return count

    def add_analyst_note(self, timestamp_str: str, note: str, analyst: str, host: str = "N/A") -> TimelineEvent:
        """Add a manual analyst observation to the timeline."""
        return self.add_event(
            timestamp=timestamp_str,
            category="analyst_note",
            description=note,
            source=f"Analyst: {analyst}",
            host=host,
            severity="info",
            analyst_note=note,
        )

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def get_attack_phases(self) -> dict:
        """Map timeline events to MITRE ATT&CK phases."""
        phase_map = {}
        for event in self.events:
            if event.mitre_technique:
                technique = event.mitre_technique
                if technique not in phase_map:
                    phase_map[technique] = []
                phase_map[technique].append({
                    "timestamp": event.timestamp.isoformat(),
                    "description": event.description,
                    "host": event.host,
                })
        return phase_map

    def get_events_by_severity(self, severity: str) -> List[TimelineEvent]:
        return [e for e in self.events if e.severity == severity]

    def get_events_for_host(self, host: str) -> List[TimelineEvent]:
        return [e for e in self.events if e.host.lower() == host.lower()]

    def get_summary(self) -> dict:
        from collections import Counter
        return {
            "total_events": len(self.events),
            "time_range": {
                "start": self.events[0].timestamp.isoformat() if self.events else None,
                "end": self.events[-1].timestamp.isoformat() if self.events else None,
            },
            "by_category": dict(Counter(e.category for e in self.events)),
            "by_severity": dict(Counter(e.severity for e in self.events)),
            "by_host": dict(Counter(e.host for e in self.events)),
            "by_source": dict(Counter(e.source for e in self.events)),
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_csv(self, output_path: str) -> str:
        """Export timeline to CSV."""
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "Timestamp (UTC)", "Severity", "Category", "Source",
                "Host", "User", "Process", "Description",
                "File Path", "Network Info", "Event ID", "MITRE", "Note"
            ])
            for e in self.events:
                writer.writerow([
                    e.timestamp.isoformat(), e.severity, e.category, e.source,
                    e.host, e.user or "", e.process or "", e.description,
                    e.file_path or "", e.network_info or "",
                    e.event_id or "", e.mitre_technique or "", e.analyst_note
                ])
        return output_path

    def export_json(self, output_path: str) -> str:
        """Export full timeline as JSON."""
        data = {
            "case_id": self.case_id,
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": self.get_summary(),
            "events": [
                {**e.__dict__, "timestamp": e.timestamp.isoformat()}
                for e in self.events
            ],
        }
        with open(output_path, "w") as fh:
            json.dump(data, fh, indent=2, default=str)
        return output_path

    def export_html(self, output_path: str) -> str:
        """Export timeline as a self-contained HTML report."""
        severity_colors = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107", "low": "#17a2b8", "info": "#6c757d"
        }
        rows = ""
        for e in self.events:
            color = severity_colors.get(e.severity, "#6c757d")
            rows += f"""
            <tr>
                <td style='white-space:nowrap'>{e.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td><span style='color:{color};font-weight:bold'>{e.severity.upper()}</span></td>
                <td>{e.category}</td>
                <td>{e.source}</td>
                <td>{e.host}</td>
                <td>{e.description[:120]}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html><head>
<title>Incident Timeline - {self.case_id}</title>
<meta charset='utf-8'>
<style>
body{{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}}
h1{{color:#00d4ff}}table{{width:100%;border-collapse:collapse}}
th{{background:#16213e;color:#00d4ff;padding:8px;text-align:left}}
tr:nth-child(even){{background:#16213e40}}td{{padding:6px 8px;border-bottom:1px solid #333;font-size:12px}}
</style>
</head><body>
<h1>Incident Timeline: {self.case_id}</h1>
<p>Generated: {datetime.now(timezone.utc).isoformat()} | Total Events: {len(self.events)}</p>
<table>
<tr><th>Timestamp</th><th>Severity</th><th>Category</th><th>Source</th><th>Host</th><th>Description</th></tr>
{rows}
</table></body></html>"""

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return output_path

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ts(value) -> Optional[datetime]:
        if not value:
            return None
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
            "%Y-%m-%dT%H:%M:%S.%f%z",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(str(value)[:26], fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        return datetime.now(timezone.utc)

    @staticmethod
    def _map_wazuh_level(level: int) -> str:
        if level >= 12:
            return "critical"
        elif level >= 9:
            return "high"
        elif level >= 6:
            return "medium"
        elif level >= 3:
            return "low"
        return "info"

    @staticmethod
    def _sysmon_category(event_id: int) -> str:
        mapping = {
            1: "process", 2: "file", 3: "network", 4: "service",
            5: "process", 6: "service", 7: "service", 8: "process",
            9: "file", 10: "process", 11: "file", 12: "registry",
            13: "registry", 14: "registry", 15: "file", 16: "service",
            17: "network", 18: "network", 19: "persistence",
            20: "persistence", 21: "persistence", 22: "network",
            23: "file", 25: "process", 26: "file",
        }
        return mapping.get(event_id, "other")

    @staticmethod
    def _sysmon_event_description(event_id: int, row: dict) -> str:
        templates = {
            1: "Process Created: {Image} (PID:{ProcessId}) Parent:{ParentImage}",
            3: "Network Connection: {Image} -> {DestinationIp}:{DestinationPort}",
            7: "DLL Loaded: {ImageLoaded} by {Image}",
            11: "File Created: {TargetFilename} by {Image}",
            12: "Registry Create/Delete: {TargetObject}",
            13: "Registry Set: {TargetObject} = {Details}",
            15: "File Stream Created: {TargetFilename}",
            22: "DNS Query: {QueryName} by {Image}",
        }
        template = templates.get(event_id, f"Sysmon Event {event_id}")
        try:
            return template.format_map({k: v or "" for k, v in row.items()})
        except KeyError:
            return template

"""Log parsing utilities for Windows Event Log, Syslog, and JSON log formats."""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional


@dataclass
class LogEntry:
    timestamp: Optional[datetime]
    source: str
    event_id: Optional[int]
    level: str
    message: str
    raw: str
    extra: dict


class LogParser:
    """Parse common log formats into normalized LogEntry objects."""

    # Syslog RFC 3164/5424 pattern
    _SYSLOG_RE = re.compile(
        r"^(?P<priority><\d+>)?(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<process>[^:]+):\s*(?P<message>.*)$"
    )
    # Windows Security Audit pattern (text export)
    _WIN_EVT_RE = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<level>\w+)\s+(?P<source>[^\s]+)\s+(?P<event_id>\d+)\s+(?P<message>.*)"
    )

    def parse_line(self, line: str) -> LogEntry:
        """Attempt to parse a single log line with multiple format detectors."""
        line = line.strip()

        # Try JSON
        if line.startswith("{"):
            try:
                data = json.loads(line)
                ts = self._parse_ts(data.get("timestamp") or data.get("@timestamp") or data.get("time"))
                return LogEntry(
                    timestamp=ts,
                    source=data.get("source", data.get("host", "unknown")),
                    event_id=data.get("event_id") or data.get("EventID"),
                    level=data.get("level", data.get("severity", "info")).upper(),
                    message=data.get("message", data.get("msg", line)),
                    raw=line,
                    extra=data,
                )
            except json.JSONDecodeError:
                pass

        # Try Windows Event log format
        m = self._WIN_EVT_RE.match(line)
        if m:
            return LogEntry(
                timestamp=self._parse_ts(m.group("timestamp")),
                source=m.group("source"),
                event_id=int(m.group("event_id")),
                level=m.group("level").upper(),
                message=m.group("message"),
                raw=line,
                extra={},
            )

        # Try Syslog
        m = self._SYSLOG_RE.match(line)
        if m:
            return LogEntry(
                timestamp=self._parse_ts(m.group("timestamp")),
                source=m.group("host"),
                event_id=None,
                level="INFO",
                message=m.group("message"),
                raw=line,
                extra={"process": m.group("process")},
            )

        # Fallback - unrecognised format
        return LogEntry(
            timestamp=None,
            source="unknown",
            event_id=None,
            level="UNKNOWN",
            message=line,
            raw=line,
            extra={},
        )

    def parse_file(self, file_path: str) -> Generator[LogEntry, None, None]:
        """Yield parsed LogEntry objects from a log file."""
        with open(file_path, "r", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    yield self.parse_line(line)

    def parse_evtx_xml(self, xml_string: str) -> List[LogEntry]:
        """Parse Windows EVTX XML export format."""
        entries = []
        try:
            root = ET.fromstring(xml_string)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            for event in root.findall(".//e:Event", ns):
                sys_node = event.find("e:System", ns)
                event_id = None
                level = "INFO"
                ts = None
                if sys_node is not None:
                    eid_node = sys_node.find("e:EventID", ns)
                    if eid_node is not None:
                        event_id = int(eid_node.text or 0)
                    lvl_node = sys_node.find("e:Level", ns)
                    if lvl_node is not None:
                        level = lvl_node.text or "INFO"
                    tc_node = sys_node.find("e:TimeCreated", ns)
                    if tc_node is not None:
                        ts = self._parse_ts(tc_node.get("SystemTime"))

                data_node = event.find("e:EventData", ns)
                message = ET.tostring(data_node, encoding="unicode") if data_node is not None else ""

                entries.append(LogEntry(
                    timestamp=ts,
                    source="Windows Event Log",
                    event_id=event_id,
                    level=str(level),
                    message=message,
                    raw=ET.tostring(event, encoding="unicode"),
                    extra={},
                ))
        except ET.ParseError:
            pass
        return entries

    @staticmethod
    def _parse_ts(value) -> Optional[datetime]:
        if not value:
            return None
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(str(value).strip(), fmt)
            except ValueError:
                continue
        return None

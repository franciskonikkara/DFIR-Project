"""
Threat hunting framework - hypothesis-based hunting against log/telemetry data.

Implements the Threat Hunting Maturity Model (HMM) levels 1-3:
  - Level 1: IOC-based hunting (reactive)
  - Level 2: TTP-based hunting (proactive)
  - Level 3: Analytics-based hunting (statistical anomaly detection)

Data sources: Wazuh, Sysmon, Windows Event Logs, network logs.
"""

import json
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Generator, List, Optional


@dataclass
class HuntHypothesis:
    hypothesis_id: str
    title: str
    description: str
    mitre_technique: str
    data_required: List[str]
    hunt_logic: str
    severity: str


@dataclass
class HuntFinding:
    hunt_id: str
    hypothesis_id: str
    timestamp: str
    host: str
    description: str
    evidence: dict
    severity: str
    mitre_technique: str
    false_positive_notes: str = ""


@dataclass
class HuntReport:
    hunt_id: str
    hypothesis: HuntHypothesis
    started_at: str
    completed_at: str
    data_sources_searched: List[str]
    records_examined: int
    findings: List[HuntFinding]
    conclusion: str


# Built-in hunt hypotheses
BUILT_IN_HYPOTHESES = [
    HuntHypothesis(
        hypothesis_id="HYP-001",
        title="Living-off-the-Land Binary Abuse",
        description="Detect abuse of Windows built-in binaries (LOLBins) for malicious execution",
        mitre_technique="T1218",
        data_required=["sysmon_event_1"],
        hunt_logic="Look for certutil, mshta, regsvr32, rundll32 spawning unusual child processes",
        severity="high",
    ),
    HuntHypothesis(
        hypothesis_id="HYP-002",
        title="Credential Dumping via LSASS",
        description="Detect LSASS memory access patterns indicative of credential theft",
        mitre_technique="T1003.001",
        data_required=["sysmon_event_10"],
        hunt_logic="Processes accessing LSASS with read permissions, excluding known AV/EDR",
        severity="critical",
    ),
    HuntHypothesis(
        hypothesis_id="HYP-003",
        title="Suspicious PowerShell Encoded Commands",
        description="Hunt for Base64 encoded PowerShell commands used to evade detection",
        mitre_technique="T1059.001",
        data_required=["sysmon_event_1", "windows_event_4104"],
        hunt_logic="PowerShell processes with -enc, -EncodedCommand, or -e flags",
        severity="high",
    ),
    HuntHypothesis(
        hypothesis_id="HYP-004",
        title="Lateral Movement via PsExec/WMI",
        description="Detect lateral movement using PsExec, WMI, or SMB",
        mitre_technique="T1021",
        data_required=["windows_event_4624", "sysmon_event_3"],
        hunt_logic="PSEXESVC service creation or WMI remote execution from unusual hosts",
        severity="high",
    ),
    HuntHypothesis(
        hypothesis_id="HYP-005",
        title="Scheduled Task Persistence",
        description="Detect creation of scheduled tasks for persistence",
        mitre_technique="T1053.005",
        data_required=["windows_event_4698", "sysmon_event_1"],
        hunt_logic="New scheduled tasks created outside of business hours or by non-admin accounts",
        severity="medium",
    ),
    HuntHypothesis(
        hypothesis_id="HYP-006",
        title="DNS Beaconing Pattern",
        description="Detect C2 beaconing via suspicious DNS query patterns",
        mitre_technique="T1071.004",
        data_required=["sysmon_event_22", "network_dns"],
        hunt_logic="High-frequency or algorithmically-generated domain queries (DGA detection)",
        severity="high",
    ),
    HuntHypothesis(
        hypothesis_id="HYP-007",
        title="Anomalous User Login Times",
        description="Detect logins outside of normal working hours for each user",
        mitre_technique="T1078",
        data_required=["windows_event_4624"],
        hunt_logic="User logins during weekend or late-night hours compared to baseline",
        severity="medium",
    ),
]

# LOLBins patterns
LOLBIN_PROCESSES = {
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wscript.exe", "cscript.exe", "msiexec.exe", "installutil.exe",
    "cmstp.exe", "xwizard.exe", "syncappvpublishingserver.exe",
    "appsyncpublishingserver.exe", "odbcconf.exe",
}

POWERSHELL_EVASION_RE = re.compile(
    r"-[Ee](?:nc(?:oded)?|xecutionpolicy)?(?:Command)?\s+[A-Za-z0-9+/=]{20,}", re.I
)

DGA_SUSPICIOUS_ENTROPY_THRESHOLD = 3.8  # bits per character


class ThreatHunter:
    """
    Execute threat hunting hypotheses against collected telemetry.

    Usage:
        hunter = ThreatHunter(case_id="TH-2024-001")
        hunter.load_sysmon_json("sysmon_events.json")
        findings = hunter.run_hypothesis("HYP-001")
        report = hunter.generate_report(findings)
    """

    def __init__(self, case_id: str, output_dir: str = "hunt_results"):
        self.case_id = case_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._events: List[dict] = []
        self._hunt_counter = 0

    # ------------------------------------------------------------------
    # Data Loading
    # ------------------------------------------------------------------

    def load_events_json(self, json_path: str) -> int:
        """Load events from a JSON file (Wazuh/SIEM export)."""
        with open(json_path, "r", errors="replace") as fh:
            try:
                data = json.load(fh)
                if isinstance(data, list):
                    self._events.extend(data)
                    return len(data)
            except json.JSONDecodeError:
                pass
            fh.seek(0)
            count = 0
            for line in fh:
                try:
                    self._events.append(json.loads(line))
                    count += 1
                except json.JSONDecodeError:
                    continue
        return count

    def load_events_from_list(self, events: List[dict]) -> int:
        """Load events directly from a Python list."""
        self._events.extend(events)
        return len(events)

    # ------------------------------------------------------------------
    # Hypothesis Execution
    # ------------------------------------------------------------------

    def run_hypothesis(self, hypothesis_id: str) -> List[HuntFinding]:
        """Run a specific built-in hypothesis."""
        hyp = self._get_hypothesis(hypothesis_id)
        handler = self._get_handler(hypothesis_id)
        if not handler:
            raise NotImplementedError(f"No handler for hypothesis: {hypothesis_id}")
        return handler(hyp)

    def run_all_hypotheses(self) -> Dict[str, List[HuntFinding]]:
        """Run all built-in hypotheses and return findings by hypothesis ID."""
        results = {}
        for hyp in BUILT_IN_HYPOTHESES:
            try:
                findings = self.run_hypothesis(hyp.hypothesis_id)
                results[hyp.hypothesis_id] = findings
            except NotImplementedError:
                results[hyp.hypothesis_id] = []
        return results

    def run_custom_hunt(
        self,
        title: str,
        hunt_fn: Callable[[List[dict]], List[dict]],
        mitre_technique: str = "",
        severity: str = "medium",
    ) -> List[HuntFinding]:
        """Execute a custom hunt function against loaded events."""
        raw_findings = hunt_fn(self._events)
        hunt_id = f"HUNT-{self._hunt_counter:04d}"
        self._hunt_counter += 1
        return [
            HuntFinding(
                hunt_id=hunt_id,
                hypothesis_id="CUSTOM",
                timestamp=datetime.now(timezone.utc).isoformat(),
                host=f.get("host", "unknown"),
                description=f.get("description", title),
                evidence=f,
                severity=severity,
                mitre_technique=mitre_technique,
            )
            for f in raw_findings
        ]

    # ------------------------------------------------------------------
    # Built-in Hunt Handlers
    # ------------------------------------------------------------------

    def _hunt_lolbin_abuse(self, hyp: HuntHypothesis) -> List[HuntFinding]:
        findings = []
        for event in self._events:
            proc = (event.get("process", {}) or event.get("data", {}) or event)
            image = str(proc.get("Image") or proc.get("exe") or proc.get("process_name") or "").lower()
            cmdline = str(proc.get("CommandLine") or proc.get("cmdline") or "")
            parent = str(proc.get("ParentImage") or proc.get("parent_name") or "").lower()

            for lolbin in LOLBIN_PROCESSES:
                if lolbin in image and ("http" in cmdline.lower() or "\\temp\\" in cmdline.lower()
                                         or "base64" in cmdline.lower()):
                    findings.append(HuntFinding(
                        hunt_id=f"HUNT-{self._hunt_counter:04d}",
                        hypothesis_id=hyp.hypothesis_id,
                        timestamp=event.get("timestamp", ""),
                        host=str(event.get("agent", {}).get("name") or event.get("host", "unknown")),
                        description=f"LOLBin abuse detected: {image} with suspicious cmdline",
                        evidence={"image": image, "cmdline": cmdline[:200], "parent": parent},
                        severity=hyp.severity,
                        mitre_technique=hyp.mitre_technique,
                    ))
                    self._hunt_counter += 1
        return findings

    def _hunt_powershell_encoded(self, hyp: HuntHypothesis) -> List[HuntFinding]:
        findings = []
        for event in self._events:
            proc = event.get("data", event)
            image = str(proc.get("Image") or proc.get("exe") or "").lower()
            cmdline = str(proc.get("CommandLine") or proc.get("cmdline") or "")
            if "powershell" in image and POWERSHELL_EVASION_RE.search(cmdline):
                findings.append(HuntFinding(
                    hunt_id=f"HUNT-{self._hunt_counter:04d}",
                    hypothesis_id=hyp.hypothesis_id,
                    timestamp=event.get("timestamp", ""),
                    host=str(event.get("agent", {}).get("name") or event.get("host", "unknown")),
                    description="Suspicious encoded PowerShell command",
                    evidence={"cmdline": cmdline[:300]},
                    severity=hyp.severity,
                    mitre_technique=hyp.mitre_technique,
                ))
                self._hunt_counter += 1
        return findings

    def _hunt_dns_beaconing(self, hyp: HuntHypothesis) -> List[HuntFinding]:
        """Detect DGA (Domain Generation Algorithm) by computing domain entropy."""
        findings = []
        domain_counts: Counter = Counter()
        domain_events: Dict[str, list] = defaultdict(list)

        for event in self._events:
            query = str(event.get("dns", {}).get("question", {}).get("name")
                        or event.get("QueryName") or "")
            if query and not query.endswith((".microsoft.com", ".windows.com", ".google.com")):
                domain_counts[query] += 1
                domain_events[query].append(event)

        for domain, count in domain_counts.items():
            # Check for high-entropy domain names (DGA indicator)
            label = domain.split(".")[0]
            if len(label) >= 6:
                ent = self._string_entropy(label)
                if ent > DGA_SUSPICIOUS_ENTROPY_THRESHOLD and count >= 3:
                    findings.append(HuntFinding(
                        hunt_id=f"HUNT-{self._hunt_counter:04d}",
                        hypothesis_id=hyp.hypothesis_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        host="network",
                        description=f"Potential DGA domain: {domain} (entropy={ent:.2f}, queries={count})",
                        evidence={"domain": domain, "query_count": count, "entropy": ent},
                        severity=hyp.severity,
                        mitre_technique=hyp.mitre_technique,
                    ))
                    self._hunt_counter += 1
        return findings

    def _hunt_lsass_access(self, hyp: HuntHypothesis) -> List[HuntFinding]:
        findings = []
        known_safe = {"antimalware", "defender", "antivirus", "splunk", "sysmon", "system"}
        for event in self._events:
            target = str(event.get("TargetImage") or event.get("target_image") or "").lower()
            source = str(event.get("SourceImage") or event.get("source_image") or "").lower()
            if "lsass.exe" in target:
                if not any(safe in source for safe in known_safe):
                    findings.append(HuntFinding(
                        hunt_id=f"HUNT-{self._hunt_counter:04d}",
                        hypothesis_id=hyp.hypothesis_id,
                        timestamp=event.get("timestamp", ""),
                        host=str(event.get("host", "unknown")),
                        description=f"LSASS access by unexpected process: {source}",
                        evidence={"source": source, "target": target},
                        severity=hyp.severity,
                        mitre_technique=hyp.mitre_technique,
                    ))
                    self._hunt_counter += 1
        return findings

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_report(self, findings_by_hyp: Dict[str, List[HuntFinding]]) -> str:
        """Generate a hunt summary report."""
        total_findings = sum(len(v) for v in findings_by_hyp.values())
        lines = [
            "=" * 60,
            f"THREAT HUNT REPORT: {self.case_id}",
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            f"Events Searched: {len(self._events)}",
            f"Total Findings: {total_findings}",
            "=" * 60, "",
        ]
        for hyp_id, findings in findings_by_hyp.items():
            hyp = self._get_hypothesis(hyp_id)
            lines.append(f"[{hyp_id}] {hyp.title if hyp else hyp_id}")
            lines.append(f"  MITRE: {hyp.mitre_technique if hyp else 'N/A'}")
            lines.append(f"  Findings: {len(findings)}")
            for f in findings[:5]:
                lines.append(f"    - [{f.severity.upper()}] {f.host}: {f.description[:80]}")
            lines.append("")

        report = "\n".join(lines)
        out = self.output_dir / f"{self.case_id}_hunt_report.txt"
        with open(out, "w") as fh:
            fh.write(report)
        return str(out)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_hypothesis(self, hyp_id: str) -> Optional[HuntHypothesis]:
        for hyp in BUILT_IN_HYPOTHESES:
            if hyp.hypothesis_id == hyp_id:
                return hyp
        return None

    def _get_handler(self, hyp_id: str):
        handlers = {
            "HYP-001": self._hunt_lolbin_abuse,
            "HYP-002": self._hunt_lsass_access,
            "HYP-003": self._hunt_powershell_encoded,
            "HYP-006": self._hunt_dns_beaconing,
        }
        return handlers.get(hyp_id)

    @staticmethod
    def _string_entropy(s: str) -> float:
        import math
        freq = Counter(s.lower())
        n = len(s)
        if n == 0:
            return 0.0
        return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)

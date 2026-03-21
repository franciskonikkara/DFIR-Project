"""
Incident Response Workflow Manager - PICERL Framework.

Phases: Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned

Integrates with TheHive for case management and Wazuh for alert correlation.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional


class IRPhase(str, Enum):
    PREPARATION = "preparation"
    IDENTIFICATION = "identification"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"
    CLOSED = "closed"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentCategory(str, Enum):
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    PHISHING = "phishing"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DOS_DDOS = "dos_ddos"
    SUPPLY_CHAIN = "supply_chain"
    OTHER = "other"


@dataclass
class IRTask:
    task_id: str
    phase: IRPhase
    title: str
    description: str
    assigned_to: str
    status: str = "pending"   # pending | in_progress | completed | blocked
    priority: str = "medium"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    notes: str = ""
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class IRNote:
    note_id: str
    timestamp: str
    author: str
    phase: IRPhase
    content: str
    iocs: List[str] = field(default_factory=list)


@dataclass
class IncidentRecord:
    incident_id: str
    title: str
    category: IncidentCategory
    severity: Severity
    created_at: str
    reported_by: str
    lead_analyst: str
    affected_systems: List[str]
    current_phase: IRPhase = IRPhase.IDENTIFICATION
    description: str = ""
    tasks: List[IRTask] = field(default_factory=list)
    notes: List[IRNote] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    thehive_case_id: Optional[str] = None
    wazuh_rule_id: Optional[str] = None
    closed_at: Optional[str] = None
    executive_summary: str = ""
    timeline_events: List[dict] = field(default_factory=list)


# Default task templates per phase
PHASE_TASK_TEMPLATES: Dict[IRPhase, List[dict]] = {
    IRPhase.IDENTIFICATION: [
        {"title": "Validate alert / confirm incident", "description": "Determine if alert is true positive. Gather initial evidence.", "priority": "critical"},
        {"title": "Determine scope of compromise", "description": "Identify affected systems, accounts, and data.", "priority": "high"},
        {"title": "Classify incident type and severity", "description": "Assign category and severity level using CVSS/risk matrix.", "priority": "high"},
        {"title": "Notify stakeholders", "description": "Alert management, legal, and affected business units as required.", "priority": "high"},
        {"title": "Open case in TheHive", "description": "Create structured case with initial IOCs and evidence.", "priority": "medium"},
    ],
    IRPhase.CONTAINMENT: [
        {"title": "Short-term containment", "description": "Isolate affected systems from network while preserving evidence.", "priority": "critical"},
        {"title": "Evidence preservation", "description": "Take memory dumps and disk images before remediation changes.", "priority": "critical"},
        {"title": "Block malicious IOCs", "description": "Add IPs/domains/hashes to firewall, DNS sinkhole, and AV blocklists.", "priority": "high"},
        {"title": "Preserve authentication artifacts", "description": "Export relevant event logs, credential cache artifacts.", "priority": "high"},
        {"title": "Long-term containment", "description": "Implement compensating controls to allow business continuity.", "priority": "medium"},
    ],
    IRPhase.ERADICATION: [
        {"title": "Identify root cause", "description": "Determine initial access vector and attacker dwell time.", "priority": "critical"},
        {"title": "Remove malware/backdoors", "description": "Delete malicious files, scheduled tasks, and persistence mechanisms.", "priority": "critical"},
        {"title": "Reset compromised credentials", "description": "Force password resets for affected accounts. Revoke tokens.", "priority": "critical"},
        {"title": "Patch exploited vulnerabilities", "description": "Apply patches/mitigations for the exploited vulnerability.", "priority": "high"},
        {"title": "Validate removal", "description": "Re-scan cleaned systems with AV, YARA, and EDR tools.", "priority": "high"},
    ],
    IRPhase.RECOVERY: [
        {"title": "Restore systems from clean backup", "description": "Restore from last known good backup, verify integrity.", "priority": "high"},
        {"title": "Verify system integrity", "description": "Hash comparison, AV scan, and EDR validation post-restoration.", "priority": "high"},
        {"title": "Restore network access", "description": "Gradually re-enable network access with enhanced monitoring.", "priority": "medium"},
        {"title": "Monitor for re-infection", "description": "Increase alert sensitivity for 30 days post-recovery.", "priority": "medium"},
        {"title": "Confirm business operations restored", "description": "Validate with business stakeholders that operations are normal.", "priority": "medium"},
    ],
    IRPhase.LESSONS_LEARNED: [
        {"title": "Conduct post-incident review", "description": "Schedule and facilitate lessons-learned meeting within 2 weeks.", "priority": "medium"},
        {"title": "Document incident timeline", "description": "Complete full attack timeline from initial access to remediation.", "priority": "medium"},
        {"title": "Identify detection gaps", "description": "Document what detection rules were missing or triggered too late.", "priority": "medium"},
        {"title": "Update playbooks", "description": "Revise IR playbooks based on lessons learned.", "priority": "low"},
        {"title": "Draft final IR report", "description": "Write executive and technical summary of the incident.", "priority": "high"},
    ],
}


class IncidentResponseWorkflow:
    """
    Manage a full incident response lifecycle following the PICERL framework.

    Usage:
        ir = IncidentResponseWorkflow(
            title="Ransomware on Finance Server",
            category=IncidentCategory.RANSOMWARE,
            severity=Severity.CRITICAL,
            lead_analyst="Jane Smith",
            reported_by="IT Help Desk",
            affected_systems=["FIN-SRV-01", "FIN-SRV-02"],
            output_dir="cases/"
        )
        ir.advance_phase()  # Move to Containment
        ir.add_note("Found ransom note at C:\\README.txt", author="Jane Smith")
    """

    def __init__(
        self,
        title: str,
        category: IncidentCategory,
        severity: Severity,
        lead_analyst: str,
        reported_by: str,
        affected_systems: List[str],
        output_dir: str = "cases",
        incident_id: Optional[str] = None,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        incident_id = incident_id or f"IR-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        self.incident = IncidentRecord(
            incident_id=incident_id,
            title=title,
            category=category,
            severity=severity,
            created_at=datetime.now(timezone.utc).isoformat(),
            reported_by=reported_by,
            lead_analyst=lead_analyst,
            affected_systems=affected_systems,
        )
        # Auto-populate identification tasks
        self._add_phase_tasks(IRPhase.IDENTIFICATION, lead_analyst)
        self.save()

    # ------------------------------------------------------------------
    # Phase Management
    # ------------------------------------------------------------------

    def advance_phase(self) -> IRPhase:
        """Move to the next IR phase and populate its default tasks."""
        phase_order = list(IRPhase)
        current_idx = phase_order.index(self.incident.current_phase)
        if current_idx < len(phase_order) - 1:
            next_phase = phase_order[current_idx + 1]
            self.incident.current_phase = next_phase
            self._add_phase_tasks(next_phase, self.incident.lead_analyst)
            self._log_timeline(f"Advanced to phase: {next_phase.value.upper()}", "system")
            self.save()
        return self.incident.current_phase

    def close_incident(self, executive_summary: str):
        """Close the incident and record executive summary."""
        self.incident.current_phase = IRPhase.CLOSED
        self.incident.closed_at = datetime.now(timezone.utc).isoformat()
        self.incident.executive_summary = executive_summary
        self._log_timeline("Incident closed", self.incident.lead_analyst)
        self.save()

    # ------------------------------------------------------------------
    # Task Management
    # ------------------------------------------------------------------

    def add_task(
        self,
        title: str,
        description: str = "",
        assigned_to: Optional[str] = None,
        priority: str = "medium",
        phase: Optional[IRPhase] = None,
    ) -> IRTask:
        task = IRTask(
            task_id=f"T-{uuid.uuid4().hex[:6].upper()}",
            phase=phase or self.incident.current_phase,
            title=title,
            description=description,
            assigned_to=assigned_to or self.incident.lead_analyst,
            priority=priority,
        )
        self.incident.tasks.append(task)
        self.save()
        return task

    def complete_task(self, task_id: str, notes: str = ""):
        for task in self.incident.tasks:
            if task.task_id == task_id:
                task.status = "completed"
                task.completed_at = datetime.now(timezone.utc).isoformat()
                task.notes = notes
                self._log_timeline(f"Task completed: {task.title}", self.incident.lead_analyst)
                self.save()
                return
        raise KeyError(f"Task not found: {task_id}")

    def get_open_tasks(self, phase: Optional[IRPhase] = None) -> List[IRTask]:
        tasks = [t for t in self.incident.tasks if t.status != "completed"]
        if phase:
            tasks = [t for t in tasks if t.phase == phase]
        return tasks

    # ------------------------------------------------------------------
    # Notes and IOCs
    # ------------------------------------------------------------------

    def add_note(self, content: str, author: Optional[str] = None, iocs: List[str] = None) -> IRNote:
        note = IRNote(
            note_id=f"N-{uuid.uuid4().hex[:6].upper()}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            author=author or self.incident.lead_analyst,
            phase=self.incident.current_phase,
            content=content,
            iocs=iocs or [],
        )
        self.incident.notes.append(note)
        if iocs:
            self.incident.iocs.extend(iocs)
        self.save()
        return note

    def add_ioc(self, ioc: str):
        if ioc not in self.incident.iocs:
            self.incident.iocs.append(ioc)
            self.save()

    def add_affected_system(self, hostname: str):
        if hostname not in self.incident.affected_systems:
            self.incident.affected_systems.append(hostname)
            self._log_timeline(f"New affected system identified: {hostname}", self.incident.lead_analyst)
            self.save()

    # ------------------------------------------------------------------
    # Reporting & Persistence
    # ------------------------------------------------------------------

    def save(self):
        path = self.output_dir / f"{self.incident.incident_id}.json"
        with open(path, "w") as fh:
            json.dump(asdict(self.incident), fh, indent=2, default=str)

    def status_report(self) -> str:
        inc = self.incident
        open_tasks = self.get_open_tasks()
        lines = [
            "=" * 60,
            f"INCIDENT STATUS REPORT",
            f"ID       : {inc.incident_id}",
            f"Title    : {inc.title}",
            f"Severity : {inc.severity.value.upper()}",
            f"Category : {inc.category.value}",
            f"Phase    : {inc.current_phase.value.upper()}",
            f"Lead     : {inc.lead_analyst}",
            f"Created  : {inc.created_at}",
            f"Systems  : {', '.join(inc.affected_systems)}",
            f"IOCs     : {len(inc.iocs)}",
            f"Open Tasks: {len(open_tasks)}",
            "=" * 60,
            "",
            "OPEN TASKS:",
        ]
        for task in open_tasks:
            lines.append(f"  [{task.priority.upper()}] {task.task_id}: {task.title} (assigned: {task.assigned_to})")
        lines += ["", "RECENT NOTES:"]
        for note in inc.notes[-5:]:
            lines.append(f"  [{note.timestamp}] {note.author}: {note.content[:100]}")
        return "\n".join(lines)

    @classmethod
    def load(cls, json_path: str) -> "IncidentResponseWorkflow":
        """Load a persisted incident from JSON."""
        with open(json_path) as fh:
            data = json.load(fh)
        inc = IncidentRecord(**{
            **data,
            "category": IncidentCategory(data["category"]),
            "severity": Severity(data["severity"]),
            "current_phase": IRPhase(data["current_phase"]),
            "tasks": [IRTask(**{**t, "phase": IRPhase(t["phase"])}) for t in data.get("tasks", [])],
            "notes": [IRNote(**{**n, "phase": IRPhase(n["phase"])}) for n in data.get("notes", [])],
        })
        obj = object.__new__(cls)
        obj.incident = inc
        obj.output_dir = Path(json_path).parent
        return obj

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _add_phase_tasks(self, phase: IRPhase, assigned_to: str):
        templates = PHASE_TASK_TEMPLATES.get(phase, [])
        for tmpl in templates:
            self.incident.tasks.append(IRTask(
                task_id=f"T-{uuid.uuid4().hex[:6].upper()}",
                phase=phase,
                title=tmpl["title"],
                description=tmpl["description"],
                assigned_to=assigned_to,
                priority=tmpl.get("priority", "medium"),
            ))

    def _log_timeline(self, event: str, actor: str):
        self.incident.timeline_events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": actor,
            "phase": self.incident.current_phase.value,
        })

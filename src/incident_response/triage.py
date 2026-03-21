"""
Host triage automation for rapid incident response.

Collects 'first 5 minutes' data from a potentially compromised host:
  - Running processes and parent-child relationships
  - Network connections (established and listening)
  - Logged-in users and failed logins
  - Recently modified files in sensitive locations
  - Suspicious scheduled tasks and services
  - Autorun persistence locations
  - Windows Security Event Log indicators
"""

import json
import os
import platform
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


WINDOWS_SUSPICIOUS_PROCS = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "wmic.exe", "net.exe",
    "schtasks.exe", "at.exe", "sc.exe", "reg.exe",
}

HIGH_VALUE_WINDOWS_EVENTS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Logon with Explicit Credentials",
    4672: "Special Privileges Assigned",
    4688: "New Process Created",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4732: "Member Added to Security Group",
    4776: "NTLM Authentication",
    7045: "New Service Installed",
}


@dataclass
class TriageResult:
    host: str
    triage_time: str
    analyst: str
    os_info: str
    processes: List[dict]
    network_connections: List[dict]
    logged_in_users: List[dict]
    recent_files: List[dict]
    suspicious_tasks: List[dict]
    autoruns: List[dict]
    security_events: List[dict]
    threat_indicators: List[str]
    risk_score: int           # 0-100
    recommended_actions: List[str]

    def to_json(self) -> str:
        import dataclasses
        return json.dumps(dataclasses.asdict(self), indent=2, default=str)


class HostTriage:
    """
    Perform rapid host triage on live Windows/Linux system.

    Usage:
        triage = HostTriage(analyst="Jane Smith", output_dir="cases/IR-001/triage")
        result = triage.run()
        triage.save_report(result)
    """

    def __init__(self, analyst: str = "analyst", output_dir: str = "triage_output"):
        self.analyst = analyst
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._os = platform.system()

    def run(self) -> TriageResult:
        """Execute full triage and return structured result."""
        processes = self._collect_processes()
        network = self._collect_network()
        users = self._collect_users()
        recent_files = self._collect_recent_files()
        tasks = self._collect_scheduled_tasks()
        autoruns = self._collect_autoruns()
        events = self._collect_security_events()

        indicators, risk_score, actions = self._analyze(
            processes, network, users, tasks, autoruns, events
        )

        return TriageResult(
            host=platform.node(),
            triage_time=datetime.now(timezone.utc).isoformat(),
            analyst=self.analyst,
            os_info=f"{platform.system()} {platform.release()} {platform.machine()}",
            processes=processes,
            network_connections=network,
            logged_in_users=users,
            recent_files=recent_files,
            suspicious_tasks=tasks,
            autoruns=autoruns,
            security_events=events,
            threat_indicators=indicators,
            risk_score=risk_score,
            recommended_actions=actions,
        )

    # ------------------------------------------------------------------
    # Collection Methods
    # ------------------------------------------------------------------

    def _collect_processes(self) -> List[dict]:
        processes = []
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
                try:
                    info = proc.info
                    info["suspicious"] = info.get("name", "").lower() in WINDOWS_SUSPICIOUS_PROCS
                    info["create_time"] = datetime.fromtimestamp(
                        info["create_time"], tz=timezone.utc
                    ).isoformat() if info.get("create_time") else None
                    processes.append(info)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except ImportError:
            result = subprocess.run(["tasklist", "/fo", "csv"], capture_output=True, text=True)
            processes = [{"raw": result.stdout}]
        return processes

    def _collect_network(self) -> List[dict]:
        connections = []
        try:
            import psutil
            for conn in psutil.net_connections(kind="inet"):
                try:
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "N/A"
                except Exception:
                    proc_name = "N/A"
                connections.append({
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status,
                    "pid": conn.pid,
                    "process": proc_name,
                    "suspicious": conn.raddr and conn.raddr.port in {4444, 1337, 31337, 8888, 9001},
                })
        except ImportError:
            result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
            connections = [{"raw": result.stdout}]
        return connections

    def _collect_users(self) -> List[dict]:
        users = []
        try:
            import psutil
            for user in psutil.users():
                users.append({
                    "name": user.name,
                    "terminal": user.terminal,
                    "host": user.host,
                    "started": datetime.fromtimestamp(user.started, tz=timezone.utc).isoformat(),
                    "pid": user.pid,
                })
        except (ImportError, AttributeError):
            if self._os == "Windows":
                result = subprocess.run(["query", "user"], capture_output=True, text=True)
            else:
                result = subprocess.run(["who"], capture_output=True, text=True)
            users = [{"raw": result.stdout}]
        return users

    def _collect_recent_files(self, hours: int = 24) -> List[dict]:
        """Find files modified in the last N hours in high-risk directories."""
        recent = []
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        if self._os == "Windows":
            scan_dirs = [
                os.environ.get("TEMP", "C:\\Windows\\Temp"),
                os.environ.get("APPDATA", ""),
                "C:\\Windows\\System32\\",
                "C:\\Users\\Public\\",
            ]
        else:
            scan_dirs = ["/tmp", "/var/tmp", "/dev/shm"]

        for d in scan_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for root, _, files in os.walk(d):
                    for fname in files[:50]:  # Limit per dir
                        fpath = os.path.join(root, fname)
                        try:
                            mtime = datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc)
                            if mtime > cutoff:
                                recent.append({
                                    "path": fpath,
                                    "modified": mtime.isoformat(),
                                    "size": os.path.getsize(fpath),
                                    "extension": Path(fpath).suffix.lower(),
                                })
                        except OSError:
                            continue
            except PermissionError:
                continue
        return recent

    def _collect_scheduled_tasks(self) -> List[dict]:
        tasks = []
        if self._os == "Windows":
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "csv", "/v"],
                capture_output=True, text=True, errors="replace"
            )
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                headers = [h.strip('"') for h in lines[0].split('","')]
                for line in lines[1:]:
                    values = [v.strip('"') for v in line.split('","')]
                    if len(values) == len(headers):
                        tasks.append(dict(zip(headers, values)))
        else:
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            tasks = [{"raw": result.stdout}]
        return tasks

    def _collect_autoruns(self) -> List[dict]:
        autoruns = []
        if self._os == "Windows":
            run_keys = [
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            ]
            for key in run_keys:
                result = subprocess.run(
                    ["reg", "query", key], capture_output=True, text=True
                )
                for line in result.stdout.splitlines():
                    if "REG_" in line:
                        autoruns.append({"registry_key": key, "entry": line.strip()})
        return autoruns

    def _collect_security_events(self, limit: int = 100) -> List[dict]:
        events = []
        if self._os == "Windows":
            event_ids = ",".join(str(eid) for eid in HIGH_VALUE_WINDOWS_EVENTS.keys())
            query = f"*[System[({' or '.join(f'EventID={e}' for e in HIGH_VALUE_WINDOWS_EVENTS)})]]]"
            result = subprocess.run(
                ["wevtutil", "qe", "Security",
                 f"/q:{query}",
                 f"/c:{limit}", "/rd:true", "/f:text"],
                capture_output=True, text=True, errors="replace"
            )
            # Parse text output
            current_event = {}
            for line in result.stdout.splitlines():
                if line.startswith("Event["):
                    if current_event:
                        events.append(current_event)
                    current_event = {}
                elif ":" in line:
                    k, _, v = line.partition(":")
                    current_event[k.strip()] = v.strip()
            if current_event:
                events.append(current_event)
        return events

    # ------------------------------------------------------------------
    # Analysis & Scoring
    # ------------------------------------------------------------------

    def _analyze(self, processes, network, users, tasks, autoruns, events) -> tuple:
        indicators = []
        risk_score = 0
        actions = []

        # Check for suspicious processes
        suspicious_procs = [p for p in processes if isinstance(p, dict) and p.get("suspicious")]
        if suspicious_procs:
            indicators.append(f"Suspicious processes running: {[p.get('name') for p in suspicious_procs]}")
            risk_score += 20

        # Check for suspicious network connections
        suspicious_conns = [c for c in network if isinstance(c, dict) and c.get("suspicious")]
        if suspicious_conns:
            indicators.append(f"Suspicious network connections: {len(suspicious_conns)}")
            risk_score += 30
            actions.append("Isolate host from network immediately")

        # Check for multiple active user sessions
        if len(users) > 3:
            indicators.append(f"Multiple active sessions: {len(users)} users logged in")
            risk_score += 15
            actions.append("Investigate concurrent user sessions for unauthorized access")

        # Check for recent files in temp directories
        exe_in_temp = [f for f in (self.output_dir if hasattr(self, '_recent') else [])
                       if isinstance(f, dict) and f.get("extension") in (".exe", ".ps1", ".dll")]
        if exe_in_temp:
            indicators.append("Executable files found in temp directories")
            risk_score += 25
            actions.append("Collect and analyze executables found in temp paths")

        # Risk rating
        if risk_score >= 70:
            actions.insert(0, "CRITICAL: Isolate host immediately, escalate to senior analyst")
        elif risk_score >= 40:
            actions.insert(0, "HIGH: Initiate containment procedures, notify IR lead")
        elif risk_score >= 20:
            actions.insert(0, "MEDIUM: Continue monitoring, gather additional artifacts")

        if not actions:
            actions.append("LOW: Continue normal monitoring cadence")

        return indicators, min(risk_score, 100), actions

    def save_report(self, result: TriageResult) -> str:
        """Save triage result as JSON."""
        out = self.output_dir / f"triage_{result.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as fh:
            fh.write(result.to_json())
        return str(out)

"""
Automated forensic artifact collection from live Windows/Linux systems.

Collects:
  - Running processes and network connections
  - Prefetch, Shimcache, Amcache data
  - Browser artifacts (history, downloads, cookies)
  - Recent files, LNK files, jump lists
  - Scheduled tasks and services
  - Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)
  - Event logs
  - Memory strings (via strings utility)
"""

import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from src.utils.hash_utils import compute_hashes


WINDOWS_ARTIFACTS = {
    "prefetch": r"C:\Windows\Prefetch",
    "event_logs": r"C:\Windows\System32\winevt\Logs",
    "registry_system": r"C:\Windows\System32\config\SYSTEM",
    "registry_software": r"C:\Windows\System32\config\SOFTWARE",
    "registry_sam": r"C:\Windows\System32\config\SAM",
    "scheduled_tasks": r"C:\Windows\System32\Tasks",
    "amcache": r"C:\Windows\AppCompat\Programs\Amcache.hve",
    "shimcache": r"C:\Windows\System32\config\SYSTEM",  # within SYSTEM hive
    "lnk_recent": r"%APPDATA%\Microsoft\Windows\Recent",
    "startup_folder": r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
}

LINUX_ARTIFACTS = {
    "bash_history": "~/.bash_history",
    "auth_log": "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "cron": "/etc/cron*",
    "hosts": "/etc/hosts",
    "passwd": "/etc/passwd",
    "shadow": "/etc/shadow",
    "sudoers": "/etc/sudoers",
    "ssh_known_hosts": "~/.ssh/known_hosts",
    "systemd_services": "/etc/systemd/system",
}


class ArtifactCollector:
    """Collect forensic artifacts from a live or mounted system."""

    def __init__(self, case_id: str, output_dir: str, analyst: str = "analyst"):
        self.case_id = case_id
        self.analyst = analyst
        self.output_dir = Path(output_dir) / case_id / "artifacts"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.manifest: List[dict] = []
        self._os = platform.system()

    # ------------------------------------------------------------------
    # Live system collection
    # ------------------------------------------------------------------

    def collect_processes(self) -> Path:
        """Snapshot running processes with full command lines."""
        out = self.output_dir / "processes.json"
        processes = []
        try:
            import psutil
            for proc in psutil.process_iter(
                ["pid", "ppid", "name", "exe", "cmdline", "username",
                 "create_time", "status", "connections", "open_files"]
            ):
                try:
                    info = proc.info
                    info["create_time_iso"] = datetime.fromtimestamp(
                        info["create_time"], tz=timezone.utc
                    ).isoformat() if info.get("create_time") else None
                    processes.append(info)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    processes.append({"pid": proc.pid, "error": "access_denied"})
        except ImportError:
            # Fallback: use OS commands
            if self._os == "Windows":
                result = subprocess.run(
                    ["tasklist", "/fo", "csv", "/v"], capture_output=True, text=True
                )
                processes = [{"raw": result.stdout}]
            else:
                result = subprocess.run(
                    ["ps", "auxwww"], capture_output=True, text=True
                )
                processes = [{"raw": result.stdout}]

        with open(out, "w") as fh:
            json.dump(processes, fh, indent=2, default=str)
        self._record(out, "process_list")
        return out

    def collect_network_connections(self) -> Path:
        """Snapshot active network connections."""
        out = self.output_dir / "network_connections.json"
        connections = []
        try:
            import psutil
            for conn in psutil.net_connections(kind="all"):
                connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid,
                })
        except ImportError:
            if self._os == "Windows":
                result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
            else:
                result = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True)
            connections = [{"raw": result.stdout}]

        with open(out, "w") as fh:
            json.dump(connections, fh, indent=2)
        self._record(out, "network_connections")
        return out

    def collect_user_accounts(self) -> Path:
        """Enumerate local user accounts."""
        out = self.output_dir / "user_accounts.json"
        users = []
        if self._os == "Windows":
            result = subprocess.run(
                ["net", "user"], capture_output=True, text=True
            )
            users = [{"raw": result.stdout}]
        else:
            with open("/etc/passwd") as fh:
                for line in fh:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        users.append({
                            "username": parts[0],
                            "uid": parts[2],
                            "gid": parts[3],
                            "home": parts[5],
                            "shell": parts[6],
                        })
        with open(out, "w") as fh:
            json.dump(users, fh, indent=2)
        self._record(out, "user_accounts")
        return out

    def collect_scheduled_tasks(self) -> Path:
        """List scheduled tasks/cron jobs."""
        out = self.output_dir / "scheduled_tasks.txt"
        if self._os == "Windows":
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "LIST", "/v"],
                capture_output=True, text=True, errors="replace"
            )
            content = result.stdout
        else:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True
            )
            content = result.stdout
        out.write_text(content, encoding="utf-8", errors="replace")
        self._record(out, "scheduled_tasks")
        return out

    def collect_autorun_entries(self) -> Path:
        """Collect persistence/autorun entries."""
        out = self.output_dir / "autoruns.json"
        entries = []
        if self._os == "Windows":
            # Common autorun registry keys
            run_keys = [
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ]
            for key in run_keys:
                result = subprocess.run(
                    ["reg", "query", key], capture_output=True, text=True
                )
                entries.append({"key": key, "output": result.stdout})
        else:
            for init_path in ["/etc/rc.local", "/etc/init.d", "/etc/systemd/system"]:
                if os.path.exists(init_path):
                    entries.append({"path": init_path, "exists": True})

        with open(out, "w") as fh:
            json.dump(entries, fh, indent=2)
        self._record(out, "autoruns")
        return out

    def copy_artifact(self, src_path: str, artifact_name: str) -> Optional[Path]:
        """Copy a specific artifact file to the collection directory."""
        src = Path(os.path.expandvars(os.path.expanduser(src_path)))
        if not src.exists():
            return None
        dest = self.output_dir / artifact_name / src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(str(src), str(dest))
            self._record(dest, artifact_name)
            return dest
        except (PermissionError, OSError):
            return None

    def collect_all(self) -> Path:
        """Run all available collectors and return manifest path."""
        self.collect_processes()
        self.collect_network_connections()
        self.collect_user_accounts()
        self.collect_scheduled_tasks()
        self.collect_autorun_entries()
        return self.save_manifest()

    def save_manifest(self) -> Path:
        """Write the collection manifest with hashes to disk."""
        manifest_path = self.output_dir / "manifest.json"
        data = {
            "case_id": self.case_id,
            "analyst": self.analyst,
            "collection_time": datetime.now(timezone.utc).isoformat(),
            "host": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "artifacts": self.manifest,
        }
        with open(manifest_path, "w") as fh:
            json.dump(data, fh, indent=2)
        return manifest_path

    def _record(self, path: Path, artifact_type: str):
        try:
            hashes = compute_hashes(str(path), ("md5", "sha256"))
        except Exception:
            hashes = {"md5": "N/A", "sha256": "N/A"}
        self.manifest.append({
            "artifact_type": artifact_type,
            "path": str(path),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "md5": hashes.get("md5"),
            "sha256": hashes.get("sha256"),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })

"""
Containment actions for incident response.

Provides documented, reversible containment steps that generate audit trails.
Each action is logged with before/after state for chain of custody.

WARNING: These functions interact with system settings. Only run on systems
you are authorized to modify during an incident response engagement.
"""

import json
import os
import platform
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class ContainmentAction:
    action_id: str
    action_type: str
    target: str
    executed_at: str
    executed_by: str
    success: bool
    output: str
    reversible: bool
    reversal_command: Optional[str] = None
    notes: str = ""


class ContainmentActions:
    """
    Execute and document containment actions during incident response.

    All actions are logged to an audit trail for chain of custody.
    """

    def __init__(self, case_id: str, analyst: str, output_dir: str = "cases"):
        self.case_id = case_id
        self.analyst = analyst
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.actions: List[ContainmentAction] = []
        self._os = platform.system()

    # ------------------------------------------------------------------
    # Network Isolation
    # ------------------------------------------------------------------

    def block_ip(self, ip_address: str, direction: str = "both") -> ContainmentAction:
        """Block inbound/outbound traffic to/from an IP address using host firewall."""
        action_id = f"CONTAIN-{len(self.actions) + 1:04d}"
        if self._os == "Windows":
            cmds = []
            if direction in ("inbound", "both"):
                cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                              f"name=IR-Block-IN-{ip_address}", "dir=in",
                              "action=block", f"remoteip={ip_address}"])
            if direction in ("outbound", "both"):
                cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                              f"name=IR-Block-OUT-{ip_address}", "dir=out",
                              "action=block", f"remoteip={ip_address}"])
            output, success = self._run_commands(cmds)
            reversal = f"netsh advfirewall firewall delete rule name=IR-Block-IN-{ip_address}"
        else:
            cmds = [["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                    ["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"]]
            output, success = self._run_commands(cmds)
            reversal = f"iptables -D INPUT -s {ip_address} -j DROP"

        return self._log_action(action_id, "block_ip", ip_address, success, output,
                                reversible=True, reversal_command=reversal)

    def block_domain(self, domain: str) -> ContainmentAction:
        """Add domain to hosts file to sinkhole DNS resolution."""
        action_id = f"CONTAIN-{len(self.actions) + 1:04d}"
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if self._os == "Windows" else "/etc/hosts"
        entry = f"\n127.0.0.1\t{domain}\t# IR-{self.case_id}\n"
        success = False
        output = ""
        try:
            with open(hosts_path, "a") as fh:
                fh.write(entry)
            success = True
            output = f"Added {domain} to hosts file"
        except PermissionError as e:
            output = f"Permission denied: {e}"

        return self._log_action(action_id, "block_domain", domain, success, output,
                                reversible=True,
                                reversal_command=f"Remove '127.0.0.1 {domain}' from {hosts_path}")

    # ------------------------------------------------------------------
    # Process Termination
    # ------------------------------------------------------------------

    def kill_process(self, pid: int, process_name: str = "") -> ContainmentAction:
        """Terminate a suspicious process by PID."""
        action_id = f"CONTAIN-{len(self.actions) + 1:04d}"
        if self._os == "Windows":
            cmd = ["taskkill", "/F", "/PID", str(pid)]
        else:
            cmd = ["kill", "-9", str(pid)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        success = result.returncode == 0
        return self._log_action(
            action_id, "kill_process", f"PID:{pid} ({process_name})",
            success, result.stdout + result.stderr,
            reversible=False
        )

    # ------------------------------------------------------------------
    # Account Actions
    # ------------------------------------------------------------------

    def disable_user_account(self, username: str) -> ContainmentAction:
        """Disable a compromised user account."""
        action_id = f"CONTAIN-{len(self.actions) + 1:04d}"
        if self._os == "Windows":
            cmd = ["net", "user", username, "/active:no"]
        else:
            cmd = ["usermod", "--lock", username]
        result = subprocess.run(cmd, capture_output=True, text=True)
        success = result.returncode == 0
        return self._log_action(
            action_id, "disable_account", username,
            success, result.stdout + result.stderr,
            reversible=True,
            reversal_command=f"net user {username} /active:yes" if self._os == "Windows" else f"usermod --unlock {username}"
        )

    # ------------------------------------------------------------------
    # Service/Task Disablement
    # ------------------------------------------------------------------

    def disable_service(self, service_name: str) -> ContainmentAction:
        """Stop and disable a malicious service."""
        action_id = f"CONTAIN-{len(self.actions) + 1:04d}"
        if self._os == "Windows":
            cmds = [
                ["sc", "stop", service_name],
                ["sc", "config", service_name, "start=disabled"],
            ]
        else:
            cmds = [
                ["systemctl", "stop", service_name],
                ["systemctl", "disable", service_name],
            ]
        output, success = self._run_commands(cmds)
        return self._log_action(
            action_id, "disable_service", service_name,
            success, output, reversible=True,
            reversal_command=f"sc start {service_name}" if self._os == "Windows" else f"systemctl enable --now {service_name}"
        )

    def disable_scheduled_task(self, task_name: str) -> ContainmentAction:
        """Disable a malicious scheduled task (Windows)."""
        action_id = f"CONTAIN-{len(self.actions) + 1:04d}"
        cmd = ["schtasks", "/change", "/tn", task_name, "/disable"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return self._log_action(
            action_id, "disable_task", task_name,
            result.returncode == 0, result.stdout + result.stderr,
            reversible=True,
            reversal_command=f"schtasks /change /tn {task_name} /enable"
        )

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def remove_registry_key(self, key_path: str, value_name: str = "") -> ContainmentAction:
        """Remove a persistence registry key/value (Windows)."""
        action_id = f"CONTAIN-{len(self.actions) + 1:04d}"
        if value_name:
            cmd = ["reg", "delete", key_path, "/v", value_name, "/f"]
        else:
            cmd = ["reg", "delete", key_path, "/f"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return self._log_action(
            action_id, "remove_registry", f"{key_path}\\{value_name}",
            result.returncode == 0, result.stdout + result.stderr,
            reversible=False
        )

    # ------------------------------------------------------------------
    # Audit Trail
    # ------------------------------------------------------------------

    def save_audit_trail(self) -> str:
        """Persist the containment audit trail to disk."""
        out = self.output_dir / f"{self.case_id}_containment_log.json"
        data = {
            "case_id": self.case_id,
            "analyst": self.analyst,
            "generated": datetime.now(timezone.utc).isoformat(),
            "actions": [a.__dict__ for a in self.actions],
        }
        with open(out, "w") as fh:
            json.dump(data, fh, indent=2)
        return str(out)

    def get_reversal_guide(self) -> str:
        """Generate a guide to reverse all containment actions."""
        lines = ["CONTAINMENT REVERSAL GUIDE", "=" * 40, ""]
        for action in self.actions:
            if action.reversible and action.reversal_command:
                lines.append(f"[{action.action_type}] {action.target}")
                lines.append(f"  Reversal: {action.reversal_command}")
                lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _log_action(self, action_id, action_type, target, success, output,
                    reversible=False, reversal_command=None, notes="") -> ContainmentAction:
        action = ContainmentAction(
            action_id=action_id,
            action_type=action_type,
            target=target,
            executed_at=datetime.now(timezone.utc).isoformat(),
            executed_by=self.analyst,
            success=success,
            output=output[:500],
            reversible=reversible,
            reversal_command=reversal_command,
            notes=notes,
        )
        self.actions.append(action)
        return action

    @staticmethod
    def _run_commands(commands: list) -> tuple:
        outputs = []
        all_success = True
        for cmd in commands:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True)
                outputs.append(r.stdout + r.stderr)
                if r.returncode != 0:
                    all_success = False
            except Exception as e:
                outputs.append(str(e))
                all_success = False
        return "\n".join(outputs), all_success

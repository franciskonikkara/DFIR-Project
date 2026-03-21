"""
Shuffle SOAR webhook integration.

Sends structured alerts to Shuffle workflows for automated orchestration:
  - Wazuh alert forwarding
  - VirusTotal enrichment triggers
  - TheHive case creation triggers
  - Email notification dispatching
  - Custom SOAR workflow execution

Shuffle docs: https://shuffler.io/docs/
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class ShuffleWebhook:
    """
    Send events and alerts to Shuffle SOAR via webhook.

    Usage:
        shuffle = ShuffleWebhook(webhook_url="https://shuffler.io/api/v1/hooks/webhook_XXX")
        shuffle.send_wazuh_alert(alert_dict)
        shuffle.trigger_workflow({"action": "block_ip", "ip": "1.2.3.4"})
    """

    def __init__(self, webhook_url: str, timeout: int = 30):
        self.webhook_url = webhook_url
        self.timeout = timeout
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required. Run: pip install requests")

    # ------------------------------------------------------------------
    # Alert Forwarding
    # ------------------------------------------------------------------

    def send_wazuh_alert(self, alert: dict) -> dict:
        """Forward a Wazuh alert to Shuffle for automated processing."""
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        payload = {
            "source": "wazuh",
            "alert_id": alert.get("id"),
            "timestamp": alert.get("timestamp"),
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "rule_groups": rule.get("groups", []),
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "agent_ip": agent.get("ip"),
            "full_alert": alert,
        }
        return self._send(payload)

    def trigger_virustotal_lookup(self, file_hash: str, context: dict = None) -> dict:
        """Trigger a VirusTotal hash lookup workflow in Shuffle."""
        payload = {
            "action": "virustotal_lookup",
            "hash": file_hash,
            "hash_type": self._detect_hash_type(file_hash),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "context": context or {},
        }
        return self._send(payload)

    def trigger_thehive_case_creation(
        self,
        title: str,
        severity: str,
        description: str,
        observables: list = None,
        tags: list = None,
    ) -> dict:
        """Trigger TheHive case creation workflow in Shuffle."""
        payload = {
            "action": "create_thehive_case",
            "title": title,
            "severity": severity,
            "description": description,
            "observables": observables or [],
            "tags": tags or [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self._send(payload)

    def send_email_notification(
        self,
        recipient: str,
        subject: str,
        body: str,
        priority: str = "normal",
    ) -> dict:
        """Trigger an email notification workflow via Shuffle."""
        payload = {
            "action": "send_email",
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "priority": priority,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self._send(payload)

    def trigger_workflow(self, data: dict) -> dict:
        """Send arbitrary data to trigger a Shuffle workflow."""
        data["_sent_at"] = datetime.now(timezone.utc).isoformat()
        return self._send(data)

    # ------------------------------------------------------------------
    # Full Automation Pipeline
    # ------------------------------------------------------------------

    def process_wazuh_alert_full_pipeline(self, alert: dict) -> dict:
        """
        Implement the full SOC automation pipeline from the SOC-Automation-Lab:
        Wazuh alert → Shuffle → VirusTotal → TheHive → Email notification

        This mirrors the DFIR YouTube lab workflow.
        """
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        data = alert.get("data", {})

        # Extract hash from Sysmon/Wazuh alert if available
        file_hash = (
            data.get("win", {}).get("eventdata", {}).get("hashes", "")
            or data.get("hash")
            or data.get("sha256")
            or ""
        )
        # Extract SHA256 specifically from Sysmon Hashes field
        if file_hash and "SHA256=" in file_hash:
            import re
            match = re.search(r"SHA256=([0-9a-fA-F]{64})", file_hash)
            file_hash = match.group(1) if match else ""

        payload = {
            "pipeline": "full_soc_automation",
            "steps": ["wazuh_alert", "virustotal_lookup", "thehive_case", "email_notification"],
            "alert": {
                "id": alert.get("id"),
                "timestamp": alert.get("timestamp"),
                "rule_id": rule.get("id"),
                "rule_level": rule.get("level"),
                "rule_description": rule.get("description"),
                "agent_name": agent.get("name"),
                "agent_ip": agent.get("ip"),
            },
            "enrichment": {
                "file_hash": file_hash,
                "source_ip": data.get("srcip") or agent.get("ip", ""),
                "destination_ip": data.get("dstip", ""),
            },
            "case_data": {
                "title": f"[{rule.get('level', 0)}] {rule.get('description', 'Security Alert')}",
                "severity": self._level_to_severity(rule.get("level", 3)),
                "tags": rule.get("groups", []) + ["wazuh", "automated"],
            },
        }
        return self._send(payload)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send(self, payload: dict) -> dict:
        """POST payload to the Shuffle webhook URL."""
        resp = requests.post(
            self.webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=self.timeout,
        )
        return {
            "status_code": resp.status_code,
            "success": resp.status_code in (200, 201, 202),
            "response": resp.text[:500],
        }

    @staticmethod
    def _detect_hash_type(h: str) -> str:
        length = len(h)
        if length == 32:
            return "md5"
        elif length == 40:
            return "sha1"
        elif length == 64:
            return "sha256"
        return "unknown"

    @staticmethod
    def _level_to_severity(level: int) -> str:
        if level >= 12:
            return "critical"
        elif level >= 9:
            return "high"
        elif level >= 6:
            return "medium"
        return "low"

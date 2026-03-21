"""
Wazuh SIEM/XDR integration client.

Capabilities:
  - Query alerts via Wazuh API
  - Create custom detection rules
  - Manage agents
  - Trigger active response actions
  - Stream alerts via webhook integration

API docs: https://documentation.wazuh.com/current/user-manual/api/index.html
"""

import json
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class WazuhClient:
    """
    Wazuh API client for DFIR workflows.

    Usage:
        wazuh = WazuhClient(host="https://192.168.1.10", username="wazuh", password="secret")
        wazuh.authenticate()
        alerts = wazuh.get_alerts(level_min=10, limit=100)
        agents = wazuh.get_agents()
    """

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._token: Optional[str] = None
        self._token_expiry: Optional[float] = None

        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required. Run: pip install requests")

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> str:
        """Obtain a JWT token from the Wazuh API."""
        resp = requests.get(
            f"{self.host}:55000/security/user/authenticate",
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        return self._token

    def _headers(self) -> dict:
        if not self._token:
            self.authenticate()
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def _get(self, endpoint: str, params: dict = None) -> dict:
        resp = requests.get(
            f"{self.host}:55000/{endpoint.lstrip('/')}",
            headers=self._headers(),
            params=params,
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, data: dict) -> dict:
        resp = requests.post(
            f"{self.host}:55000/{endpoint.lstrip('/')}",
            headers=self._headers(),
            json=data,
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def get_alerts(
        self,
        level_min: int = 0,
        limit: int = 500,
        agent_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[dict]:
        """Query Wazuh alerts from the indexer API."""
        query = {"query": {"bool": {"must": []}}}

        if level_min > 0:
            query["query"]["bool"]["must"].append(
                {"range": {"rule.level": {"gte": level_min}}}
            )
        if agent_id:
            query["query"]["bool"]["must"].append(
                {"match": {"agent.id": agent_id}}
            )
        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time
            if end_time:
                time_range["lte"] = end_time
            query["query"]["bool"]["must"].append(
                {"range": {"timestamp": time_range}}
            )

        query["size"] = limit
        query["sort"] = [{"timestamp": {"order": "desc"}}]

        resp = requests.post(
            f"{self.host}:9200/wazuh-alerts-*/_search",
            headers={"Content-Type": "application/json"},
            json=query,
            verify=self.verify_ssl,
            timeout=30,
        )
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
        return []

    def get_alerts_for_agent(self, agent_id: str, level_min: int = 5) -> List[dict]:
        """Get all recent alerts for a specific agent (host)."""
        return self.get_alerts(level_min=level_min, agent_id=agent_id)

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    def get_agents(self, status: str = "active") -> List[dict]:
        """List Wazuh agents."""
        resp = self._get("/agents", params={"status": status, "limit": 500})
        return resp.get("data", {}).get("affected_items", [])

    def get_agent_info(self, agent_id: str) -> dict:
        """Get detailed info for a specific agent."""
        resp = self._get(f"/agents/{agent_id}")
        return resp.get("data", {}).get("affected_items", [{}])[0]

    def disconnect_agent(self, agent_id: str) -> dict:
        """Isolate an agent from the Wazuh network (containment)."""
        return self._post(f"/active-response", {
            "command": "firewall-drop",
            "custom": False,
            "agent_id": [agent_id],
        })

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def get_rules(self, level_min: int = 0, limit: int = 1000) -> List[dict]:
        """List detection rules loaded in Wazuh."""
        params = {"level": level_min, "limit": limit} if level_min else {"limit": limit}
        resp = self._get("/rules", params=params)
        return resp.get("data", {}).get("affected_items", [])

    def get_rules_by_group(self, group: str) -> List[dict]:
        """Get rules belonging to a specific group (e.g., 'sysmon', 'authentication')."""
        resp = self._get("/rules", params={"group": group, "limit": 500})
        return resp.get("data", {}).get("affected_items", [])

    # ------------------------------------------------------------------
    # Active Response
    # ------------------------------------------------------------------

    def trigger_active_response(
        self,
        command: str,
        agent_ids: List[str],
        alert: Optional[dict] = None,
    ) -> dict:
        """Trigger an active response action on one or more agents."""
        payload = {
            "command": command,
            "custom": True,
            "arguments": [alert.get("id", "")] if alert else [],
            "agent_id": agent_ids,
        }
        return self._post("/active-response", payload)

    def block_ip_on_agent(self, agent_id: str, ip_address: str) -> dict:
        """Block an IP address on a specific agent using Wazuh active response."""
        return self.trigger_active_response(
            command="firewall-drop",
            agent_ids=[agent_id],
            alert={"id": ip_address},
        )

    # ------------------------------------------------------------------
    # Vulnerability Data
    # ------------------------------------------------------------------

    def get_vulnerabilities(self, agent_id: str, severity: str = "High") -> List[dict]:
        """Get vulnerability data for an agent."""
        resp = self._get(
            f"/vulnerability/{agent_id}",
            params={"severity": severity, "limit": 500}
        )
        return resp.get("data", {}).get("affected_items", [])

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_summary(self) -> dict:
        """Get a high-level summary of the Wazuh deployment."""
        agents = self.get_agents()
        return {
            "total_agents": len(agents),
            "active_agents": sum(1 for a in agents if a.get("status") == "active"),
            "disconnected_agents": sum(1 for a in agents if a.get("status") == "disconnected"),
            "agents_by_os": {},
            "query_time": datetime.now(timezone.utc).isoformat(),
        }

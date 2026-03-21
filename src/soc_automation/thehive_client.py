"""
TheHive 5 case management client.

Capabilities:
  - Create and manage cases
  - Add observables (IOCs)
  - Create tasks and task logs
  - Attach evidence files
  - Integrate with MISP for threat intel
  - Export case data for reporting

TheHive API v1 (TheHive 5.x): https://docs.strangebee.com/thehive/api-docs/
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


SEVERITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}
TLP_MAP = {"white": 0, "green": 1, "amber": 2, "red": 3}
PAP_MAP = {"white": 0, "green": 1, "amber": 2, "red": 3}


class TheHiveClient:
    """
    TheHive 5 API client for incident case management.

    Usage:
        hive = TheHiveClient(url="http://thehive:9000", api_key="YOUR_API_KEY")
        case = hive.create_case(
            title="Ransomware - Finance Server",
            severity="high",
            tags=["ransomware", "IR"],
            description="Suspected Lockbit infection detected on FIN-SRV-01"
        )
        hive.add_observable(case["_id"], "192.168.1.100", observable_type="ip")
    """

    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip("/")
        self.api_key = api_key
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required. Run: pip install requests")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _post(self, endpoint: str, data: dict) -> dict:
        resp = requests.post(
            f"{self.url}/api/v1/{endpoint.lstrip('/')}",
            headers=self._headers(),
            json=data,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _get(self, endpoint: str, params: dict = None) -> dict:
        resp = requests.get(
            f"{self.url}/api/v1/{endpoint.lstrip('/')}",
            headers=self._headers(),
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _patch(self, endpoint: str, data: dict) -> dict:
        resp = requests.patch(
            f"{self.url}/api/v1/{endpoint.lstrip('/')}",
            headers=self._headers(),
            json=data,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def create_case(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        tags: List[str] = None,
        tlp: str = "amber",
        pap: str = "amber",
        assignee: Optional[str] = None,
        flag: bool = False,
    ) -> dict:
        """Create a new case in TheHive."""
        payload = {
            "title": title,
            "description": description,
            "severity": SEVERITY_MAP.get(severity.lower(), 2),
            "tags": tags or [],
            "tlp": TLP_MAP.get(tlp.lower(), 2),
            "pap": PAP_MAP.get(pap.lower(), 2),
            "flag": flag,
            "startDate": int(datetime.now(timezone.utc).timestamp() * 1000),
        }
        if assignee:
            payload["assignee"] = assignee
        return self._post("/case", payload)

    def get_case(self, case_id: str) -> dict:
        """Get case details by ID."""
        return self._get(f"/case/{case_id}")

    def update_case(self, case_id: str, **kwargs) -> dict:
        """Update case fields."""
        return self._patch(f"/case/{case_id}", kwargs)

    def close_case(self, case_id: str, resolution: str = "TruePositive", summary: str = "") -> dict:
        """Close a case with resolution status."""
        return self._patch(f"/case/{case_id}", {
            "status": "Resolved",
            "resolutionStatus": resolution,
            "summary": summary,
            "endDate": int(datetime.now(timezone.utc).timestamp() * 1000),
        })

    def list_cases(self, status: str = "Open", limit: int = 50) -> List[dict]:
        """List cases, optionally filtered by status."""
        query = {
            "query": [{"_name": "listCase"}],
            "from": 0,
            "to": limit,
        }
        if status:
            query["query"].append({"_name": "filter", "_field": "status", "_value": status})
        try:
            resp = requests.post(
                f"{self.url}/api/v1/query",
                headers=self._headers(),
                json=query,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Alerts (from Wazuh/Shuffle)
    # ------------------------------------------------------------------

    def create_alert(
        self,
        title: str,
        description: str,
        alert_type: str = "wazuh",
        source: str = "Wazuh",
        source_ref: str = "",
        severity: str = "medium",
        tags: List[str] = None,
        observables: List[dict] = None,
    ) -> dict:
        """Create an alert (can be promoted to a case later)."""
        payload = {
            "title": title,
            "description": description,
            "type": alert_type,
            "source": source,
            "sourceRef": source_ref or f"ALERT-{int(datetime.now().timestamp())}",
            "severity": SEVERITY_MAP.get(severity.lower(), 2),
            "tags": tags or [],
            "date": int(datetime.now(timezone.utc).timestamp() * 1000),
            "observables": observables or [],
        }
        return self._post("/alert", payload)

    def create_alert_from_wazuh(self, wazuh_alert: dict) -> dict:
        """Create a TheHive alert from a Wazuh JSON alert."""
        rule = wazuh_alert.get("rule", {})
        agent = wazuh_alert.get("agent", {})
        level = rule.get("level", 5)

        if level >= 12:
            severity = "critical"
        elif level >= 9:
            severity = "high"
        elif level >= 6:
            severity = "medium"
        else:
            severity = "low"

        description = f"""
**Wazuh Alert**

- **Agent**: {agent.get('name', 'unknown')} ({agent.get('ip', 'unknown')})
- **Rule ID**: {rule.get('id', 'N/A')}
- **Rule Description**: {rule.get('description', 'N/A')}
- **Level**: {level}
- **Groups**: {', '.join(rule.get('groups', []))}
- **Timestamp**: {wazuh_alert.get('timestamp', 'N/A')}

**Full Alert**:
```json
{json.dumps(wazuh_alert, indent=2)[:2000]}
```
"""
        observables = []
        if agent.get("ip"):
            observables.append({"dataType": "ip", "data": agent["ip"], "message": "Source agent IP"})

        # Extract IOCs from alert data
        data_fields = wazuh_alert.get("data", {})
        for field_name in ["srcip", "dstip", "src_ip", "dst_ip"]:
            if data_fields.get(field_name):
                observables.append({"dataType": "ip", "data": data_fields[field_name]})

        for field_name in ["sha256", "hash", "file_hash"]:
            if data_fields.get(field_name):
                observables.append({"dataType": "hash", "data": data_fields[field_name]})

        return self.create_alert(
            title=f"[Wazuh] {rule.get('description', 'Security Alert')}",
            description=description,
            source="Wazuh",
            source_ref=f"WAZUH-{wazuh_alert.get('id', int(datetime.now().timestamp()))}",
            severity=severity,
            tags=rule.get("groups", []) + ["wazuh"],
            observables=observables,
        )

    def promote_alert_to_case(self, alert_id: str) -> dict:
        """Promote an alert to a full case."""
        return self._post(f"/alert/{alert_id}/case", {})

    # ------------------------------------------------------------------
    # Observables (IOCs)
    # ------------------------------------------------------------------

    def add_observable(
        self,
        case_id: str,
        data: str,
        observable_type: str,
        message: str = "",
        tlp: str = "amber",
        tags: List[str] = None,
    ) -> dict:
        """Add an observable (IOC) to a case."""
        payload = {
            "dataType": observable_type,  # ip | domain | url | hash | filename | email
            "data": data,
            "message": message,
            "tlp": TLP_MAP.get(tlp.lower(), 2),
            "tags": tags or [],
            "ioc": True,
            "sighted": True,
        }
        return self._post(f"/case/{case_id}/observable", payload)

    def add_bulk_observables(self, case_id: str, ioc_bundle: dict) -> dict:
        """Add multiple IOCs from an IOCBundle dict."""
        results = {"added": 0, "errors": 0}
        type_map = {
            "ips": "ip", "domains": "domain", "urls": "url",
            "md5s": "hash", "sha1s": "hash", "sha256s": "hash",
            "emails": "mail",
        }
        for ioc_list_key, obs_type in type_map.items():
            for value in ioc_bundle.get(ioc_list_key, [])[:50]:  # Limit 50 per type
                try:
                    self.add_observable(case_id, value, obs_type)
                    results["added"] += 1
                except Exception:
                    results["errors"] += 1
        return results

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    def create_task(self, case_id: str, title: str, description: str = "",
                    assignee: Optional[str] = None) -> dict:
        """Add a task to a case."""
        payload = {
            "title": title,
            "description": description,
            "status": "Waiting",
        }
        if assignee:
            payload["assignee"] = assignee
        return self._post(f"/case/{case_id}/task", payload)

    def add_task_log(self, task_id: str, message: str) -> dict:
        """Add a log entry to a task."""
        return self._post(f"/task/{task_id}/log", {"message": message})

    # ------------------------------------------------------------------
    # File Attachment
    # ------------------------------------------------------------------

    def attach_file(self, case_id: str, file_path: str, description: str = "") -> dict:
        """Attach a file to a case as evidence."""
        path = Path(file_path)
        headers = {"Authorization": f"Bearer {self.api_key}"}
        with open(path, "rb") as fh:
            resp = requests.post(
                f"{self.url}/api/v1/case/{case_id}/attachment",
                headers=headers,
                files={"attachment": (path.name, fh)},
                data={"description": description},
                timeout=60,
            )
        resp.raise_for_status()
        return resp.json()

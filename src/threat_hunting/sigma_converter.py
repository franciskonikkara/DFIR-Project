"""
Sigma rule support - load, parse, and convert Sigma rules to Wazuh/Elasticsearch queries.

Sigma is an open, vendor-agnostic SIEM signature format.
https://github.com/SigmaHQ/sigma

This module provides:
  - Sigma rule parsing
  - Conversion to Wazuh custom rule XML
  - Conversion to Elasticsearch query DSL
  - Sigma rule matching against log events
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    status: str
    author: str
    date: str
    tags: List[str]
    logsource: dict
    detection: dict
    falsepositives: List[str]
    level: str     # informational | low | medium | high | critical
    references: List[str]
    raw: dict


class SigmaConverter:
    """
    Parse Sigma rules and convert to SIEM-specific query languages.

    Usage:
        converter = SigmaConverter()
        rules = converter.load_directory("configs/sigma_rules/")
        wazuh_xml = converter.to_wazuh_rules(rules, start_id=100100)
        es_queries = converter.to_elasticsearch_dsl(rules)
    """

    SIGMA_LEVEL_TO_WAZUH = {
        "informational": 3,
        "low": 5,
        "medium": 8,
        "high": 11,
        "critical": 14,
    }

    def __init__(self):
        self._rules: List[SigmaRule] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_rule_file(self, yaml_path: str) -> Optional[SigmaRule]:
        """Parse a single Sigma YAML rule file."""
        if not YAML_AVAILABLE:
            raise ImportError("pyyaml not installed. Run: pip install pyyaml")
        with open(yaml_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        return self._parse_rule(raw)

    def load_directory(self, directory: str, recursive: bool = True) -> List[SigmaRule]:
        """Load all Sigma rule YAML files from a directory."""
        if not YAML_AVAILABLE:
            raise ImportError("pyyaml not installed. Run: pip install pyyaml")
        rules = []
        dir_path = Path(directory)
        pattern = "**/*.yml" if recursive else "*.yml"
        for rule_file in dir_path.glob(pattern):
            try:
                rule = self.load_rule_file(str(rule_file))
                if rule:
                    rules.append(rule)
                    self._rules.append(rule)
            except Exception:
                continue
        return rules

    # ------------------------------------------------------------------
    # Conversion: Wazuh
    # ------------------------------------------------------------------

    def to_wazuh_rules(self, rules: Optional[List[SigmaRule]] = None, start_id: int = 100100) -> str:
        """Convert Sigma rules to Wazuh custom rules XML."""
        rules = rules or self._rules
        xml_parts = ['<group name="sigma_rules">']
        rule_id = start_id

        for rule in rules:
            wazuh_level = self.SIGMA_LEVEL_TO_WAZUH.get(rule.level, 5)
            detection_conditions = self._sigma_detection_to_wazuh(rule.detection)
            if not detection_conditions:
                continue

            mitre_tags = [t for t in rule.tags if t.startswith("attack.t")]
            mitre_id = mitre_tags[0].replace("attack.", "").upper() if mitre_tags else ""

            rule_xml = f"""
  <rule id="{rule_id}" level="{wazuh_level}">
    <decoded_as>json</decoded_as>
    {detection_conditions}
    <description>Sigma: {self._xml_escape(rule.title)}</description>
    <group>sigma,{rule.level}</group>
    {"<mitre><id>" + mitre_id + "</id></mitre>" if mitre_id else ""}
    <!-- {self._xml_escape(rule.description[:100])} -->
  </rule>"""
            xml_parts.append(rule_xml)
            rule_id += 1

        xml_parts.append("</group>")
        return "\n".join(xml_parts)

    def _sigma_detection_to_wazuh(self, detection: dict) -> str:
        """Convert Sigma detection section to Wazuh XML conditions."""
        conditions = []
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field_name, field_value in value.items():
                    if isinstance(field_value, list):
                        for v in field_value[:3]:  # Limit to 3 per field in Wazuh
                            conditions.append(f'<field name="{self._xml_escape(field_name)}">{self._xml_escape(str(v))}</field>')
                    elif isinstance(field_value, str):
                        conditions.append(f'<field name="{self._xml_escape(field_name)}">{self._xml_escape(field_value)}</field>')
            elif isinstance(value, list):
                for v in value[:3]:
                    conditions.append(f'<match>{self._xml_escape(str(v))}</match>')
        return "\n    ".join(conditions)

    # ------------------------------------------------------------------
    # Conversion: Elasticsearch
    # ------------------------------------------------------------------

    def to_elasticsearch_dsl(self, rules: Optional[List[SigmaRule]] = None) -> List[dict]:
        """Convert Sigma rules to Elasticsearch Query DSL."""
        rules = rules or self._rules
        queries = []
        for rule in rules:
            query = self._sigma_to_es_query(rule.detection)
            queries.append({
                "rule_id": rule.rule_id,
                "title": rule.title,
                "level": rule.level,
                "tags": rule.tags,
                "query": query,
            })
        return queries

    def _sigma_to_es_query(self, detection: dict) -> dict:
        """Convert Sigma detection dict to ES bool query."""
        must_clauses = []
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field_name, field_value in value.items():
                    if isinstance(field_value, list):
                        should = [{"match": {field_name: v}} for v in field_value]
                        must_clauses.append({"bool": {"should": should, "minimum_should_match": 1}})
                    else:
                        must_clauses.append({"match": {field_name: field_value}})
        return {"query": {"bool": {"must": must_clauses}}}

    # ------------------------------------------------------------------
    # Rule Matching (Python-based, no SIEM required)
    # ------------------------------------------------------------------

    def match_event(self, event: dict, rule: SigmaRule) -> bool:
        """Test if an event matches a Sigma rule's detection conditions."""
        detection = rule.detection
        condition = detection.get("condition", "selection")
        selectors = {k: v for k, v in detection.items() if k != "condition"}

        results = {}
        for selector_name, selector_def in selectors.items():
            results[selector_name] = self._matches_selector(event, selector_def)

        # Basic condition evaluation (handles 'selection', 'selection and filter', etc.)
        if condition == "selection":
            return results.get("selection", False)
        elif "and" in condition:
            parts = [p.strip() for p in condition.split("and")]
            return all(results.get(p, False) for p in parts)
        elif "or" in condition:
            parts = [p.strip() for p in condition.split("or")]
            return any(results.get(p, False) for p in parts)
        elif "not" in condition:
            base = condition.replace("not", "").strip()
            return not results.get(base, False)
        return False

    def _matches_selector(self, event: dict, selector: Any) -> bool:
        """Check if an event matches a selector definition."""
        event_str = json.dumps(event).lower()
        if isinstance(selector, dict):
            for field_name, field_value in selector.items():
                event_val = str(event.get(field_name, "")).lower()
                if isinstance(field_value, list):
                    if not any(str(v).lower() in event_val for v in field_value):
                        return False
                elif isinstance(field_value, str):
                    if str(field_value).lower() not in event_val:
                        return False
            return True
        elif isinstance(selector, list):
            return any(self._matches_selector(event, s) for s in selector)
        elif isinstance(selector, str):
            return selector.lower() in event_str
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_rule(self, raw: dict) -> Optional[SigmaRule]:
        if not raw or "detection" not in raw:
            return None
        return SigmaRule(
            rule_id=str(raw.get("id", "")),
            title=raw.get("title", "Unknown"),
            description=raw.get("description", ""),
            status=raw.get("status", "experimental"),
            author=raw.get("author", ""),
            date=str(raw.get("date", "")),
            tags=raw.get("tags", []),
            logsource=raw.get("logsource", {}),
            detection=raw.get("detection", {}),
            falsepositives=raw.get("falsepositives", []),
            level=raw.get("level", "medium"),
            references=raw.get("references", []),
            raw=raw,
        )

    @staticmethod
    def _xml_escape(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

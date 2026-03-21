"""
DFIR Technical Report Generator.

Generates professional incident response reports in multiple formats:
  - Markdown (primary)
  - HTML (self-contained, styled)
  - Plain text

Report structure follows CRA/SANS IR report standards:
  1. Executive Summary
  2. Incident Timeline
  3. Technical Analysis
  4. Evidence Inventory
  5. IOCs
  6. Containment & Remediation Actions
  7. Recommendations
  8. Appendices
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


class ReportGenerator:
    """
    Generate professional DFIR reports from case data.

    Usage:
        rg = ReportGenerator(output_dir="reports/")
        report_path = rg.generate_ir_report(
            case_id="IR-2024-001",
            incident_data=ir_workflow.incident,
            timeline_csv="timeline.csv",
            iocs=ioc_bundle.to_dict(),
            evidence_items=coc.items,
        )
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Main Report Generation
    # ------------------------------------------------------------------

    def generate_ir_report(
        self,
        case_id: str,
        title: str,
        analyst: str,
        severity: str,
        category: str,
        executive_summary: str,
        affected_systems: List[str],
        timeline_events: List[dict],
        iocs: dict,
        evidence_items: List[dict],
        containment_actions: List[dict],
        recommendations: List[str],
        output_format: str = "markdown",
        technical_details: str = "",
        root_cause: str = "",
    ) -> str:
        """Generate a complete IR report."""
        context = {
            "case_id": case_id,
            "title": title,
            "analyst": analyst,
            "severity": severity,
            "category": category,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "executive_summary": executive_summary,
            "affected_systems": affected_systems,
            "timeline_events": timeline_events,
            "iocs": iocs,
            "evidence_items": evidence_items,
            "containment_actions": containment_actions,
            "recommendations": recommendations,
            "technical_details": technical_details,
            "root_cause": root_cause,
        }

        if output_format == "html":
            content = self._render_html(context)
            ext = "html"
        else:
            content = self._render_markdown(context)
            ext = "md"

        out_path = self.output_dir / f"{case_id}_IR_Report_{datetime.now().strftime('%Y%m%d')}.{ext}"
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return str(out_path)

    def generate_forensic_report(
        self,
        case_id: str,
        analyst: str,
        evidence_items: List[dict],
        disk_findings: dict = None,
        memory_findings: dict = None,
        network_findings: dict = None,
        malware_analysis: dict = None,
    ) -> str:
        """Generate a forensic examination report."""
        lines = [
            f"# Digital Forensic Examination Report",
            f"",
            f"**Case ID**: {case_id}",
            f"**Examiner**: {analyst}",
            f"**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            f"**Classification**: CONFIDENTIAL",
            f"",
            "---",
            "",
            "## 1. Purpose and Scope",
            "",
            "This report documents the digital forensic examination conducted in support of the above-referenced investigation. "
            "All examinations were conducted following standard forensic best practices and ACPO guidelines.",
            "",
            "## 2. Evidence Received",
            "",
        ]

        for item in evidence_items:
            lines += [
                f"### Evidence Item: {item.get('evidence_id', 'N/A')}",
                f"- **Description**: {item.get('description', 'N/A')}",
                f"- **Type**: {item.get('evidence_type', 'N/A')}",
                f"- **MD5**: `{item.get('md5', 'N/A')}`",
                f"- **SHA256**: `{item.get('sha256', 'N/A')}`",
                f"- **Acquired**: {item.get('acquisition_timestamp', 'N/A')}",
                f"- **Size**: {item.get('file_size_bytes', 0):,} bytes",
                "",
            ]

        lines += ["## 3. Findings", ""]

        if disk_findings:
            lines += ["### 3.1 Disk/File System Findings", ""]
            lines += self._format_findings_section(disk_findings)

        if memory_findings:
            lines += ["### 3.2 Memory Analysis Findings", ""]
            lines += self._format_findings_section(memory_findings)

        if network_findings:
            lines += ["### 3.3 Network Forensics Findings", ""]
            lines += self._format_findings_section(network_findings)

        if malware_analysis:
            lines += ["### 3.4 Malware Analysis", ""]
            lines += self._format_malware_section(malware_analysis)

        lines += [
            "## 4. Conclusions",
            "",
            "_[To be completed by examiner based on findings above]_",
            "",
            "## 5. Examiner Certification",
            "",
            f"I certify that this report accurately reflects the findings of my forensic examination.",
            "",
            f"**Examiner**: {analyst}",
            f"**Date**: {datetime.now().strftime('%Y-%m-%d')}",
        ]

        content = "\n".join(lines)
        out_path = self.output_dir / f"{case_id}_Forensic_Report_{datetime.now().strftime('%Y%m%d')}.md"
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return str(out_path)

    # ------------------------------------------------------------------
    # Markdown Renderer
    # ------------------------------------------------------------------

    def _render_markdown(self, ctx: dict) -> str:
        severity_emoji = {
            "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"
        }.get(ctx["severity"].lower(), "⚪")

        lines = [
            f"# Incident Response Report: {ctx['title']}",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Case ID** | {ctx['case_id']} |",
            f"| **Severity** | {severity_emoji} {ctx['severity'].upper()} |",
            f"| **Category** | {ctx['category']} |",
            f"| **Lead Analyst** | {ctx['analyst']} |",
            f"| **Generated** | {ctx['generated']} |",
            f"| **Classification** | CONFIDENTIAL |",
            f"",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            ctx['executive_summary'] or "_No executive summary provided._",
            "",
            "## 2. Affected Systems",
            "",
        ]

        for system in ctx['affected_systems']:
            lines.append(f"- `{system}`")

        lines += [
            "",
            "## 3. Incident Timeline",
            "",
            "| Timestamp | Severity | Description | Source | Host |",
            "|-----------|----------|-------------|--------|------|",
        ]
        for evt in ctx['timeline_events'][:50]:
            lines.append(
                f"| {evt.get('timestamp', '')[:19]} | {evt.get('severity', '')} | "
                f"{str(evt.get('description', ''))[:60]} | {evt.get('source', '')} | {evt.get('host', '')} |"
            )

        lines += [
            "",
            "## 4. Technical Analysis",
            "",
            ctx['technical_details'] or "_See appendices for full technical details._",
            "",
            "### Root Cause",
            "",
            ctx['root_cause'] or "_Root cause analysis pending._",
            "",
            "## 5. Indicators of Compromise (IOCs)",
            "",
        ]

        iocs = ctx['iocs']
        if iocs.get('ips'):
            lines += ["### IP Addresses", "```"] + iocs['ips'][:20] + ["```", ""]
        if iocs.get('domains'):
            lines += ["### Domains", "```"] + iocs['domains'][:20] + ["```", ""]
        if iocs.get('sha256s'):
            lines += ["### File Hashes (SHA256)", "```"] + iocs['sha256s'][:20] + ["```", ""]
        if iocs.get('urls'):
            lines += ["### URLs", "```"] + iocs['urls'][:10] + ["```", ""]

        lines += [
            "",
            "## 6. Evidence Inventory",
            "",
            "| Evidence ID | Type | Description | SHA256 | Acquired By |",
            "|-------------|------|-------------|--------|-------------|",
        ]
        for ev in ctx['evidence_items'][:20]:
            lines.append(
                f"| {ev.get('evidence_id', 'N/A')} | {ev.get('evidence_type', 'N/A')} | "
                f"{ev.get('description', '')[:40]} | `{ev.get('sha256', 'N/A')[:16]}...` | "
                f"{ev.get('acquired_by', 'N/A')} |"
            )

        lines += [
            "",
            "## 7. Containment & Remediation Actions",
            "",
        ]
        for action in ctx['containment_actions']:
            status = "✅" if action.get("success") else "❌"
            lines.append(f"- {status} **{action.get('action_type', 'N/A')}**: `{action.get('target', 'N/A')}` "
                         f"({action.get('executed_at', '')[:19]})")

        lines += [
            "",
            "## 8. Recommendations",
            "",
        ]
        for i, rec in enumerate(ctx['recommendations'], 1):
            lines.append(f"{i}. {rec}")

        lines += [
            "",
            "---",
            "",
            "_This report was generated by the DFIR Automation Framework. "
            "All findings should be reviewed and validated by a qualified analyst before distribution._",
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # HTML Renderer
    # ------------------------------------------------------------------

    def _render_html(self, ctx: dict) -> str:
        severity_colors = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107", "low": "#28a745"
        }
        color = severity_colors.get(ctx["severity"].lower(), "#6c757d")

        ioc_html = ""
        for ioc_type, ioc_list in ctx["iocs"].items():
            if ioc_list:
                items = "".join(f"<li><code>{v}</code></li>" for v in ioc_list[:15])
                ioc_html += f"<h4>{ioc_type.upper()}</h4><ul>{items}</ul>"

        timeline_rows = ""
        for evt in ctx["timeline_events"][:100]:
            sev = evt.get("severity", "info")
            sev_color = severity_colors.get(sev, "#6c757d")
            timeline_rows += f"""
            <tr>
                <td>{str(evt.get('timestamp', ''))[:19]}</td>
                <td style='color:{sev_color}'>{sev.upper()}</td>
                <td>{evt.get('source', '')}</td>
                <td>{evt.get('host', '')}</td>
                <td>{str(evt.get('description', ''))[:80]}</td>
            </tr>"""

        evidence_rows = "".join(
            f"<tr><td>{e.get('evidence_id','')}</td><td>{e.get('evidence_type','')}</td>"
            f"<td>{e.get('description','')[:50]}</td><td><code>{e.get('sha256','')[:16]}...</code></td></tr>"
            for e in ctx["evidence_items"]
        )

        recommendations_html = "".join(
            f"<li>{r}</li>" for r in ctx["recommendations"]
        )

        return f"""<!DOCTYPE html>
<html lang='en'><head>
<meta charset='utf-8'>
<title>IR Report - {ctx['case_id']}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:24px;line-height:1.6}}
.header{{background:#161b22;border-left:4px solid {color};padding:20px;border-radius:4px;margin-bottom:24px}}
h1{{color:#58a6ff;font-size:24px}} h2{{color:#58a6ff;margin:20px 0 10px;border-bottom:1px solid #30363d;padding-bottom:6px}}
h3{{color:#79c0ff;margin:16px 0 8px}} h4{{color:#8b949e;margin:12px 0 6px}}
.badge{{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:bold;background:{color};color:white}}
table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}}
th{{background:#161b22;color:#58a6ff;padding:8px;text-align:left;border-bottom:2px solid #30363d}}
td{{padding:6px 8px;border-bottom:1px solid #21262d}}
tr:hover{{background:#161b2240}} code{{background:#161b22;padding:2px 6px;border-radius:4px;font-size:12px;color:#79c0ff}}
ul{{margin-left:24px}} li{{margin:4px 0}}
.section{{background:#161b22;padding:16px;border-radius:6px;margin:16px 0}}
.info-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:14px}}
.info-row{{display:flex;gap:8px}}.info-label{{color:#8b949e;min-width:120px}}
</style>
</head><body>
<div class='header'>
<h1>Incident Response Report</h1>
<p style='color:#8b949e'>{ctx['title']}</p>
</div>
<div class='section'>
<div class='info-grid'>
<div><div class='info-row'><span class='info-label'>Case ID</span><strong>{ctx['case_id']}</strong></div>
<div class='info-row'><span class='info-label'>Severity</span><span class='badge'>{ctx['severity'].upper()}</span></div>
<div class='info-row'><span class='info-label'>Category</span>{ctx['category']}</div></div>
<div><div class='info-row'><span class='info-label'>Lead Analyst</span>{ctx['analyst']}</div>
<div class='info-row'><span class='info-label'>Generated</span>{ctx['generated']}</div>
<div class='info-row'><span class='info-label'>Classification</span><span style='color:#f85149'>CONFIDENTIAL</span></div></div>
</div></div>
<h2>1. Executive Summary</h2>
<div class='section'><p>{ctx['executive_summary'] or 'Pending.'}</p></div>
<h2>2. Incident Timeline</h2>
<table><tr><th>Timestamp</th><th>Severity</th><th>Source</th><th>Host</th><th>Description</th></tr>
{timeline_rows}</table>
<h2>3. Indicators of Compromise</h2>
<div class='section'>{ioc_html or '<p>No IOCs recorded.</p>'}</div>
<h2>4. Evidence Inventory</h2>
<table><tr><th>ID</th><th>Type</th><th>Description</th><th>SHA256</th></tr>
{evidence_rows}</table>
<h2>5. Recommendations</h2>
<div class='section'><ol>{recommendations_html}</ol></div>
<p style='color:#8b949e;text-align:center;margin-top:32px;font-size:12px'>
Generated by DFIR Automation Framework | {ctx['generated']}</p>
</body></html>"""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _format_findings_section(self, findings: dict) -> List[str]:
        lines = []
        for key, value in findings.items():
            lines.append(f"**{key}**: {value}")
        lines.append("")
        return lines

    def _format_malware_section(self, analysis: dict) -> List[str]:
        lines = [
            f"- **File**: `{analysis.get('file_name', 'N/A')}`",
            f"- **SHA256**: `{analysis.get('sha256', 'N/A')}`",
            f"- **Threat Score**: {analysis.get('threat_score', 'N/A')}/100",
            f"- **Packer**: {analysis.get('packer_detected', 'None')}",
            f"- **Entropy**: {analysis.get('entropy', 'N/A'):.2f}" if isinstance(analysis.get('entropy'), float) else "",
            "",
            "**Threat Indicators:**",
        ]
        for ind in analysis.get("threat_indicators", []):
            lines.append(f"- {ind}")
        lines.append("")
        return [l for l in lines if l is not None]

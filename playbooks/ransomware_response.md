# Incident Response Playbook: Ransomware

**Playbook ID**: PB-001
**Version**: 1.0
**Last Updated**: 2024-01-01
**Applicable To**: All ransomware variants (LockBit, BlackCat, Cl0p, Royal, etc.)
**Classification**: CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY

---

## Overview

This playbook guides responders through a ransomware incident following the PICERL framework. Ransomware incidents require immediate action to limit encryption spread and preserve evidence for recovery and potential legal proceedings.

**Key Priorities (in order)**:
1. Contain the spread to prevent additional encryption
2. Preserve evidence before any remediation
3. Identify the initial access vector
4. Assess data exfiltration (double-extortion check)
5. Recover business operations

---

## Phase 1: Identification

### Detection Triggers
- Wazuh Rule 100083: Ransom note file created
- Wazuh Rule 100082: Ransomware file extension created
- Wazuh Rule 100080: Mass file modification
- User reports files showing `.locked`, `.encrypted`, or similar extensions
- EDR alert on mass file encryption behavior

### Initial Triage Checklist

```
[ ] 1. Confirm alert is a true positive (not FP from backup software)
[ ] 2. Identify the first affected host (patient zero)
[ ] 3. Check if encryption is active/ongoing or completed
[ ] 4. Identify affected file shares (network drives)
[ ] 5. Check for lateral spread to other systems
[ ] 6. Locate the ransom note (README, HOW_TO_DECRYPT, etc.)
[ ] 7. Identify the ransomware variant (use ID Ransomware: https://id-ransomware.malwarehunterteam.com/)
[ ] 8. Check for data exfiltration before encryption (DLP logs, network traffic)
[ ] 9. Notify: Management, Legal, IR Lead (P1 escalation)
```

### Python: Start IR Case
```python
from src.incident_response.ir_workflow import IncidentResponseWorkflow, IncidentCategory, Severity

ir = IncidentResponseWorkflow(
    title="Ransomware Encryption - [SYSTEM_NAME]",
    category=IncidentCategory.RANSOMWARE,
    severity=Severity.CRITICAL,
    lead_analyst="[ANALYST_NAME]",
    reported_by="[REPORTER]",
    affected_systems=["[HOSTNAME_1]", "[HOSTNAME_2]"],
    output_dir="cases/"
)
print(ir.status_report())
```

---

## Phase 2: Containment

### IMMEDIATE Actions (First 15 Minutes)

```
[ ] 1. ISOLATE affected hosts:
       - Physical: Disconnect network cable / disable Wi-Fi
       - Logical: Wazuh active response, EDR isolation, VLAN change
       - Document exact time of isolation

[ ] 2. PRESERVE memory (BEFORE any system changes):
       - Take RAM dump of all affected systems
       - Use WinPmem, DumpIt, or Magnet RAM Capture
       - Calculate and record hashes immediately

[ ] 3. BLOCK IOCs at perimeter:
       - Add C2 IP/domains to firewall deny rules
       - Block at DNS level (sinkhole)
       - Update EDR/AV with identified hashes

[ ] 4. DISABLE compromised accounts:
       - Reset service accounts on affected systems
       - Disable accounts used in initial access vector
       - Force password resets for privileged accounts

[ ] 5. PRESERVE logs before rotation:
       - Export Windows Security Event Logs
       - Export Sysmon logs
       - Export Wazuh archives
       - Export EDR telemetry
```

### Python: Containment Actions
```python
from src.incident_response.containment import ContainmentActions

contain = ContainmentActions(case_id="IR-2024-001", analyst="[ANALYST]", output_dir="cases/")

# Block C2 IP
contain.block_ip("1.2.3.4", direction="both")

# Disable compromised account
contain.disable_user_account("compromised_user")

# Save audit trail
contain.save_audit_trail()
print(contain.get_reversal_guide())
```

### Evidence Preservation
```python
from src.forensics.chain_of_custody import ChainOfCustody
from src.forensics.artifact_collector import ArtifactCollector

coc = ChainOfCustody(case_id="IR-2024-001", analyst="[ANALYST]")
# Acquire memory dump
coc.acquire("C:/memory_dump.raw", evidence_type="memory_dump",
            description="RAM dump from infected host FIN-SRV-01")
# Acquire disk image
coc.acquire("D:/disk_image.dd", evidence_type="disk_image",
            description="Forensic disk image of C: drive")
coc.export_report()
```

---

## Phase 3: Eradication

### Root Cause Analysis

```
[ ] 1. Identify initial access vector:
       - Review authentication logs (4624, 4625, 4648) for unusual logins
       - Check email gateway for phishing emails to affected users
       - Review VPN/RDP access logs for external connections
       - Look for exploitation of public-facing services (CVEs)
       - Check for malicious macros/attachments in email

[ ] 2. Identify attacker dwell time:
       - Search for earliest malicious artifact timestamps
       - Look for C2 communication in network logs before encryption
       - Review scheduled tasks, services, and Run keys

[ ] 3. Identify all persistence mechanisms:
       - Scheduled tasks (schtasks /query)
       - Services (sc query)
       - Registry Run keys
       - WMI subscriptions
       - Startup folders

[ ] 4. Identify any exfiltrated data:
       - Review DLP logs
       - Review network egress to unusual destinations
       - Check cloud storage upload logs
       - Review data staging directories
```

### Malware Analysis
```python
from src.malware_analysis.static_analyzer import StaticAnalyzer
from src.malware_analysis.yara_scanner import YaraScanner

# Analyze ransomware binary
analyzer = StaticAnalyzer()
report = analyzer.analyze("evidence/ransomware_sample.exe")
print(f"Threat Score: {report.threat_score}/100")
print(f"IOCs: {report.iocs_extracted}")

# YARA scan for related samples
scanner = YaraScanner()
scanner.load_rules_from_directory("configs/yara_rules/")
result = scanner.scan_directory("C:/", extensions=[".exe", ".dll"])
print(f"YARA detections: {result.files_matched}")
```

### Eradication Checklist
```
[ ] Delete all ransomware executables (verify with YARA scan)
[ ] Remove all scheduled tasks created by attacker
[ ] Remove malicious services
[ ] Clean registry persistence keys
[ ] Remove all attacker tools from system
[ ] Patch exploited vulnerability
[ ] Verify no living-off-the-land tools remain misconfigured
[ ] Re-scan with AV/EDR after cleanup
```

---

## Phase 4: Recovery

```
[ ] 1. Verify backups are clean (pre-infection, not encrypted)
[ ] 2. Test restore in isolated environment first
[ ] 3. Restore from clean backup to rebuilt/wiped system
[ ] 4. Apply all security patches before connecting to network
[ ] 5. Restore network connectivity gradually, with enhanced monitoring
[ ] 6. Monitor for 30 days post-recovery with elevated alerts
[ ] 7. Validate business operations restored with stakeholders
[ ] 8. Notify regulatory bodies if required (GDPR, HIPAA, PCI-DSS)
```

---

## Phase 5: Lessons Learned (Complete within 2 weeks)

```
[ ] Schedule post-incident review with all stakeholders
[ ] Document complete attack timeline (initial access to detection)
[ ] Calculate total business impact (downtime, data loss, costs)
[ ] Identify detection gaps (why wasn't this caught earlier?)
[ ] Update Wazuh detection rules
[ ] Update this playbook with new TTPs
[ ] Draft final IR report (executive + technical)
[ ] Submit IOCs to threat intel sharing platforms (MISP, ISAC)
```

### Final Report Generation
```python
from src.reporting.report_generator import ReportGenerator

rg = ReportGenerator(output_dir="reports/")
path = rg.generate_ir_report(
    case_id="IR-2024-001",
    title="Ransomware Incident - Finance Server",
    analyst="[ANALYST_NAME]",
    severity="critical",
    category="ransomware",
    executive_summary="...",
    affected_systems=["FIN-SRV-01"],
    timeline_events=[...],
    iocs={"ips": [...], "sha256s": [...]},
    evidence_items=[...],
    containment_actions=[...],
    recommendations=[...],
    output_format="html"
)
print(f"Report saved: {path}")
```

---

## Key Contacts

| Role | Contact | Notes |
|------|---------|-------|
| IR Lead | [NAME] | Primary escalation |
| Legal Counsel | [NAME] | Required for data breach notification |
| PR/Communications | [NAME] | If public disclosure needed |
| Cyber Insurance | [NAME] | Notify within 24-72 hours |
| Law Enforcement | FBI IC3 / Local PD | For major incidents |

---

## Reference: Ransomware Identification Resources

- **ID Ransomware**: https://id-ransomware.malwarehunterteam.com/
- **No More Ransom**: https://www.nomoreransom.org/
- **Ransomware.live**: https://www.ransomware.live/
- **CISA Ransomware Guide**: https://www.cisa.gov/stopransomware

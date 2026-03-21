# Incident Response Playbook: Data Breach / Exfiltration

**Playbook ID**: PB-002
**Version**: 1.0
**Last Updated**: 2024-01-01
**Classification**: CONFIDENTIAL

---

## Overview

Covers unauthorized access to, acquisition, use, or disclosure of protected data. Includes exfiltration via C2, cloud storage, email, USB, or insider threat.

---

## Phase 1: Identification

### Detection Triggers
- DLP alert on sensitive data transmission
- Unusual outbound traffic volume (>100MB to unknown external IP)
- Wazuh alert on exfiltration (Rule 100071)
- Third-party notification (breach notification from partner, threat intel)
- Discovery of data on paste sites or dark web

### Initial Assessment Checklist

```
[ ] 1. What data was accessed/exfiltrated?
       - PII (names, SSNs, medical records)?
       - Financial data (credit cards, bank accounts)?
       - Intellectual property?
       - Authentication credentials?

[ ] 2. How many records/individuals affected?
[ ] 3. What is the data classification level?
[ ] 4. Was the data encrypted at rest/in transit?
[ ] 5. When did the breach begin? (determine dwell time)
[ ] 6. Is the breach ongoing or contained?
[ ] 7. Notify Legal immediately - regulatory clock may be ticking
       - GDPR: 72 hours to supervisory authority
       - HIPAA: 60 days to HHS
       - State breach laws: vary 30-90 days
```

---

## Phase 2: Containment

```
[ ] 1. Identify and terminate active exfiltration channels
[ ] 2. Block exfiltration destination IPs/domains at firewall
[ ] 3. Revoke compromised credentials and tokens
[ ] 4. Preserve all relevant logs (do NOT delete anything)
[ ] 5. Document all affected systems
[ ] 6. Capture memory from affected systems
[ ] 7. Isolate if active compromise ongoing
```

### Python: IOC Extraction from Network Logs
```python
from src.utils.ioc_extractor import IOCExtractor
from src.soc_automation.virustotal_client import VirusTotalClient

# Extract IOCs from network logs
extractor = IOCExtractor(exclude_private_ips=True)
iocs = extractor.extract_from_file("network_capture.log")

# Enrich with VT
vt = VirusTotalClient(api_key="YOUR_VT_KEY")
enriched = vt.enrich_ioc_bundle(iocs.to_dict(), max_per_type=5)
for ioc_val, report in enriched.items():
    if report.get("is_malicious"):
        print(f"MALICIOUS: {ioc_val}")
```

---

## Phase 3: Investigation

```
[ ] 1. Reconstruct full attacker timeline
[ ] 2. Identify all data accessed (query database logs, DLP logs)
[ ] 3. Determine exact records/files exfiltrated
[ ] 4. Identify attacker's path through the network
[ ] 5. Determine if data was copied, modified, or deleted
[ ] 6. Collect and preserve all digital evidence with CoC documentation
```

### Python: Network Forensics
```python
from src.forensics.network_forensics import NetworkForensics

nf = NetworkForensics("capture.pcap")
nf.load()
summary = nf.analyze()
print(f"Suspicious connections: {summary['suspicious_connections']}")
iocs = nf.extract_network_iocs()
nf.export_connections_csv("exfil_connections.csv")
```

---

## Phase 4: Eradication & Remediation

```
[ ] 1. Remove attacker access (close all backdoors)
[ ] 2. Rotate all potentially compromised credentials
[ ] 3. Patch exploited vulnerabilities
[ ] 4. Review and strengthen data access controls (least privilege)
[ ] 5. Enable/enhance DLP controls
[ ] 6. Review cloud storage sharing permissions
```

---

## Phase 5: Notification & Reporting

```
[ ] 1. Legal determines notification obligations
[ ] 2. Draft notifications (regulatory, individual)
[ ] 3. Set up breach response hotline if needed
[ ] 4. Monitor for identity theft/misuse of exfiltrated data
[ ] 5. Consider credit monitoring services for affected individuals
[ ] 6. Draft final incident report
```

---

## Regulatory Reference

| Regulation | Notification Timeline | Notify |
|------------|----------------------|--------|
| GDPR | 72 hours | Supervisory authority |
| HIPAA | 60 days | HHS + affected individuals |
| PCI-DSS | Immediately | Card brands + acquiring bank |
| CCPA | 72 hours | CA AG (if >500 CA residents) |
| NY SHIELD | 30 days | NY AG |

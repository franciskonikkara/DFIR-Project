# 🔍 DFIR Automation Framework

> A production-grade **Digital Forensics & Incident Response (DFIR)** platform that extends the [SOC Automation Lab](https://github.com/uruc/SOC-Automation-Lab) with comprehensive forensics, threat hunting, malware analysis, and case management capabilities — aligned with industry certifications (SANS GIAC, IACIS, EnCE) and real-world consulting workflows.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?logo=python" />
  <img src="https://img.shields.io/badge/Wazuh-4.x-blue?logo=wazuh" />
  <img src="https://img.shields.io/badge/TheHive-5.x-orange" />
  <img src="https://img.shields.io/badge/Shuffle-SOAR-green" />
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red" />
  <img src="https://img.shields.io/badge/License-Educational-lightgrey" />
</p>

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Module Deep-Dives](#module-deep-dives)
   - [Digital Forensics](#1-digital-forensics-srcforensics)
   - [Incident Response](#2-incident-response-srcincident_response)
   - [Malware Analysis](#3-malware-analysis-srcmalware_analysis)
   - [Threat Hunting](#4-threat-hunting-srcthreat_hunting)
   - [SOC Automation](#5-soc-automation-srcsoc_automation)
   - [Reporting](#6-reporting-srcreporting)
5. [Configuration Files](#configuration-files)
6. [IR Playbooks](#ir-playbooks)
7. [Automation Scripts](#automation-scripts)
8. [Installation & Quick Start](#installation--quick-start)
9. [Lab Deployment](#lab-deployment)
10. [Detection Coverage](#detection-coverage)
11. [Technology Stack](#technology-stack)
12. [Relevant Certifications](#relevant-certifications)

---

## Overview

This framework was built to demonstrate real-world DFIR capabilities across the entire incident response lifecycle. It combines two major pillars:

**Pillar 1 — SOC Automation** (extended from [uruc/SOC-Automation-Lab](https://github.com/uruc/SOC-Automation-Lab)):
- Wazuh SIEM/XDR collecting Sysmon telemetry
- Shuffle SOAR automating alert triage workflows
- TheHive for structured case management
- VirusTotal for automated IOC enrichment

**Pillar 2 — DFIR Platform** (purpose-built):
- End-to-end forensic artifact collection with chain of custody
- Memory, disk, and network forensics automation
- Static + dynamic malware analysis with YARA scanning
- Hypothesis-based threat hunting against log data
- Professional IR report generation (Markdown, HTML, e-discovery)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DFIR AUTOMATION FRAMEWORK                        │
├──────────────────────┬──────────────────────┬───────────────────────────┤
│    SOC AUTOMATION    │  DIGITAL FORENSICS   │   INCIDENT RESPONSE       │
│                      │                      │                           │
│  Windows (Sysmon)    │  ┌───────────────┐   │  ┌─────────────────────┐  │
│       ↓              │  │ Disk Forensics │   │  │  PICERL Workflow    │  │
│  Wazuh Agent         │  │ • File timeline│   │  │  Preparation        │  │
│       ↓              │  │ • Carving      │   │  │  Identification     │  │
│  Wazuh Manager       │  │ • Metadata     │   │  │  Containment        │  │
│  (Custom Rules)      │  │ • Susp. detect │   │  │  Eradication        │  │
│       ↓              │  └───────────────┘   │  │  Recovery           │  │
│  Shuffle SOAR        │  ┌───────────────┐   │  │  Lessons Learned    │  │
│  (Webhook trigger)   │  │Memory Forensics│   │  └─────────────────────┘  │
│   /         \        │  │ • Volatility 3 │   │                           │
│  VT       TheHive    │  │ • Proc inject  │   │  ┌─────────────────────┐  │
│  Lookup   (Cases)    │  │ • Net conns    │   │  │  Host Triage        │  │
│       \   /          │  │ • YARA scan    │   │  │  Timeline Builder   │  │
│   Email Notif.       │  └───────────────┘   │  │  Containment Actions│  │
│                      │  ┌───────────────┐   │  └─────────────────────┘  │
│                      │  │Network Forensics│  │                           │
│                      │  │ • PCAP (scapy) │   │  ┌─────────────────────┐  │
│                      │  │ • DNS analysis │   │  │  Threat Hunting     │  │
│                      │  │ • Beaconing    │   │  │  • 7 hypotheses     │  │
│                      │  └───────────────┘   │  │  • IOC matching     │  │
│                      │  ┌───────────────┐   │  │  • Sigma engine     │  │
│                      │  │ Chain Custody  │   │  └─────────────────────┘  │
│                      │  │ • Hash verify  │   │                           │
│                      │  │ • Audit trail  │   │  ┌─────────────────────┐  │
│                      │  │ • CoC report   │   │  │  Report Generator   │  │
│                      │  └───────────────┘   │  │  • IR Report (HTML) │  │
│                      │                      │  │  • Forensic Report  │  │
│                      │                      │  │  • E-discovery DAT  │  │
└──────────────────────┴──────────────────────┴──┴─────────────────────┴──┘
```

---

## Project Structure

```
DFIR-Project/
│
├── src/                              # Core Python library
│   ├── forensics/                    # Digital forensics toolkit
│   │   ├── __init__.py
│   │   ├── disk_forensics.py         # File system analysis & carving
│   │   ├── memory_forensics.py       # Volatility 3 automation wrapper
│   │   ├── network_forensics.py      # PCAP analysis (scapy/dpkt/tshark)
│   │   ├── artifact_collector.py     # Live artifact collection
│   │   └── chain_of_custody.py       # Evidence tracking & integrity
│   │
│   ├── incident_response/            # IR lifecycle management
│   │   ├── __init__.py
│   │   ├── ir_workflow.py            # PICERL case management
│   │   ├── triage.py                 # Rapid host triage
│   │   ├── timeline.py               # Event timeline builder
│   │   └── containment.py            # Documented containment actions
│   │
│   ├── malware_analysis/             # Malware analysis toolkit
│   │   ├── __init__.py
│   │   ├── static_analyzer.py        # PE analysis, strings, entropy
│   │   ├── yara_scanner.py           # YARA scanning engine
│   │   └── dynamic_analyzer.py       # Sandbox integration
│   │
│   ├── threat_hunting/               # Proactive hunting
│   │   ├── __init__.py
│   │   ├── hunter.py                 # Hypothesis-based hunting
│   │   ├── ioc_matcher.py            # IOC matching engine
│   │   └── sigma_converter.py        # Sigma rule support
│   │
│   ├── soc_automation/               # SOC tool integrations
│   │   ├── __init__.py
│   │   ├── wazuh_integration.py      # Wazuh API client
│   │   ├── thehive_client.py         # TheHive 5 API client
│   │   ├── shuffle_webhook.py        # Shuffle SOAR triggers
│   │   └── virustotal_client.py      # VirusTotal v3 client
│   │
│   ├── reporting/                    # Report generation
│   │   ├── __init__.py
│   │   ├── report_generator.py       # IR + forensic reports
│   │   └── evidence_reporter.py      # Evidence log & e-discovery
│   │
│   └── utils/                        # Shared utilities
│       ├── __init__.py
│       ├── hash_utils.py             # Cryptographic hashing
│       ├── ioc_extractor.py          # IOC extraction from text
│       └── log_parser.py             # Multi-format log parser
│
├── configs/                          # Detection & monitoring configs
│   ├── wazuh_custom_rules.xml        # 25 MITRE-mapped Wazuh rules
│   ├── sysmon_config.xml             # Optimized Sysmon config
│   ├── yara_rules/
│   │   └── malware_detection.yar     # 7 malware detection rules
│   └── sigma_rules/
│       └── windows_lateral_movement.yml
│
├── playbooks/                        # IR response playbooks
│   ├── ransomware_response.md        # Full PICERL ransomware guide
│   ├── data_breach_response.md       # Exfiltration / breach response
│   └── malware_infection.md          # Malware infection response
│
├── scripts/                          # Automation scripts
│   ├── triage_windows.ps1            # Windows live triage (PowerShell)
│   ├── collect_artifacts.sh          # Linux artifact collection (bash)
│   └── deploy_lab.sh                 # Full lab deployment (Ubuntu 22.04)
│
├── evidence_store/                   # Chain of custody storage
│   └── chain_of_custody/
│
├── reports/                          # Generated report output
│   └── templates/
│
├── requirements.txt                  # Python dependencies
└── README.md
```

---

## Module Deep-Dives

### 1. Digital Forensics (`src/forensics/`)

#### `chain_of_custody.py` — Evidence Registry
Implements **NIST SP 800-86** and **ACPO Guidelines** for defensible digital evidence handling.

Every piece of evidence is:
- Assigned a unique ID (`EV-XXXXXXXX`)
- Hashed at acquisition with **MD5 + SHA1 + SHA256** in a single file-read pass
- Tracked through every transfer, access, and analysis event
- Exportable as a signed text CoC report

```python
from src.forensics.chain_of_custody import ChainOfCustody

coc = ChainOfCustody(case_id="IR-2024-001", analyst="Jane Smith")

# Acquire a memory dump with automatic hashing
item = coc.acquire(
    "C:/memory.raw",
    evidence_type="memory_dump",
    description="RAM dump from FIN-SRV-01 before isolation"
)
print(f"Evidence ID: {item.evidence_id}")
print(f"SHA256: {item.sha256}")

# Record a transfer to another analyst
coc.transfer(item.evidence_id, new_location="Lab Workstation A", recipient="Bob")

# Verify integrity at any time
check = item.verify_integrity("C:/memory.raw")
print(f"Intact: {check['intact']}")

# Export formal CoC report
coc.export_report("evidence_store/IR-2024-001_coc_report.txt")
```

---

#### `artifact_collector.py` — Live System Collection
Collects the **"first 5 minutes"** of forensic artifacts from a live Windows or Linux system, building a timestamped manifest with hashes of all collected files.

**Collects:**
- Running processes (full command lines, hashes of executables)
- Active network connections with owning process names
- Logged-in user sessions
- Scheduled tasks and cron jobs
- Registry autorun persistence entries
- Recently modified files in suspicious directories

```python
from src.forensics.artifact_collector import ArtifactCollector

collector = ArtifactCollector("IR-2024-001", output_dir="evidence_store/")
manifest = collector.collect_all()  # Returns path to manifest.json
print(f"Collected {len(collector.manifest)} artifacts")
```

---

#### `disk_forensics.py` — File System Analysis
Performs forensic analysis of file systems for timeline construction and suspicious file detection.

**Features:**
- **Timeline generation** — Builds a sorted MAC-time (Modified/Accessed/Changed) timeline from any directory tree, exportable to CSV for tools like Excel or Plaso
- **Suspicious file detection** — Flags executables with double extensions (`invoice.pdf.exe`), scripts in temp directories, PE magic/extension mismatches, and unusually long filenames
- **File signature carving** — Searches raw binary data for known file magic bytes and extracts carved files
- **Metadata extraction** — Full stat() info plus magic byte detection for any file

```python
from src.forensics.disk_forensics import DiskForensics

df = DiskForensics("C:/Users/", compute_file_hashes=True)

# Build timeline
df.timeline_to_csv("timeline.csv")

# Find suspicious files
suspicious = df.find_suspicious_files()
for f in suspicious:
    print(f"{f.path}: {f.suspicious_reasons}")
```

---

#### `memory_forensics.py` — Volatility 3 Wrapper
Automates memory forensic analysis by wrapping Volatility 3 plugins into a clean Python API.

**Capabilities:**
- `list_processes()` — Parse pslist output into structured `MemoryProcess` objects
- `list_network_connections()` — Extract network connections from memory (netscan)
- `list_dlls()` — Enumerate loaded DLLs per process (dlllist)
- `find_process_injection()` — Run malfind to detect injected shellcode
- `scan_with_yara()` — Scan memory dump with YARA rules
- `detect_rootkit_indicators()` — DKOM detection (pslist vs psscan comparison for hidden processes)
- `extract_strings_iocs()` — Extract all printable strings and parse IOCs
- `get_command_history()` — Extract console command history
- `dump_process_memory()` — Dump a specific process's memory to disk

```python
from src.forensics.memory_forensics import MemoryForensics

mf = MemoryForensics("memory.dmp")
processes = mf.list_processes()
injected = mf.find_process_injection()

rootkit = mf.detect_rootkit_indicators()
if rootkit["dkom_suspected"]:
    print(f"Hidden PIDs: {rootkit['hidden_process_pids']}")

iocs = mf.extract_strings_iocs()
print(f"IPs in memory: {iocs.ips}")
```

---

#### `network_forensics.py` — PCAP Analysis
Analyzes packet captures for threat hunting and incident investigation.

**Supports three parsing backends** (auto-detected):
1. **scapy** — Full protocol dissection, DNS parsing, flag analysis
2. **dpkt** — High-speed PCAP reading
3. **tshark** — Wireshark CLI fallback

**Capabilities:**
- Connection record aggregation (src/dst/port, bytes, timestamps)
- Suspicious port detection (C2 ports 4444, 1337, 31337, etc.)
- Large data transfer flagging (potential exfiltration)
- DNS query extraction and DGA detection via entropy analysis
- IOC extraction from packet payloads
- CSV export of all connection records

```python
from src.forensics.network_forensics import NetworkForensics

nf = NetworkForensics("capture.pcap")
nf.load()

summary = nf.analyze()
print(f"Total packets: {summary['total_packets']}")
print(f"Suspicious connections: {summary['suspicious_connections']}")

# Export for Excel review
nf.export_connections_csv("connections.csv")

# Extract IOCs
iocs = nf.extract_network_iocs()
print(f"Domains seen: {iocs.domains}")
```

---

### 2. Incident Response (`src/incident_response/`)

#### `ir_workflow.py` — PICERL Case Manager
Full lifecycle incident management following the **PICERL framework**:

**Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned**

Each incident gets:
- A unique case ID (`IR-20240101-XXXXXX`)
- Auto-populated task checklists for each phase (30+ pre-built tasks)
- Timestamped notes with IOC tracking
- Audit trail of all phase transitions
- JSON persistence for handoff between analysts

```python
from src.incident_response.ir_workflow import (
    IncidentResponseWorkflow, IncidentCategory, Severity
)

# Open a new case
ir = IncidentResponseWorkflow(
    title="LockBit Ransomware - Finance Server",
    category=IncidentCategory.RANSOMWARE,
    severity=Severity.CRITICAL,
    lead_analyst="Jane Smith",
    reported_by="IT Help Desk",
    affected_systems=["FIN-SRV-01", "FIN-SRV-02"],
    output_dir="cases/"
)

# Print current status
print(ir.status_report())

# Add an IOC
ir.add_ioc("185.220.101.47")

# Add an analyst note
ir.add_note("Found ransom note at C:\\README_DECRYPT.txt", author="Jane Smith")

# Complete a task
open_tasks = ir.get_open_tasks()
ir.complete_task(open_tasks[0].task_id, notes="Confirmed true positive")

# Advance to next phase (auto-populates phase tasks)
ir.advance_phase()  # → Containment
```

---

#### `triage.py` — Rapid Host Triage
Performs automated first-response triage on a live system and produces a scored risk assessment.

**Collects in one call:**
- Running processes (flagged against known LOLBin list)
- Network connections (flagged against known C2 ports)
- Active user sessions
- Recently modified files in suspicious locations
- Scheduled tasks
- Registry autorun entries
- Windows Security Event Log (key event IDs: 4624, 4688, 4698, 7045, etc.)

**Outputs a `TriageResult`** with:
- `risk_score` (0–100) based on automated indicator analysis
- `threat_indicators` — human-readable findings
- `recommended_actions` — prioritized response steps

```python
from src.incident_response.triage import HostTriage

triage = HostTriage(analyst="Jane Smith", output_dir="cases/IR-001/triage")
result = triage.run()

print(f"Risk Score: {result.risk_score}/100")
print(f"Indicators: {result.threat_indicators}")
print(f"Actions: {result.recommended_actions}")

path = triage.save_report(result)
```

---

#### `timeline.py` — Event Timeline Builder
Aggregates events from multiple sources into a single chronological timeline for attack reconstruction.

**Ingests from:**
- **Wazuh** JSON alert exports (NDJSON)
- **Sysmon** CSV exports (Event IDs 1, 3, 7, 10, 11, 13, 22, etc.)
- **Windows EVTX** JSON exports
- Manual analyst notes

**Exports to:**
- **CSV** — For Excel/LibreOffice analysis
- **JSON** — For programmatic processing
- **Self-contained HTML** — Dark-themed, color-coded by severity for presentations

```python
from src.incident_response.timeline import EventTimeline

tl = EventTimeline(case_id="IR-2024-001")

# Ingest multiple sources
tl.ingest_wazuh_alerts("wazuh_export.json")
tl.ingest_sysmon_csv("sysmon_events.csv")
tl.add_analyst_note("2024-01-15T14:22:00Z",
                    "User reported encrypted files at 14:20 UTC",
                    analyst="Jane Smith", host="FIN-SRV-01")

print(tl.get_summary())

# Export all formats
tl.export_csv("reports/timeline.csv")
tl.export_html("reports/timeline.html")   # Interactive dark-themed HTML
```

---

#### `containment.py` — Documented Containment Actions
Every containment action is **executed AND logged** with before/after state, reversal instructions, and analyst attribution — creating a defensible audit trail.

**Available Actions:**
| Action | Method | Reversible |
|--------|--------|-----------|
| Block IP (host firewall) | `block_ip(ip, direction)` | ✅ Yes |
| Sinkhole domain (hosts file) | `block_domain(domain)` | ✅ Yes |
| Kill process | `kill_process(pid)` | ❌ No |
| Disable user account | `disable_user_account(username)` | ✅ Yes |
| Stop + disable service | `disable_service(service)` | ✅ Yes |
| Disable scheduled task | `disable_scheduled_task(name)` | ✅ Yes |
| Remove registry key | `remove_registry_key(key, value)` | ❌ No |

```python
from src.incident_response.containment import ContainmentActions

contain = ContainmentActions("IR-2024-001", analyst="Jane Smith")

contain.block_ip("185.220.101.47")
contain.block_domain("c2-malware.xyz")
contain.disable_user_account("compromised_admin")

# Save full audit trail with reversal guide
contain.save_audit_trail()
print(contain.get_reversal_guide())
```

---

### 3. Malware Analysis (`src/malware_analysis/`)

#### `static_analyzer.py` — PE Static Analysis
Performs comprehensive static analysis without executing the sample.

**Analysis pipeline:**
1. **File identification** — Magic byte detection, file type classification
2. **Cryptographic hashing** — MD5, SHA1, SHA256 in one file-read pass
3. **Entropy calculation** — Per-file and per-PE-section Shannon entropy (> 7.0 = packed/encrypted)
4. **PE header parsing** — Machine type, compile timestamp, section info, characteristics (via `pefile`)
5. **Import/Export analysis** — Full DLL::function import table (flags process injection APIs)
6. **String extraction** — ASCII and Unicode strings with suspicious pattern matching
7. **Packer detection** — UPX, MPRESS, PECompact, VMProtect signatures
8. **IOC extraction** — Embedded IPs, domains, URLs, registry keys
9. **Threat scoring** — 0–100 composite score with human-readable indicators

**Suspicious string categories detected:**
- Shell execution (`cmd.exe`, `powershell`, `wscript`)
- Process injection APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`)
- Network APIs (`WinHttpOpen`, `URLDownloadToFile`, `InternetOpen`)
- Crypto APIs (`CryptEncrypt`, `BCryptEncrypt`)
- Credential dumping (`mimikatz`, `sekurlsa`, `lsadump`)
- Keylogger indicators (`GetAsyncKeyState`, `SetWindowsHook`)

```python
from src.malware_analysis.static_analyzer import StaticAnalyzer

report = StaticAnalyzer().analyze("suspicious.exe")

print(f"Threat Score : {report.threat_score}/100")
print(f"File Type    : {report.file_type}")
print(f"Entropy      : {report.entropy:.2f} bits")
print(f"Packer       : {report.packer_detected or 'None'}")
print(f"Compiled     : {report.compile_timestamp}")
print(f"Indicators   : {report.threat_indicators}")
print(f"Embedded IPs : {report.iocs_extracted.get('ips', [])}")
```

---

#### `yara_scanner.py` — YARA Scanning Engine
A flexible YARA rule management and scanning engine.

**Capabilities:**
- Load rules from strings, individual files, or entire directories
- Compile all rules into a single optimized ruleset
- Scan: individual files, entire directory trees (recursive), or raw bytes (memory)
- Timeout protection per file
- Graceful `ImportError` if `yara-python` not installed
- JSON result export

**Included YARA rules** (`configs/yara_rules/malware_detection.yar`):
| Rule | Detects |
|------|---------|
| `Mimikatz_Strings` | Mimikatz by internal command strings |
| `PowerShell_Encoded_Download` | Encoded PS download cradles |
| `Cobalt_Strike_Beacon_Artifacts` | CS default named pipes, shellcode preambles |
| `Ransomware_Common_Strings` | Ransom notes, crypto wallet references |
| `WMI_Persistence` | WMI event subscription persistence |
| `Suspicious_PE_Characteristics` | Packed PE files with injection APIs |
| `Office_Macro_Dropper` | OLE2 documents with auto-open + download macros |

```python
from src.malware_analysis.yara_scanner import YaraScanner

scanner = YaraScanner()
scanner.load_rules_from_directory("configs/yara_rules/")

# Scan a file
result = scanner.scan_file("suspicious.exe")
for match in result.matches:
    print(f"RULE HIT: {match.rule_name} ({match.meta.get('severity')})")
    print(f"  Description: {match.meta.get('description')}")

# Scan entire directory
result = scanner.scan_directory("C:/Windows/Temp/", extensions=[".exe", ".dll"])
print(f"Files scanned: {result.files_scanned}, Detections: {result.files_matched}")
```

---

#### `dynamic_analyzer.py` — Sandbox Integration
Submits samples to sandbox environments and parses behavioral analysis reports.

**Supported sandboxes:**
| Sandbox | Type | Notes |
|---------|------|-------|
| **Cuckoo** | Self-hosted | Full behavioral report parsing |
| **Any.run** | Cloud | Interactive analysis |
| **VirusTotal** | Cloud | Multi-engine + sandbox |

**Parsed from reports:**
- Verdict and maliciousness score
- All behavioral events (process, file, registry, network, mutex)
- Network IOCs (hosts, domains, URLs contacted)
- Dropped files
- MITRE ATT&CK technique mappings

```python
from src.malware_analysis.dynamic_analyzer import DynamicAnalyzer

# Cuckoo sandbox
analyzer = DynamicAnalyzer(sandbox="cuckoo", base_url="http://cuckoo:8090")
task_id = analyzer.submit_file("malware.exe")
report = analyzer.get_report(task_id, wait=True, timeout=300)

print(f"Verdict   : {report.verdict}")
print(f"Score     : {report.score}/100")
print(f"C2 hosts  : {report.network_iocs['hosts']}")
print(f"MITRE     : {report.mitre_techniques}")
print(f"Processes : {[p['name'] for p in report.processes_created]}")
```

---

### 4. Threat Hunting (`src/threat_hunting/`)

#### `hunter.py` — Hypothesis-Based Threat Hunter
Implements the **Threat Hunting Maturity Model** (HMM), running structured hypotheses against collected log/telemetry data.

**7 Built-in Hypotheses:**

| ID | Hypothesis | MITRE | Method |
|----|-----------|-------|--------|
| HYP-001 | Living-off-the-Land Binary Abuse | T1218 | LOLBin process + suspicious cmdline |
| HYP-002 | Credential Dumping via LSASS | T1003.001 | LSASS memory access by non-system procs |
| HYP-003 | PowerShell Encoded Commands | T1059.001 | Regex on `-enc`/`-EncodedCommand` flags |
| HYP-004 | Lateral Movement (PsExec/WMI) | T1021 | PSEXESVC service + WMI child procs |
| HYP-005 | Scheduled Task Persistence | T1053.005 | New tasks outside business hours |
| HYP-006 | DNS Beaconing (DGA Detection) | T1071.004 | Shannon entropy > 3.8 on domain labels |
| HYP-007 | Anomalous Login Times | T1078 | Logins outside normal working hours |

**Custom hunts** can be added with a single lambda:
```python
custom_findings = hunter.run_custom_hunt(
    title="Curl/Wget Download Cradle",
    hunt_fn=lambda events: [
        {"host": e.get("host"), "description": e.get("cmdline")}
        for e in events
        if "curl" in str(e.get("cmdline","")).lower() and "http" in str(e.get("cmdline","")).lower()
    ],
    mitre_technique="T1105",
    severity="high"
)
```

```python
from src.threat_hunting.hunter import ThreatHunter

hunter = ThreatHunter(case_id="TH-2024-001")
hunter.load_events_json("wazuh_alerts.json")   # Wazuh NDJSON export

# Run all built-in hypotheses
results = hunter.run_all_hypotheses()

# Generate report
report_path = hunter.generate_report(results)
total_findings = sum(len(v) for v in results.values())
print(f"Found {total_findings} threats across {len(results)} hypotheses")
```

---

#### `ioc_matcher.py` — IOC Matching Engine
Matches threat intelligence IOCs against log events and telemetry at scale.

**Supported IOC types:** IP, domain, URL, MD5, SHA1, SHA256, email, CVE

**Feed ingestion:**
- **CSV** — Generic IOC CSV (configurable column mapping)
- **MISP** — JSON event export from MISP instances
- **AlienVault OTX** — Pulse JSON exports

**Fast matching** using pre-built lookup sets (O(1) hash lookups) for IPs, domains, and hashes:

```python
from src.threat_hunting.ioc_matcher import IOCMatcher

matcher = IOCMatcher()
matcher.load_misp_feed("threat_intel/misp_export.json")      # 500 IOCs
matcher.load_otx_pulse("threat_intel/otx_pulse.json")        # 200 IOCs
matcher.load_ioc_csv("threat_intel/internal_iocs.csv")       # Custom feed

print(f"IOC stats: {matcher.get_stats()}")

# Match against Wazuh alerts
hits = matcher.match_events(wazuh_alerts)
print(f"IOC hits: {len(hits)}")
matcher.export_hits_csv(hits, "ioc_hits.csv")
```

---

#### `sigma_converter.py` — Sigma Rule Engine
Loads, parses, and converts [Sigma](https://github.com/SigmaHQ/sigma) rules.

**Capabilities:**
- Parse YAML Sigma rules from files or directories
- Convert to **Wazuh XML** detection rules
- Convert to **Elasticsearch Query DSL**
- Python-based rule matching against event dicts (no SIEM required)
- Automatic MITRE technique tag extraction

```python
from src.threat_hunting.sigma_converter import SigmaConverter

converter = SigmaConverter()
rules = converter.load_directory("configs/sigma_rules/")

# Convert to Wazuh XML (deploy to /var/ossec/etc/rules/)
wazuh_xml = converter.to_wazuh_rules(rules, start_id=100200)
with open("configs/sigma_wazuh.xml", "w") as f:
    f.write(wazuh_xml)

# Convert to Elasticsearch queries
es_queries = converter.to_elasticsearch_dsl(rules)

# Match directly against events
for event in log_events:
    for rule in rules:
        if converter.match_event(event, rule):
            print(f"Sigma hit: {rule.title} on {event.get('host')}")
```

---

### 5. SOC Automation (`src/soc_automation/`)

This module implements the full **SOC Automation Lab** pipeline in Python, extending the original lab's manual workflow into a programmable API.

#### The Automation Pipeline

```
Wazuh Alert (level ≥ 10)
      ↓
Shuffle Webhook receives JSON
      ↓
Extract SHA256 hash from alert
      ↓
VirusTotal hash lookup
      ↓ (if malicious)
Create TheHive alert with:
  - Agent name/IP as observable
  - Rule description
  - Severity mapped from Wazuh level
  - Full alert JSON in description
      ↓
Email notification to SOC analyst
```

#### `wazuh_integration.py`
Full Wazuh REST API client (v4.x):
- `get_alerts()` — Query alerts from Wazuh indexer with filters (level, agent, time range)
- `get_agents()` — List and manage agents
- `trigger_active_response()` — Execute firewall-drop or custom scripts on agents
- `block_ip_on_agent()` — Block a specific IP via active response
- `get_vulnerabilities()` — Pull CVE data per agent
- `get_rules()` — List loaded detection rules

#### `thehive_client.py`
Full TheHive 5 API client:
- `create_case()` — Open a new case with severity, TLP, PAP, tags
- `create_alert()` / `create_alert_from_wazuh()` — Ingest Wazuh alerts as TheHive alerts
- `promote_alert_to_case()` — Escalate alert to full case
- `add_observable()` / `add_bulk_observables()` — Add IP/domain/hash IOCs
- `create_task()` / `add_task_log()` — Task management
- `attach_file()` — Attach evidence files
- `close_case()` — Close with resolution status and summary

#### `virustotal_client.py`
VirusTotal v3 API with rate limiting (respects 4 req/min free tier):
- `get_file_report(hash)` — Returns normalized result with `is_malicious`, `detection_ratio`, `threat_names`
- `get_ip_report(ip)` — IP reputation, ASN, country, whois
- `get_domain_report(domain)` — Domain categorization, registrar, DNS history
- `get_url_report(url)` — URL safety check
- `get_file_behavior(hash)` — Sandbox behavioral reports
- `enrich_ioc_bundle(ioc_dict)` — Bulk enrich a full IOC bundle

#### `shuffle_webhook.py`
Trigger Shuffle SOAR workflows programmatically:
- `send_wazuh_alert()` — Forward a Wazuh alert payload
- `trigger_virustotal_lookup()` — Request hash enrichment
- `trigger_thehive_case_creation()` — Create case via workflow
- `send_email_notification()` — Trigger analyst notification
- `process_wazuh_alert_full_pipeline()` — **One-call full SOC automation pipeline**

---

### 6. Reporting (`src/reporting/`)

#### `report_generator.py`
Generates professional reports in **Markdown** and **self-contained HTML**.

**IR Report sections:**
1. Case metadata table (ID, severity badge, category, analyst, timestamp)
2. Executive Summary
3. Affected Systems
4. Incident Timeline (tabular, up to 100 events)
5. Technical Analysis + Root Cause
6. Indicators of Compromise (grouped by type: IP, domain, hash, URL)
7. Evidence Inventory (with truncated SHA256s)
8. Containment & Remediation Actions (✅/❌ status)
9. Recommendations (numbered list)

The HTML output is dark-themed, self-contained (no external dependencies), and ready for email or client delivery.

#### `evidence_reporter.py`
Generates legally-admissible evidence documentation:
- **Evidence Log CSV** — Full metadata, CoC events, hashes in one spreadsheet
- **E-discovery DAT** — Concordance-format `.dat` file for legal review platforms (Relativity, Nuix)
- **Hash Verification Report** — Re-hashes all evidence files and attests integrity

---

## Configuration Files

### `configs/wazuh_custom_rules.xml`
25 custom Wazuh detection rules mapped to MITRE ATT&CK, organized by tactic:

| Tactic | Rules |
|--------|-------|
| Credential Dumping | Mimikatz strings, LSASS memory access |
| Process Injection | CreateRemoteThread into sensitive processes |
| Defense Evasion | Defender disablement, event log clearing |
| LOLBin Abuse | certutil, regsvr32, mshta with suspicious cmdlines |
| PowerShell | Encoded commands, download cradles |
| Persistence | Scheduled tasks, Run key modifications |
| Lateral Movement | PsExec service, NTLM auth anomalies |
| Ransomware | File extension creation, ransom note detection, mass file modification |

### `configs/sysmon_config.xml`
Optimized Sysmon 4.90 configuration capturing:
- **All process creations** (Event 1) with full command lines
- **Network connections** from LOLBins and to C2 ports
- **File creation** in AppData, Temp, Public directories + ransomware extensions
- **Registry modifications** to persistence keys and Defender settings
- **Remote thread creation** (injection indicator)
- **LSASS/SAM memory access** (credential dumping)
- **DNS queries** from suspicious processes and to suspicious TLDs (`.top`, `.xyz`, `.tk`)
- **Named pipes** matching known C2 framework defaults (Cobalt Strike, Meterpreter)

---

## IR Playbooks

Three complete PICERL playbooks with embedded Python code snippets:

### `playbooks/ransomware_response.md`
Full ransomware response guide covering:
- Detection triggers and initial triage checklist (15 items)
- Immediate containment actions with Python code (first 15 minutes)
- Evidence preservation before any system changes
- Root cause analysis methodology
- Eradication checklist (YARA scanning, persistence removal)
- Recovery steps and integrity verification
- Regulatory notification requirements
- Final report generation code

### `playbooks/data_breach_response.md`
Data exfiltration / breach response covering:
- Data classification assessment
- Regulatory notification timelines (GDPR 72h, HIPAA 60d, PCI-DSS immediate)
- Network forensics for exfiltration reconstruction
- IOC extraction and VT enrichment workflow

### `playbooks/malware_infection.md`
General malware response covering static analysis, YARA scanning, sandbox submission, and eradication verification.

---

## Automation Scripts

### `scripts/triage_windows.ps1` — Windows Live Triage
Run as Administrator on a suspected compromised Windows host.

```powershell
.\scripts\triage_windows.ps1 -CaseID "IR-2024-001" -Analyst "Jane Smith"
```

**Collects to timestamped output folder:**
| File | Contents |
|------|----------|
| `00_metadata.json` | System info, IPs, OS, architecture |
| `01_processes.csv/json` | All processes with command lines and SHA256 hashes |
| `02_netstat.txt` | Raw netstat output |
| `02_network_connections.csv` | Structured TCP connections with process names |
| `02_dns_cache.csv` | DNS resolver cache |
| `03_logged_in_users.txt` | Active sessions (query user) |
| `03_recent_logons.csv` | Last 200 logins from Security event log |
| `04_scheduled_tasks.csv` | All tasks with actions, triggers, last run |
| `05_services.csv` | All services with file paths and MD5 hashes |
| `06_autoruns.csv` | Registry Run/RunOnce + Winlogon keys |
| `07_prefetch.csv` | All Prefetch files sorted by last execution |
| `08_recent_files.csv` | Files modified in last 48h in Temp/AppData/Public |
| `09_security_events.csv` | Key Event IDs (4624, 4688, 4698, 7045, 1102, etc.) |
| `00_manifest.csv` | SHA256 + MD5 of every collected artifact |

### `scripts/collect_artifacts.sh` — Linux Artifact Collection
Run as root on a suspected compromised Linux system.

```bash
sudo ./scripts/collect_artifacts.sh -c IR-2024-001 -a "Jane Smith"
```

Collects: process tree, network connections, routing/ARP, users, cron jobs, systemd services, SSH authorized keys, recently modified files, SUID/SGID files, bash/zsh history, auth log, syslog/journal, installed packages + manifest.

### `scripts/deploy_lab.sh` — Full Lab Deployment
One-command deployment of the complete SOC + DFIR stack on Ubuntu 22.04:

```bash
sudo ./scripts/deploy_lab.sh [WAZUH_IP] [THEHIVE_IP]
```

Deploys in order:
1. Java 17 (TheHive/Elasticsearch dependency)
2. Apache Cassandra (TheHive database)
3. Elasticsearch (TheHive indexer)
4. TheHive 5 (case management)
5. Wazuh Manager + Indexer + Dashboard (all-in-one)
6. Docker + Docker Compose
7. Shuffle SOAR (Docker containers)
8. Python dependencies (`pip install -r requirements.txt`)
9. Custom Wazuh detection rules deployment

---

## Installation & Quick Start

### Prerequisites
- Python 3.9+
- (Optional) Volatility 3 for memory forensics
- (Optional) Wazuh, TheHive, Shuffle for full SOC automation

```bash
# Clone the repository
git clone https://github.com/franciskonikkara/DFIR-Project.git
cd DFIR-Project

# Install Python dependencies
pip install -r requirements.txt

# Quick test: static analysis
python3 -c "
from src.malware_analysis.static_analyzer import StaticAnalyzer
import sys
report = StaticAnalyzer().analyze(sys.argv[1])
print(f'Score: {report.threat_score}/100 | {report.threat_indicators}')
" /path/to/suspicious.exe
```

---

## Lab Deployment

```
┌──────────────────────────────────────────────────────┐
│              RECOMMENDED LAB TOPOLOGY                │
│                                                      │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │ Windows 10   │    │     Ubuntu 22.04         │   │
│  │ (Victim VM)  │    │   Wazuh + TheHive +      │   │
│  │              │    │   Shuffle + ELK          │   │
│  │ • Sysmon     │───▶│                          │   │
│  │ • Wazuh Agent│    │  RAM: 8GB+ recommended   │   │
│  │ • Test tools │    │  Disk: 50GB+             │   │
│  └──────────────┘    └──────────────────────────┘   │
│          │                       │                   │
│          └───────────────────────┘                   │
│              Host-Only or NAT Network                │
└──────────────────────────────────────────────────────┘
```

Access after deployment:
- **Wazuh Dashboard**: `https://<WAZUH_IP>` (credentials in `/etc/wazuh-install-files.tar`)
- **TheHive**: `http://<THEHIVE_IP>:9000` (default: `admin@thehive.local` / `secret`)
- **Shuffle**: `http://<WAZUH_IP>:3001` (default: `admin@example.com` / `password`)

> ⚠️ **Change all default credentials immediately after deployment.**

---

## Detection Coverage

| Rule ID | MITRE ID | Description | Level |
|---------|----------|-------------|-------|
| 100001 | T1003.001 | Mimikatz execution detected | **15** 🔴 |
| 100002 | T1003.001 | Suspicious LSASS memory access | 14 🔴 |
| 100010 | T1055 | CreateRemoteThread process injection | 14 🔴 |
| 100020 | T1218.014 | Certutil download/decode abuse | 12 🟠 |
| 100021 | T1218.010 | Regsvr32 Squiblydoo technique | 13 🟠 |
| 100022 | T1218.005 | Suspicious mshta.exe execution | 12 🟠 |
| 100030 | T1059.001 | Encoded PowerShell command | 12 🟠 |
| 100031 | T1059.001 | PowerShell download cradle | 13 🟠 |
| 100032 | T1562.001 | Windows Defender disabled via PS | 14 🔴 |
| 100040 | T1053.005 | New scheduled task created | 9 🟡 |
| 100042 | T1547.001 | Registry Run key modified | 11 🟠 |
| 100050 | T1021.002 | PsExec service installation | 13 🟠 |
| 100051 | T1550.002 | NTLM auth failure (Pass-the-Hash) | 11 🟠 |
| 100060 | T1070.001 | Security event log cleared | 14 🔴 |
| 100061 | T1562.001 | Defender registry tampered | 14 🔴 |
| 100070 | T1071.004 | DNS query to suspicious TLD | 10 🟡 |
| 100082 | T1486 | Ransomware file extension created | 8 🟡 |
| 100083 | T1486 | Ransom note file detected | **15** 🔴 |

---

## Technology Stack

| Category | Tool/Library | Purpose |
|----------|-------------|---------|
| SIEM/XDR | Wazuh 4.x | Log collection, alerting, active response |
| Case Management | TheHive 5 | Incident cases, observables, tasks |
| SOAR | Shuffle | Workflow automation, integrations |
| Threat Intel | VirusTotal v3 | Hash/IP/domain enrichment |
| Threat Intel | MISP, AlienVault OTX | IOC feeds |
| Memory Forensics | Volatility 3 | Memory dump analysis |
| Endpoint Telemetry | Sysmon | Detailed Windows event logging |
| Network Forensics | Scapy, dpkt, tshark | PCAP analysis |
| Malware Analysis | YARA, pefile | Static analysis |
| Sandbox | Cuckoo, Any.run | Dynamic analysis |
| Detection Rules | Sigma | Vendor-agnostic signatures |
| Database | Cassandra + Elasticsearch | TheHive backends |
| Scripting | Python 3, PowerShell, Bash | Automation |

---

## Relevant Certifications

This project demonstrates skills validated by the following certifications:

| Cert | Issuer | Skills Demonstrated Here |
|------|--------|--------------------------|
| **GCFA** — Forensic Analyst | SANS GIAC | Memory forensics, timeline analysis, disk forensics |
| **GCFE** — Forensic Examiner | SANS GIAC | Windows artifacts, registry, event logs, CoC |
| **GCIA** — Intrusion Analyst | SANS GIAC | Network forensics, PCAP analysis, IDS tuning |
| **GREM** — Reverse Engineering | SANS GIAC | Static/dynamic malware analysis, YARA |
| **GNFA** — Network Forensics | SANS GIAC | PCAP analysis, protocol analysis |
| **GCCC** — Critical Controls | SANS GIAC | Detection rules, SIEM, threat hunting |
| **CFCE** | IACIS | Evidence handling, CoC, forensic procedures |
| **EnCE** | Guidance/OpenText | File system forensics, e-discovery |

---

## Legal Disclaimer

This framework is intended for **authorized security testing, forensic analysis, and educational purposes only**. All techniques, tools, and scripts must only be used on systems you own or have explicit written authorization to access. Unauthorized use against third-party systems is illegal.

---

*Built to demonstrate DFIR capabilities aligned with consulting firm requirements (CRA, Big 4 Forensics) and SANS/IACIS certification tracks.*

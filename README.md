# SIEM Engineering Lab (KQL + Python) — Detection, Triage, and Automation

![Security](https://img.shields.io/badge/focus-SIEM%20Engineering-blue)
![Status](https://img.shields.io/badge/status-active-success)
![Python](https://img.shields.io/badge/python-3.10%2B-informational)
![KQL](https://img.shields.io/badge/KQL-Microsoft%20Defender%20%2F%20Sentinel-informational)

A hands-on SIEM engineering lab demonstrating how to:
- Collect and analyze security telemetry
- Write KQL hunting queries
- Build detection rules and triage playbooks
- Automate log parsing/enrichment with Python
- Document repeatable workflows like a production SOC

# SIEM Engineering Lab  
Detection Engineering • KQL • Log Analysis • Python Automation

A hands-on SIEM engineering lab demonstrating:

- KQL hunting queries
- Suspicious activity detection logic
- Log enrichment with Python
- Detection rule design
- Triage workflow documentation
- Case evidence export automation

This project demonstrates real SIEM engineering workflow:  
Baseline → Hunt → Detection → Triage → Automation.

---

## Table of Contents

- Overview
- Architecture
- Prerequisites
- Repository Structure
- Step 1 – Establish Baseline
- Step 2 – Authentication Hunt
- Step 3 – Process & Enumeration Hunt
- Step 4 – Convert Hunt to Detection
- Step 5 – Python Enrichment
- Step 6 – Triage & Case Bundling
- Deliverables
- Resources
- License

---

## Overview

This lab simulates real-world SIEM operations:

1. Establish environment baseline  
2. Hunt suspicious patterns  
3. Create detection logic  
4. Automate enrichment  
5. Export case-ready evidence  

Designed for use with:
- Microsoft Sentinel
- Microsoft Defender Advanced Hunting
- Any KQL-compatible environment

---

## Architecture

Telemetry Sources → SIEM → KQL Hunts → Detection Rules → Triage Workflow  
Telemetry Sources → Python Enrichment → Case Bundle Export  

---

## Prerequisites

- Access to a KQL-enabled SIEM (Sentinel or MDE preferred)
- Python 3.10+
- `pip install -r requirements.txt`

---

## Repository Structure

```
SIEM-Engineering-Lab/
│
├── kql/
│   ├── baseline.kql
│   ├── auth_hunt.kql
│   ├── process_hunt.kql
│   └── persistence_hunt.kql
│
├── scripts/
│   ├── enrich_events.py
│   └── export_case_bundle.py
│
├── data/
│   └── sample_events.jsonl
│
├── docs/
│   ├── triage-playbook.md
│   ├── detection-template.md
│   └── evidence-checklist.md
│
└── outputs/
```

---

## Step 1 – Establish Baseline

Example baseline query:

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| summarize Logons=count() by DeviceName, AccountName, LogonType
| order by Logons desc
```

Goal:
- Understand normal login patterns
- Identify high-volume accounts
- Establish behavioral baseline

---

## Step 2 – Authentication Hunt

```kql
DeviceLogonEvents
| where Timestamp > ago(14d)
| where LogonType in ("RemoteInteractive", "Interactive")
| summarize count() by AccountName, DeviceName, RemoteIP
| order by count_ desc
```

Goal:
- Identify unusual remote logins
- Detect external IP anomalies
- Spot off-hours activity

---

## Step 3 – Process & Enumeration Hunt

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in ("arp.exe", "net.exe", "whoami.exe", "ipconfig.exe", "nltest.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

Goal:
- Detect post-compromise discovery activity
- Identify enumeration behavior

---

## Step 4 – Convert Hunt to Detection

Use detection template to define:

- Query logic
- Schedule
- Severity
- Threshold
- Triage steps
- Entity mapping

Store detection documentation in:

```
docs/detection-template.md
```

---

## Step 5 – Python Enrichment

Run enrichment pipeline:

```bash
python scripts/enrich_events.py --input data/sample_events.jsonl --output outputs/enriched_events.jsonl
```

Enrichment features:
- Normalize timestamps
- Tag suspicious commands
- Assign risk scores
- Add explanation field

---

## Step 6 – Triage & Case Bundling

Generate case bundle:

```bash
python scripts/export_case_bundle.py --input outputs/enriched_events.jsonl --case CASE-001 --out outputs/CASE-001/
```

Output includes:
- Enriched events
- Summary report
- Evidence checklist
- Timeline

---

## Deliverables

- KQL hunting pack
- Detection templates
- Python enrichment scripts
- Case export automation
- Triage documentation

---

## Resources

- Microsoft Defender Advanced Hunting Schema
- Microsoft Sentinel Analytics Rule Documentation
- MITRE ATT&CK Framework
- KQL Documentation

---

## License

MIT

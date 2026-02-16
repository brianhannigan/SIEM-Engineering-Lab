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

This repo is structured as a tutorial so you can reproduce each stage and show real SIEM engineering capability to hiring teams.

---

## Table of Contents
- [What You’ll Build](#what-youll-build)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Repo Structure](#repo-structure)
- [Lab Data](#lab-data)
- [Step 1 — Establish a Baseline (KQL)](#step-1--establish-a-baseline-kql)
- [Step 2 — Hunt for Suspicious Authentication](#step-2--hunt-for-suspicious-authentication)
- [Step 3 — Process Execution & Enumeration Hunt](#step-3--process-execution--enumeration-hunt)
- [Step 4 — Turn Hunts into Detections](#step-4--turn-hunts-into-detections)
- [Step 5 — Python Enrichment Pipeline](#step-5--python-enrichment-pipeline)
- [Step 6 — Triage Playbook + Evidence Checklist](#step-6--triage-playbook--evidence-checklist)
- [Testing & Validation](#testing--validation)
- [Screenshots](#screenshots)
- [Hiring Manager Notes](#hiring-manager-notes)
- [Resources](#resources)
- [License](#license)

---

## What You’ll Build
- **KQL query pack** for investigation patterns:
  - Suspicious logons
  - Rare processes / LOLBins
  - Network discovery utilities
  - Off-hours activity
- **Detection rule templates** (what should become alerts)
- **Python enrichment** that:
  - Parses raw events (JSON/CSV)
  - Adds derived fields (risk scoring, tags)
  - Outputs “case-ready” evidence bundles

---

## Architecture

```mermaid
flowchart LR
  A[Telemetry Sources<br/>Endpoints / Identity / Network] --> B[SIEM / Log Store<br/>Sentinel / MDE / Log Analytics]
  B --> C[KQL Hunts<br/>Queries + notebooks]
  C --> D[Detections<br/>Scheduled analytics rules]
  D --> E[Triage Workflow<br/>Evidence + escalation]
  B --> F[Python Enrichment<br/>Parse + Tag + Export]
  F --> E

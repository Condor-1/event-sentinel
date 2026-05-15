### Event Sentinel Readme V1

# Event Sentinel

A modular Windows event log SIEM built for learning and experimenting with rule-based detection. This project focuses on collecting Windows Security/System logs and detecting high-signal attacker behavior using simple but meaningful detection rules. The main goal of this project is to understand how SIEM pipelines actually work under the hood instead of only using existing tools

---

## Features

- Real-time Windows event log collection
- Rule-based detection engine
- Modular detection rules
- Event parsing pipeline
- State tracking to avoid duplicate event processing
- Debug system for tracing parsing/detection logic

---

## Detection Rules

### Current detections include:

| Event ID | Detection |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4672 | Privileged logon |
| 4688 | Process creation |
| 4720 | User account creation |
| 4732 | User added to group |
| 6005 | Event log service started |
| 6006 | Event log service stopped |
| 41 | Unexpected shutdown/reboot |
| 600 | Custom system detection |

---

## Architecture

The project is split into separate modules to keep the detection logic isolated and makes debugging easier

```text
mini_siem/
├── collector/
├── parser/
├── rules/
├── database/
```

### Collector:

Handles Windows Event Log ingestion and state tracking

### Parser:

Normalizes raw event data into a format the rule engine can process

### Rules:

Contains independent detection modules

### Database:

Handles SQLite storage and schema management

---

## Project Structure

```text
event-sentinel/
├── main.py
├── config.py
├── requirements.txt
├── mini_siem/
│   ├── collector/
│   ├── parser/
│   ├── rules/
│   └── database/
└── data/
```

---

## Installation

<!-- Installation section will be expanded as the project stabilizes -->

---

## Learning Goals

This project is mainly a learning-focused cybersecurity engineering project

Some things I wanted to learn while building this:

- Windows Event Log internals
- Detection engineering basics
- SIEM pipeline design
- Rule-based detection systems
- Event parsing challenges
- Modular software architecture

---

## Notes

This is still an active learning project and the architecture/detections will continue evolving over time. The focus right now is stability, clean modular design, and understanding how defensive security tooling works internally

